# token-walker

Deterministic, **un-pruned** state & path extractor for token contracts (ERC-20, tax, reflection, pair-integrated, vault-style).
It does **not** judge. It emits `token-state-graph.json`: every reachable state transition per entrypoint, the cross-entrypoint
dependency graph, sinks, accounting-divergence sites and an external-call matrix — for downstream agents / Foundry fuzzers.

```
node dist/index.js <file.sol | dir> -o token-state-graph.json [--contract Name] [--depth 4] [--max-paths 20000]
                   [--max-seq 3000] [--include-privileged] [--raw-paths] [--quiet] [--no-timestamp]
npm run build && npm test
```

## Why it exists (gap vs `tracaktor-walker`)
Measured on `YFSX/YfsxCoin.sol` with `tracaktor-walker`: `transfer` path list was truncated at the cap, **0 of 397 paths contained
`_reflectFee` / `_takeLiquidity` / `_rTotal` writes** (call-depth cut at `_transferStandard`), the `touches_value_bearing_write`
flag was true only for fee-toggles (not for balance writes), writes had no delta expression, and `transferToAddressETH` (native sink)
was missing. `token-walker` inlines every internal call (cycle-guarded), keeps delta expressions, and never drops a path for lacking a flag.

## Architecture
```
src/parse.ts      @solidity-parser/parser → Index: contracts, C3 linearization, state vars, fns, modifiers, using-for
src/engine.ts     symbolic path walker (no pruning). Inlines internal/library/modifier calls, substitutes args/locals,
                  records ordered trace events R(ead) / W(rite) / C(all). Forks on if / loops; require ⇒ constraint.
src/state.ts      State (frames, constraints, decided-conditions memo, trace), text helpers
src/model.ts      role tagging (labels only): balance, supply, rate_driver, allowance, fee, exclusion, pair, router, owner, mutex…
                  ALSO behavioral: runs balanceOf()/totalSupply() and tags what they read (→ rate drivers, per-account maps)
src/analyze.ts    group paths by identical effects, access class, sinks, divergence sites, external-call matrix
src/sequences.ts  entrypoint graph (A.writes ∩ B.reads) + depth-bounded sequence composition incl. synthetic ENV:pair.* nodes
src/index.ts      CLI / JSON assembly / console summary
```
Language: TypeScript + `@solidity-parser/parser` (parse-only: no solc/build needed; works on flattened or multi-file repos).

### Path semantics (what "un-pruned" means here)
* Every completing path of every public/external function is enumerated (cap `--max-paths`, truncation is reported, never silent).
* `require(c)` adds `c` as a constraint on the surviving path; the failing arm is recorded under `reverting_guards`
  (it writes nothing, so it is not a state-transition path). `if (c) revert()` is handled the same way.
* Only **self-contradicting** combinations are skipped (same canonical condition decided twice, or a local folded to a literal) — a
  feasible path is never dropped.
* Paths with identical effects are **grouped** (`effect_groups[].path_count`, up to `maxConstraintSets` distinct constraint sets kept).
  `--raw-paths` additionally dumps every path with its full ordered trace.
* Loops: body is explored 0 and 1 times (`loop_unrolled_once` flag).

## token-state-graph.json (schema_version 1.0)
Formal schema: `schema/token-state-graph.schema.json`. Shape:
```
{ schema_version, tool, generated_at, input{path,files}, config, diagnostics{warnings,unresolved_calls,unsupported_nodes,truncated_entries},
  targets: [ {
    contract, file, linearization[],
    token_model{ ledger_types[], balance_vars[], supply_vars[], rate_drivers[], allowance_vars[], fee_vars[], exclusion_vars[],
                 pair_vars[], router_vars[], owner_vars[], treasury_vars[], mutex_vars[], toggle_vars[], threshold_vars[],
                 balance_of_inputs{per_account_maps[],global_inputs[]}, evidence{var:[why]} },
    attacker_capabilities[],
    state_vars[ {name,type,kind,key_types,roles[],initial,line,...} ],
    entrypoints[ { id, signature, visibility, mutability, payable, modifiers, access{class,guards},
        summary{paths_enumerated,paths_completing,effect_groups,reverting_guards,truncated,cap,flags},
        reverting_guards[ {cond,kind,line,fn,count} ], reads_union[], writes_union[],
        effect_groups[ { group_id, path_count, call_chain[], constraints[{text,kind,line,fn}], constraint_sets[], eq_facts[],
            reads[{var,key,line,fn}],
            writes[{var,key,key_class,op,operand,delta,line,fn,roles[],pair_alias,in_loop,ext_derived}],   // delta: "_rOwned[recipient] += (...)"
            external_calls[], sinks[], divergence[], pseudo{reads[],writes[]} } ] } ],
    env_entrypoints[],            // synthetic ENV:pair.sync/skim/swap (reads/writes PAIR_BALANCE, PAIR_RESERVE)
    entrypoint_graph[ {from,to,via[],via_accounting[]} ],
    sequences{ max_depth,total_generated,kept,items[ {id,steps[],score,links[{from,to,via[]}],touches{divergence,sinks,accounting_vars},flags,equivalent_variants} ] },
    divergence_sites[ {id,entry,kind,confidence,line,fn,detail,note,magnitude_hint?,operand_params?,group_count,groups[]} ],
    sinks[ {id,entry,kind,line,fn,target,call,value?,group_count} ],
    external_call_matrix[ {entry,kind,target,target_class,target_type,function,args,value,callback_surface,state_writes_after_call[],mutex_guard} ]
  } ] }
```
Divergence kinds: `pair_balance_written_by_token_logic` (definite alias via `to == pair` constraint), `implicit_balance_shift`
(write to a global that `balanceOf()` reads — rebases every holder incl. the pair; `magnitude_hint`: `user_controlled_unscaled` /
`user_controlled_fee_scaled` / `no_user_control`), `supply_mutation`, `balance_credit_without_debit`, `balance_debit_without_credit`,
`third_party_debit`, `contract_balance_triggered_sink`, `zero_slippage_swap`.
Sink kinds: `native_transfer|native_send|low_level_call|delegatecall|selfdestruct|create`, `pair_<fn>`, `router_<fn>`,
`external_token_transfer|pull|mint|burn`, `supply_increase|decrease`, `burn_to_dead`, `external_call`.

### Sequences
Edge `A→B` when `A.writes ∩ B.reads ≠ ∅`. A sequence keeps only links whose shared variables are accounting-relevant
(balances, supply, rate drivers, fees, exclusions, pair, thresholds, mutex, `PAIR_*`, `$native_balance`). Starts are permissionless
entrypoints (`--include-privileged` to add owner-gated). Raw edges are always complete in `entrypoint_graph`; the **sequence list is
collapsed** by touch-signature (best 3 shortest per signature, `equivalent_variants` = hidden count) so permutations don't drown signal.
Score favors `user_controlled_unscaled` rate-driver writes and ENV pair primitives; it is a *triage order*, not a verdict.

## Known limits (read before trusting output)
1. Parse-only: no type system. Contract-typed state vars are recognised by declared type; `using for` is resolved by function name/arity.
2. Inline assembly is **not** modeled (flag `unmodeled_assembly` + warning). Cross-contract calls are recorded, not followed.
3. Loops: 0/1 iterations; `break/continue` approximated. Ternaries with effects are merged (`ternary_effects_merged`).
4. Constraints are text, not solved. No feasibility check beyond syntactic self-contradiction.
5. `pair_alias: definite` needs an `x == pair` constraint on the path; `possible` means the key is a parameter. Nothing proves a pair is *not* excluded from rewards etc. — that is on-chain state the tool cannot see.
6. Role tags are heuristics (names + what `balanceOf` reads). Wrong tag ⇒ wrong divergence label, never a dropped path.
7. A divergence site / sequence is a **lead**. Confirm with a fork PoC and a profit number before reporting.
