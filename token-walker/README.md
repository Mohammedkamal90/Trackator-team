# token-walker

Deterministic, **un-pruned** state & path extractor for token contracts (ERC-20, tax, reflection, pair-integrated, vault-style).
It does **not** judge. It emits a completing-path report and an `R-` reverted-path companion: every reachable state transition per entrypoint, the cross-entrypoint
dependency graph, sinks, accounting-divergence sites and an external-call matrix — for downstream agents / Foundry fuzzers.

```
node dist/index.js <file.sol | dir> [-o token-state-graph.json] [--contract A,B] [--exclude substr] [--depth 2-6] [--max-paths N]
                   [--max-seq N] [--include-privileged] [--no-env] [--raw-paths] [--abs-paths] [--strict] [--quiet] [--no-timestamp]
node dist/index.js <Pair.sol> <Token.sol> --bind-token token0=TokenContract [--bind-token token1=OtherToken] [--scenario JSON] [--amm v2] [-o pool-report.json]
exit codes: 0 ok · 1 runtime/no input · 2 usage · 3 i/o · 4 --strict violation
npm run build && npm test
```

## V2 Pair-to-token source analysis

Pool-context mode accepts one V2 Pair source and one token source. It interprets the parsed `skim`, `sync`, and `swap` ASTs and writes a single JSON report. It does not add the standalone mode's synthetic `ENV:pair.*` nodes. A token-slot binding is an explicit source-analysis assumption; it is not evidence of a deployed Pair address or token address.

```bash
node dist/index.js /path/to/PancakePair.sol /path/to/ARK.sol \
  --amm v2 --bind-token token0=ARK --bind-token token1=ARK \
  --scenario '{"skim":{"to":"recipient"},"swap":{"amount0Out":1,"amount1Out":0,"to":"recipient","data":"0x"}}' \
  -o pool-report.json
```

Omit scenario fields to leave those transaction arguments symbolic. In particular, an unknown `swap.data` can stop at callback dispatch; that path is reported unresolved. `--max-paths` sets the number of paths retained per entrypoint (Pool mode defaults to 100); path interpretation itself is not bounded by that report cap. Reports label normal returns and reverts as static candidates, include source hashes and trace details, and set `full_analysis` to `false`. Pool mode supports V2 only; V3/V4 selections are rejected explicitly.

## Run it on any project
Needs Node ≥ 18 + npm. No solc, no Foundry/Hardhat build, no compiled artifacts — it only parses `.sol` source.

**1. One-time setup** (from anywhere):
```bash
TW=/run/media/glitch/Glitch/Data/Audit-Agents/Trackator-team/token-walker
cd $TW && npm install --include=dev && npm run build        # `--include=dev` matters if NODE_ENV=production
```
**2. Make it callable from any directory** — pick one:
```bash
# a) wrapper script (self-locating, auto-builds on first use)
$TW/token-walker.sh <project|file.sol> [options]
# b) shell alias (add to ~/.bashrc / ~/.zshrc)
alias token-walker='node /run/media/glitch/Glitch/Data/Audit-Agents/Trackator-team/token-walker/dist/index.js'
# c) PATH — installed this way on this machine (symlink lives on ext4 home, target on the drive):
mkdir -p ~/.local/bin && ln -sf $TW/token-walker.sh ~/.local/bin/token-walker
#    + ensure ~/.bashrc has:  export PATH="$HOME/.local/bin:$PATH"   then `source ~/.bashrc` (or open a new terminal)
```
**3. Run it from the project you are auditing:**
```bash
cd ~/audits/SomeToken
token-walker src/Token.sol -o token-state-graph.json                     # single / flattened file
token-walker . --exclude /lib/,/test/,/script/,/mocks/ --contract MyToken  # Foundry / Hardhat repo (recommended form)
token-walker contracts --exclude /node_modules/,/mocks/                  # Hardhat: point at the contracts dir
token-walker . --contract TokenA,TokenB                                  # several tokens in one run (one `targets[]` entry each)
```
How it picks targets: every non-abstract **leaf** contract (not inherited by another); if any leaf has `transfer` + `balanceOf`, only the token-like
leaves are analyzed. In a repo with mocks/routers/pairs that auto-pick is often wrong ⇒ **always pass `--contract`** and `--exclude` for `lib/`, `test/`, `script/`.
`--exclude` matches substrings of the absolute path (so use `/lib/`, not `lib`). Skipped automatically: `node_modules`, `out`, `cache`, `artifacts`,
`broadcast`, `typechain*`, `.git`. Excluded files are listed in `diagnostics.excluded_files`.

**Checklist for a clean run**
* Same contract name in two files ⇒ only the later one is analyzed (warning; `--strict` fails). Exclude the duplicate or use a flattened file.
* Read the console summary: any `INCOMPLETE` row or non-zero `warnings/unresolved/incomplete` means the inventory for that entrypoint is **not** complete.
* Inline-assembly-heavy or proxy/diamond code: the tool will flag it, not model it. Run it on the implementation contract, not the proxy.
* Pin the evidence: `input.files[].sha256` + `input.tree_sha256` identify exactly what was analyzed; `--no-timestamp` gives byte-identical output.
* CI / gate: `token-walker . --contract X --exclude /lib/ --strict --quiet -o out.json` ⇒ exit 4 if anything was parse-failed, duplicated or incomplete.

**Read the result** (`jq` recipes; `T=.targets[0]`):
```bash
J=token-state-graph.json
jq -r '.targets[0].sequences.items[:10][] | "\(.score) \(.steps|join(" -> "))"' $J                  # ranked attack-chain leads
jq -r '.targets[0].divergence_sites[] | "\(.confidence) \(.kind) \(.entry) :: \(.detail)"' $J     # accounting-divergence sites
jq -r '.targets[0].divergence_sites[] | select(.magnitude_hint=="user_controlled_unscaled") | .entry' $J   # permissionless rate-driver writes
jq -r '.targets[0].entrypoints[] | select(.access.class=="permissionless" and .mutability!="view") | .id' $J
jq -r '.targets[0].entrypoints[] | select(.summary.complete|not) | "\(.id): \(.summary.incomplete_reasons|join(","))"' $J   # what NOT to trust
jq -r '.targets[0].external_call_matrix[] | select(.callback_surface=="yes") | "\(.entry) \(.kind) \(.target).\(.function)"' $J
jq '.targets[0].entrypoints[] | select(.name=="transfer") | .effect_groups[0].writes[].delta' $J       # exact state deltas
```
Feeding downstream: hand `token-state-graph.json` (or the `sequences` / `divergence_sites` arrays) to the redteam agent / a Foundry fork-test generator;
validate it with `schema/token-state-graph.schema.json` (ajv) before consuming. Typical per-run cost: seconds for one token (YFSX ≈ 2 s; whole Foundry repo with libs ≈ 10 s).

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
* `require(c)` forks into a completing `c` arm and reverting `!c` arm. Both carry chronological branch and terminal events; `if/else` paths are recorded similarly.
* Only **self-contradicting** combinations are skipped (same canonical condition decided twice, or a local folded to a literal). Apart from the
  reported cap truncation, a feasible path is never dropped.
* Paths with identical effects are **grouped** (`effect_groups[].path_count`, up to `maxConstraintSets` distinct constraint sets kept).
  `--raw-paths` additionally dumps every path with its full ordered trace.
* Loops: 0 and 1 iterations. Static conditions are honoured (`while(false)` has no body path; `while(true)` has no 0-iteration path; a loop that cannot
  exit after 1 iteration yields no completing path unless `break`/`return`). For-initializer values are kept (first iteration sees `i = 1`). The exit
  condition is assumed false after the iteration. Any loop whose body writes state or calls out sets `loop_effects_bounded` ⇒ entrypoint **incomplete**
  (only one iteration modeled). Pure loops only get the `loop_unrolled_once` approximation marker.
* Condition memo: a write to V (or any non-view external call, for state-dependent conditions) invalidates earlier decisions about conditions mentioning V.
* Group key = ordered writes/calls **with source lines** + pair-relevant equality facts, so alias/location-derived findings hold for every group member.

## Reports (schema_version 1.4)
Each entrypoint has `execution_paths[]`, an ordered trace with branch conditions, reads, writes, calls, call chain, and terminal outcome. The primary report contains completing paths; its `R-` companion contains reverted/failed paths. With one target and no `-o`, filenames are `<Contract>-state-graph.json` and `R-<Contract>-state-graph.json`. With explicit `-o`, the companion is `R-<basename>`. Existing effect groups and graph summaries remain available.

## token-state-graph.json
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

## Soundness model (v0.4.0)
Every entrypoint reports `summary.complete` + `summary.incomplete_reasons`. An entrypoint is **incomplete** (and any sequence using it carries
`flags.involves_incomplete_entry`) when it hit: path-cap truncation, an unresolved/opaque call, an unresolved modifier, an unsupported
statement/expression, a depth/recursion limit, or an ambiguous same-arity overload. `--strict` turns any of these (or parse errors) into exit code 4.
Never treat an incomplete entrypoint as a full inventory.

Cap truncation keeps a deterministic **evenly-strided sample** of the frontier (not the tail), and reports `states_generated`,
`paths_discarded_by_cap`, `peak_frontier`. These are implementation work counters, not an exact count of every path ever created.

## Known limits (read before trusting output)
1. Parse-only: no type system. Same-arity overloads are all explored and flagged (not type-resolved). Contract-typed vars are recognised by declared type;
   unknown interfaces fall back to a name heuristic for "view" only when the target is a state variable (`view_basis` says which).
2. Inline assembly is **not** modeled (flag `unmodeled_assembly`, entrypoint marked incomplete-by-warning). Cross-contract calls are recorded, not followed.
3. Loops: 0 and 1 iterations (`continue`/`break`/do-while handled; no fixed-point). Ternaries with effects are merged (`ternary_effects_merged`).
   Modifier arguments are evaluated without forking; `return` inside a modifier is approximated.
4. Constraints are text, not solved. No feasibility check beyond syntactic self-contradiction.
5. Access: `role-gated` needs a role-tagged or role-named subject (`owner|admin|operator|…`); other `msg.sender == x` / `map[msg.sender]` shapes are `unknown`. Name-based roles set `access.uncertain`.
   `_msgSender()` is rendered as `msg.sender` (no ERC-2771 trusted-forwarder model). Access class `permissionless` means *no auth-shaped guard found on any path*;
   `unknown`/`mixed` carry `access.uncertain`. Signature-based or off-chain authorisation is not recognised.
6. `pair_alias: definite` needs an `x == pair` constraint or a pair-var key. One pair per pair-role variable; chain/pool identity is not resolved.
   Nothing proves a pair is *not* excluded from rewards — that is on-chain state.
7. Role tags are heuristics (names + what `balanceOf` reads). `confidence`: `definite` = observed fact, `inferred` = name/role based; each divergence has a `basis`.
   Wrong tag ⇒ wrong label, never a dropped path. Mutex evidence = set-before/reset-after on the path + `mutex_checked_by` (entrypoints whose constraints test the lock);
   boolean locks only (no `1/0` or enum locks).
8. Source resolution is by contract name over all collected `.sol` files (no import/remapping resolution). Duplicate names warn; use `--exclude` to scope.
9. A divergence site / sequence is a **lead**. Confirm with a fork PoC and a profit number before reporting.

## Tests
`npm test` (30 tests; CLI is spawned via `process.execPath`): semantic fixture matrix (loops, overloads, unresolved calls/modifiers, base-ctor args, access classes, truncation fairness,
grouping, view classification, pair-model evidence), CLI exit codes, `--strict`, schema validation (ajv, `additionalProperties:false`), determinism, provenance.
