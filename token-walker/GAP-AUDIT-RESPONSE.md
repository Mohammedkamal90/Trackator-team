# Response to token-walker-gap-audit.md (Codex, 2026-10-20) — v0.1.0 → v0.2.0

Every finding was checked against the code, then fixed or scoped. "Verified" = reproduced/confirmed in source; tests live in `test/token-walker.test.js`.

| ID | Verdict | Status | What changed / residual |
|---|---|---|---|
| G-01 | Valid | **Fixed** | `continue` ≠ `break` (separate halt states); `continue` runs increment, `break` skips it; do-while always runs body once; loop condition re-read after the iteration. Tests: `forInc/doWhile/whileBreak/forContinue`. |
| G-02 | Valid | **Fixed** (assembly still unmodeled) | Unknown expressions now traverse children; unresolved internal calls and non-member/non-identifier callees emit an **opaque call event** (in the external-call matrix); every such case sets a path flag → `summary.complete=false` + `incomplete_reasons`; `--strict` exits 4. |
| G-03 | Valid | **Mitigated** | `findFns` returns all same-arity overloads; all are explored on forked states and flagged `overload_ambiguous`. Not type-resolved (parse-only). Applies to plain, `super`, `this.`, `Lib.f`, using-for calls. |
| G-04 | Valid | **Fixed (fairness) / residual (completeness)** | Tail cut replaced by deterministic evenly-strided sampling; counters `states_generated`, `paths_discarded_by_cap`, `peak_frontier`; truncation ⇒ entrypoint incomplete ⇒ sequences flagged `involves_incomplete_entry`. Test proves both arms of the first branch survive. |
| G-05 | **Partly valid** | **Fixed** except noted | Base-constructor args from inheritance clause / ctor modifier-invocations are bound (`cap = 100`). Unresolved modifiers are reported (flag + warning, entrypoint incomplete). Multiple placeholders verified correct. **Not valid for solc ≥ 0.6:** state-variable shadowing is a compile error; a warning is emitted for pre-0.6 sources. Residual: modifier args evaluated without fork; `return` inside modifier approximated. |
| G-06 | Valid | **Fixed** | `if (bad) revert();` now yields a require-style guard; guards are parsed structurally (`X == msg.sender`, `map[msg.sender]`, registry call keyed by caller), not "owner-ish identifier anywhere". No completing path ⇒ `unknown` (not `permissionless`); `mixed`/`unknown` set `access.uncertain`; allowance comparisons are not treated as auth. Sequences keep `unknown` as startable but flag `access_uncertain`. Residual: ERC-2771 forwarders, signature auth. |
| G-07 | Valid | **Fixed** | Group key = ordered write/call interleaving; `reads` = union over the group (`reads_scope`); first-path facts moved under `representative` with a note; `constraint_sets_truncated`; `call_chain_union`. |
| G-08 | Valid | **Mitigated** | `PAIR_BALANCE` is written only by balance writes aliasing a pair, or by writes to variables `balanceOf()` provably reads; ENV assumptions are emitted in `env_model`; `--no-env` disables synthetic nodes. Residual: multiple pairs / chain identity. |
| G-09 | Valid | **Fixed / partly** | "View" now = declared mutability when the interface is in the source, name heuristic only for state-var targets of undeclared interfaces; param/derived/unknown targets are never view (`view_basis` exposed). Mutex output adds `mutex_checked_by` (entrypoints whose constraints test the lock). Residual: dominance proof, non-boolean locks. |
| G-10 | Valid | **Fixed** except imports | Symlink-cycle guard; parser recovery errors → `diagnostics.parse_errors`/`failed_files`; unknown `--contract` is an error; `--exclude`; duplicate names/shadowing warn. Residual: import/remapping resolution. |
| G-11 | **Partly valid** | **Fixed** except noted | `owner` in the accounting set for both model and analysis; `confidence` split `definite` (observed) vs `inferred` (name-based) + `basis`; `balanceOf` inputs never written outside the constructor are demoted (`balance_of_readonly_input`; removes e.g. `_tTotal` from rate drivers); zero-slippage check fixed — it **missed `swapExactETH*` (min-out is arg 0)**, which hid the YFSX buy-back swap. Residual: key-alias/nested-map detection in `balanceOf`, name heuristics. |
| G-12 | Valid | **Fixed** | Strict option parser, integer/range checks, unknown flags/extra positionals rejected, output dir validated, exit codes 0/1/2/3/4. |
| G-13 | Valid | **Fixed** | Full nested schema (v1.1, `additionalProperties:false`) validated with ajv in tests over every fixture incl. `--raw-paths`. (First run caught real drift: `reads[].k`.) Not generated from `types.ts` — the validation test is the drift guard. |
| G-14 | Valid | **Fixed (scope)** | 5 → 21 tests: semantic matrix per finding, CLI, strict mode, schema, determinism, provenance. Not done: property-based tests, golden full-output snapshots. |
| G-15 | Valid | **Fixed** except license | `input.files[].sha256/bytes`, relative paths, parser/node versions; absolute root only with `--abs-paths`; `--no-timestamp` documented as the deterministic mode. Not done: license, formal threat model. |

YFSX re-run after fixes: 0 incomplete entrypoints, schema-valid; top lead unchanged (`deliver → ENV:pair.skim`); zero-slippage sites 2 → 4 (buy-back `swapExactETH…(0, …)` now caught); `_tTotal` no longer a rate driver.


---
# Re-audit response (token-walker-reaudit.md, 2026-10-20) — v0.2.0 → v0.3.0 (schema 1.2)

| ID | Verdict | Status |
|---|---|---|
| R-01 loop conditions / initializers | **Valid (reproduced)** | **Fixed.** Static loop conditions decided (`while(false)`, `while(true)`); post-iteration exit condition applied; initializer values kept; non-terminating iterations yield no path; loops with effects ⇒ `loop_effects_bounded` ⇒ incomplete. Re-running the reviewer's fixture: `alwaysFalse → []`, `alwaysTrueBreak → [x = 2]`, `forInit → x = 1`. **Found while testing:** the condition memo survived writes to the variables in the condition (stale decisions) — now invalidated on write / external call. |
| R-02 unknown statements don't traverse children | Valid | **Fixed** (children executed/visited). No parser statement type currently reaches this fallback in my fixtures, so the guard is covered by code review + the try/catch test, not a dedicated trigger. |
| R-03 arbitrary state treated as role | Valid | **Fixed.** `role` requires an owner/treasury/privileged-set tag or role-like name; other shapes ⇒ `unknown`; name-based roles ⇒ `access.uncertain`. |
| R-04 representative-derived findings | Valid | **Fixed.** Group key now includes source lines and pair-relevant equality facts (YFSX `transfer` groups 144 → 162). Residual: other representative-derived facts are still equal across members only because the key covers ordered writes/calls. |
| R-05 schema permissive | Valid | **Fixed.** `divergence_sites` / `sinks` fully typed, `additionalProperties:false`. Strict schema immediately exposed divergences missing `basis` — now always set. Tests mutate documents and assert rejection. |
| Probe overloads (G-03 note) | Valid | **Fixed.** `balanceOf/totalSupply` probes use all same-arity candidates (union) + warning. |
| G-05 base-arg state / shadowing | Valid (disclosed) | Warning when base-ctor args read state; pre-0.6 shadowing still name-merged (documented). |
| G-10 duplicates / traversal errors | Valid | **Fixed.** Traversal errors → `failed_files`; duplicate contract names fail `--strict`. |
| G-15 basename collision | Valid | **Fixed.** `input.tree_sha256` over (relative path, file hash). |
| Test EPERM | Environmental | Tests now spawn `process.execPath` instead of `node` from PATH. Reviewer's sandbox may still deny nested spawn; run `npm test` in a normal shell. |
| G-04 counters | Accepted | They are implementation counters (frontier work), not exact path accounting — README says so. |

YFSX re-run: schema-valid; `includeInReward` (owner-only loop with writes) is now correctly **incomplete**; top lead unchanged (`deliver → ENV:pair.skim`).
