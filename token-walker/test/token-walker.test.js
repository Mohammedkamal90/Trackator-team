const { test } = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path');
const Ajv = require('ajv');
const bin = path.join(__dirname, '..', 'dist', 'index.js');
const fx = f => path.join(__dirname, 'fixtures', f);
const schema = require('../schema/token-state-graph.schema.json');
const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);

function cli(args) { return spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8' }); }
const cache = new Map();
function run(fixture, extra = []) {
  const key = fixture + extra.join(' ');
  if (cache.has(key)) return cache.get(key);
  const out = path.join(os.tmpdir(), `tw-${process.pid}-${cache.size}.json`);
  const r = cli([fx(fixture), '-o', out, '--quiet', '--no-timestamp', ...extra]);
  assert.strictEqual(r.status, 0, r.stderr);
  const raw = fs.readFileSync(out, 'utf8'); fs.unlinkSync(out);
  const res = { raw, doc: JSON.parse(raw), T: Object.fromEntries(JSON.parse(raw).targets.map(t => [t.contract, t])) };
  cache.set(key, res); return res;
}
const ACC = ['--contract', 'AccessSem,PairAlias,TryBody'];
const E = (t, n) => t.entrypoints.find(e => e.name === n);
const writes = g => g.writes.map(w => w.delta);
const groupsW = e => e.effect_groups.map(writes);

// ───────── regression: original heuristics ─────────
test('reflection: deliver() flagged as unscaled user-controlled rate-driver write', () => {
  const t = run('Reflection.sol').doc.targets[0];
  const d = t.divergence_sites.find(x => x.entry.endsWith('.deliver') && x.kind === 'implicit_balance_shift');
  assert.ok(d); assert.strictEqual(d.magnitude_hint, 'user_controlled_unscaled'); assert.strictEqual(d.confidence, 'definite');
});
test('reflection: read-only balanceOf input (_tTotal) is demoted, written one (_rTotal) is a rate driver', () => {
  const t = run('Reflection.sol').doc.targets[0];
  assert.ok(t.token_model.rate_drivers.includes('_rTotal'));
  assert.ok(!t.token_model.rate_drivers.includes('_tTotal'));
  assert.ok(t.state_vars.find(v => v.name === '_tTotal').roles.includes('balance_of_readonly_input'));
});
test('reflection: deliver -> ENV:pair.skim ranks in top 3; owner-gated setPair never a sequence step', () => {
  const t = run('Reflection.sol').doc.targets[0];
  const i = t.sequences.items.findIndex(s => s.steps[0].endsWith('.deliver') && s.steps[1].startsWith('ENV:pair.skim'));
  assert.ok(i >= 0 && i < 3, `rank ${i}`);
  assert.ok(!t.sequences.items.some(s => s.steps.some(x => x.endsWith('.setPair'))));
});
test('burn-from-pair: pair balance debit is a definite divergence site', () => {
  const t = run('BurnFromPair.sol').doc.targets[0];
  const d = t.divergence_sites.find(x => x.kind === 'pair_balance_written_by_token_logic' && x.detail.includes('bal[pair]'));
  assert.ok(d && d.confidence === 'definite');
});

// ───────── G-01 loops ─────────
test('G-01 loops: continue runs the increment, break does not; do-while has no zero-iteration path', () => {
  const L = run('Semantics.sol').T.Loops;
  const inc = groupsW(E(L, 'forInc')).map(a => a.join(';')).sort();
  assert.deepStrictEqual(inc, ['k = 0', 'k = 0;k += 1', 'k = 0;total += 1;k += 1'].sort());   // 0 iters/break · continue (increment runs) · normal
  assert.ok(groupsW(E(L, 'doWhile')).every(a => a.includes('d += 1')), 'do-while must always execute body once');
  assert.ok(groupsW(E(L, 'whileBreak')).every(a => a.includes('after_ = 1')), 'statement after loop must always run');
  assert.ok(groupsW(E(L, 'forContinue')).some(a => a.length === 0) && groupsW(E(L, 'forContinue')).some(a => a.includes('total += 1')));
});

// ───────── G-02 / G-03 incompleteness + overloads ─────────
test('G-02 unresolved call emits an opaque call event and marks the entrypoint incomplete', () => {
  const U = run('Semantics.sol').T.Unresolved; const e = E(U, 'h');
  assert.ok(!e.summary.complete && e.summary.incomplete_reasons.some(r => r.startsWith('unresolved_call:missingFn')));
  assert.ok(U.external_call_matrix.some(c => c.entry.endsWith('.h') && c.function === 'missingFn' && c.target === '<opaque>'));
  assert.ok(run('Semantics.sol').doc.diagnostics.incomplete_entries.some(x => x.includes('Unresolved.h')));
});
test('G-03 same-arity overloads: all candidates explored and flagged ambiguous', () => {
  const e = E(run('Semantics.sol').T.Overloads, 'g');
  const w = groupsW(e).flat();
  assert.ok(w.includes('x = a') && w.includes('y = 1'));
  assert.ok(!e.summary.complete && e.summary.incomplete_reasons.includes('overload_ambiguous:f'));
});

// ───────── G-04 truncation ─────────
test('G-04 truncation is fair (strided), counted, and propagated to incompleteness', () => {
  const r = run('Semantics.sol', ['--max-paths', '8']); const e = E(r.T.Trunc, 'many');
  assert.strictEqual(e.summary.truncated, true); assert.ok(e.summary.paths_discarded_by_cap > 0);
  assert.ok(e.summary.states_generated >= e.summary.paths_completing && e.summary.peak_frontier > e.summary.cap);
  assert.ok(!e.summary.complete);
  const firstArms = new Set(e.effect_groups.map(g => g.writes.some(w => w.var === 'first')));
  assert.deepStrictEqual([...firstArms].sort(), [false, true], 'both arms of the FIRST branch must survive (tail-cut would keep only one)');
  assert.ok(r.doc.diagnostics.truncated_entries.some(x => x.includes('Trunc.many')));
});

// ───────── G-05 modifiers / constructors ─────────
test('G-05 base-constructor arguments from the inheritance clause are bound (cap = 100)', () => {
  const c = E(run('Semantics.sol').T.ModChild, 'constructor');
  assert.ok(groupsW(c).flat().includes('cap = 100'));
});
test('G-05 multiple modifier placeholders execute the body twice; unresolved modifier is reported', () => {
  const M = run('Semantics.sol').T.ModChild;
  assert.deepStrictEqual(groupsW(E(M, 'bump'))[0], ['v += 1', 'v += 1']);
  assert.ok(E(M, 'bad').summary.incomplete_reasons.includes('unresolved_modifier:onlyMissing'));
});

// ───────── G-06 access ─────────
test('G-06 access classes are evidence-based', () => {
  const A = run('Semantics.sol').T.AccessCtl; const cls = n => E(A, n).access.class;
  assert.strictEqual(cls('ifRevertOwner'), 'owner-only');     // if (msg.sender != owner) revert();
  assert.strictEqual(cls('requireOwner'), 'owner-only');
  assert.strictEqual(cls('requireAdmin'), 'role-gated');
  assert.strictEqual(cls('open'), 'permissionless');
  assert.strictEqual(cls('pull'), 'permissionless');           // allowance comparison is not an auth guard
  assert.strictEqual(cls('alwaysReverts'), 'unknown');         // no completing path ≠ permissionless
  assert.strictEqual(E(A, 'alwaysReverts').access.uncertain, true);
});

// ───────── G-07 grouping ─────────
test('G-07 group reads are a union; ordered write/call interleavings are separate groups; representative is labelled', () => {
  const G = run('Semantics.sol').T.GroupSem;
  const se = E(G, 'sameEffects'); assert.strictEqual(se.effect_groups.length, 1);
  const rv = se.effect_groups[0].reads.map(r => r.var); assert.ok(rv.includes('a1') && rv.includes('b1'));
  assert.strictEqual(se.effect_groups[0].reads_scope, 'union'); assert.ok(se.effect_groups[0].representative.note);
  assert.strictEqual(E(G, 'ordering').effect_groups.length, 2);
});

// ───────── G-08 pair model ─────────
test('G-08 supply writes do not create PAIR_BALANCE writes unless balanceOf provably reads the variable', () => {
  const P = run('Semantics.sol').T.PlainSupply;
  assert.ok(!E(P, 'mint').effect_groups.some(g => g.pseudo.writes.includes('PAIR_BALANCE')));
});
test('G-08 --no-env removes synthetic nodes', () => {
  const t = run('Reflection.sol', ['--no-env']).doc.targets[0];
  assert.strictEqual(t.env_model.enabled, false); assert.ok(!t.sequences.items.some(s => s.flags.contains_env));
});

// ───────── G-09 external calls ─────────
test('G-09 view classification: declared mutability wins; param-controlled targets are never "view"', () => {
  const X = run('Semantics.sol').T.ExtView; const m = n => X.external_call_matrix.find(c => c.entry.endsWith(n));
  assert.strictEqual(m('viaDeclaredView').likely_view, true); assert.strictEqual(m('viaDeclaredView').view_basis, 'declared');
  assert.strictEqual(m('viaDeclaredNonView').likely_view, false);
  assert.strictEqual(m('viaParam').likely_view, false); assert.strictEqual(m('viaParam').callback_surface, 'yes');
});

// ───────── G-10 / G-12 CLI ─────────
test('G-12 CLI validation: exit codes and messages', () => {
  assert.strictEqual(cli([]).status, 2);
  assert.strictEqual(cli([fx('Reflection.sol'), '--bogus']).status, 2);
  assert.strictEqual(cli([fx('Reflection.sol'), '--depth', 'abc']).status, 2);
  assert.strictEqual(cli([fx('Reflection.sol'), '--depth']).status, 2);
  assert.strictEqual(cli([fx('Reflection.sol'), '--max-paths', '0']).status, 2);
  const bad = cli([fx('Reflection.sol'), '--contract', 'Nope']); assert.strictEqual(bad.status, 2); assert.match(bad.stderr, /unknown contract/);
  assert.strictEqual(cli([path.join(os.tmpdir(), 'does-not-exist.sol')]).status, 1);
  assert.strictEqual(cli([fx('Reflection.sol'), '-o', '/nonexistent-dir-xyz/out.json']).status, 3);
  assert.strictEqual(cli([fx('Reflection.sol'), fx('BurnFromPair.sol')]).status, 2);
});
test('G-10/G-12 --strict exits 4 when entrypoints are incomplete; clean input passes', () => {
  const out = path.join(os.tmpdir(), `tw-strict-${process.pid}.json`);
  assert.strictEqual(cli([fx('Semantics.sol'), '-o', out, '--quiet', '--strict']).status, 4);
  assert.strictEqual(cli([fx('Reflection.sol'), '-o', out, '--quiet', '--strict']).status, 0);
  fs.unlinkSync(out);
});
test('G-10 parse errors are reported (tolerant parser recovery is not silent)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tw-bad-')); fs.writeFileSync(path.join(dir, 'Bad.sol'), 'pragma solidity ^0.8.0; contract Bad { function f( public { } }');
  const out = path.join(dir, 'o.json'); const r = cli([dir, '-o', out, '--quiet', '--no-timestamp']);
  const d = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')).diagnostics : null;
  assert.ok(r.status !== 0 || (d && (d.parse_errors.length || d.failed_files.length)), 'malformed source must surface as an error or diagnostic');
});

// ───────── G-13 schema ─────────
test('G-13 every generated artifact validates against the full schema (incl. --raw-paths)', () => {
  for (const f of ['Reflection.sol', 'BurnFromPair.sol', 'Semantics.sol']) {
    const doc = run(f, ['--raw-paths']).doc; const ok = validate(doc);
    assert.ok(ok, f + ' ' + JSON.stringify((validate.errors || []).slice(0, 3)));
  }
});

// ───────── G-15 provenance / determinism ─────────
test('G-15 provenance: sha256 per file, relative paths, parser version; deterministic with --no-timestamp', () => {
  const { doc, raw } = run('Reflection.sol');
  assert.ok(doc.input.files.every(f => /^[0-9a-f]{64}$/.test(f.sha256) && !path.isAbsolute(f.path)));
  assert.ok(!path.isAbsolute(doc.input.path)); assert.match(doc.tool.parser, /@solidity-parser\/parser@/);
  assert.strictEqual(run('Reflection.sol', ['--max-seq', '3000']).raw.length > 0, true);
  const out2 = path.join(os.tmpdir(), `tw-det-${process.pid}.json`);
  assert.strictEqual(cli([fx('Reflection.sol'), '-o', out2, '--quiet', '--no-timestamp']).status, 0);
  assert.strictEqual(fs.readFileSync(out2, 'utf8'), raw); fs.unlinkSync(out2);
});
test('G-15 default run records generated_at; --abs-paths opt-in', () => {
  const out = path.join(os.tmpdir(), `tw-ts-${process.pid}.json`);
  cli([fx('Reflection.sol'), '-o', out, '--quiet', '--abs-paths']); const d = JSON.parse(fs.readFileSync(out, 'utf8')); fs.unlinkSync(out);
  assert.ok(typeof d.generated_at === 'string'); assert.ok(path.isAbsolute(d.input.path));
});

// ───────── Re-audit R-01 .. R-05 ─────────
test('R-01 loop conditions: static false/true conditions, initializer values, post-iteration exit', () => {
  const L = run('LoopCond.sol').T.LoopCond; const g = n => groupsW(E(L, n)).map(a => a.join(';'));
  assert.deepStrictEqual(g('alwaysFalse'), ['']);                         // body unreachable
  assert.deepStrictEqual(g('alwaysTrueBreak'), ['x = 2']);                // zero-iteration arm impossible
  assert.strictEqual(E(L, 'alwaysTrueNoBreak').summary.paths_completing, 0);   // never terminates ⇒ no completing path
  assert.deepStrictEqual(g('forInit').sort(), ['', 'x = 1']);             // initializer value kept (not `x = i`)
  assert.deepStrictEqual(g('doOnce'), ['x = 3']);
  assert.strictEqual(E(L, 'doTrue').summary.paths_completing, 0);
});
test('R-01 loops with state effects are reported incomplete (only 1 iteration modeled); pure loops are not', () => {
  const L = run('LoopCond.sol').T.LoopCond;
  assert.ok(E(L, 'effectLoop').summary.incomplete_reasons.includes('loop_effects_bounded'));
  assert.strictEqual(E(L, 'effectLoop').summary.complete, false);
  assert.strictEqual(E(L, 'pureLoop').summary.complete, true);
  assert.ok(E(L, 'pureLoop').summary.approximations.includes('loop_unrolled_once'));
});
test('R-03 access: arbitrary state is NOT a role; role-like names are role-gated but uncertain', () => {
  const A = run('AccessSem.sol', ACC).T.AccessSem; const a = n => E(A, n).access;
  assert.strictEqual(a('eqPlainVar').class, 'unknown');                    // msg.sender == lastCaller
  assert.strictEqual(a('registered').class, 'unknown');                    // balances-like map keyed by caller
  assert.strictEqual(a('rolenamed').class, 'role-gated'); assert.strictEqual(a('rolenamed').uncertain, true);
  assert.strictEqual(a('ownerOnly').class, 'owner-only'); assert.strictEqual(a('ownerOnly').uncertain, false);
});
test('R-04 groups: same textual delta with/without pair alias are separate groups (no alias leakage)', () => {
  const P = run('AccessSem.sol', ACC).T.PairAlias; const e = E(P, 'transfer');
  const gs = e.effect_groups.filter(g => g.writes.some(w => w.var === 'bal' && w.delta === 'bal[to] += amt'));
  assert.ok(gs.length >= 2, 'alias and non-alias paths must not share a group');
  assert.ok(gs.some(g => g.writes.some(w => w.pair_alias === 'definite')) && gs.some(g => g.writes.every(w => w.pair_alias !== 'definite' || w.var !== 'bal' || w.key !== 'to')));
});
test('R-02 try/catch bodies are executed (their effects reach the trace); unknown-statement fallback visits children', () => {
  const e = E(run('AccessSem.sol', ACC).T.TryBody, 'f');
  assert.ok(groupsW(e).flat().includes('s = 1') && groupsW(e).flat().includes('s = 2'));
});
test('stale-condition memo: a write to V invalidates earlier decisions about V (state-var loop condition)', () => {
  // for (k = 0; k < n; k += 1): the post-iteration `k < n` must NOT be treated as the already-decided pre-iteration `k < n`
  const g = groupsW(E(run('Semantics.sol').T.Loops, 'forInc')).map(a => a.join(';'));
  assert.ok(g.includes('k = 0;k += 1') && g.includes('k = 0;total += 1;k += 1'));
});
test('R-05 schema rejects malformed divergence / sink records', () => {
  const doc = JSON.parse(JSON.stringify(run('Reflection.sol').doc));
  assert.ok(validate(doc));
  const bad1 = JSON.parse(JSON.stringify(doc)); bad1.targets[0].divergence_sites[0].extra = 1; assert.ok(!validate(bad1));
  const bad2 = JSON.parse(JSON.stringify(doc)); bad2.targets[0].divergence_sites[0].line = 'x'; assert.ok(!validate(bad2));
  const bad3 = JSON.parse(JSON.stringify(doc)); if (bad3.targets[0].sinks[0]) { bad3.targets[0].sinks[0].kind = 5; assert.ok(!validate(bad3)); }
});
test('provenance: tree_sha256 distinguishes project roots with the same basename', () => {
  const a = run('Reflection.sol').doc.input.tree_sha256, b = run('BurnFromPair.sol').doc.input.tree_sha256;
  assert.match(a, /^[0-9a-f]{64}$/); assert.notStrictEqual(a, b);
});
test('ingestion: duplicate contract names are surfaced and fail --strict', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tw-dup-'));
  fs.writeFileSync(path.join(dir, 'A.sol'), 'pragma solidity ^0.8.0; contract Dup { uint x; function f() public { x = 1; } }');
  fs.writeFileSync(path.join(dir, 'B.sol'), 'pragma solidity ^0.8.0; contract Dup { uint y; function f() public { y = 1; } }');
  const out = path.join(dir, 'o.json'); const r = cli([dir, '-o', out, '--quiet', '--strict']);
  assert.strictEqual(r.status, 4); assert.ok(JSON.parse(fs.readFileSync(out, 'utf8')).diagnostics.warnings.some(w => w.includes('duplicate contract name Dup')));
});

test('unchecked { } blocks are executed (regression: ARK crash "stmts is not iterable")', () => {
  const w = groupsW(E(run('Semantics.sol').T.Unchecked, 'dec'))[0];
  assert.deepStrictEqual(w, ['u -= a', 'bal[msg.sender] += a']);
});

test('summary block is the FIRST data key of the JSON (right after schema_version) and mirrors the entrypoint table', () => {
  const { doc } = run('Reflection.sol');
  assert.deepStrictEqual(Object.keys(doc).slice(0, 2), ['schema_version', 'summary']);
  const s = doc.summary.targets[0];
  assert.ok(s.table_text[0].startsWith('entrypoint') && s.table_text.length === doc.targets[0].entrypoints.length + 1);
  assert.strictEqual(s.entrypoints.length, doc.targets[0].entrypoints.length);
  assert.ok(s.sequences.top.length > 0 && s.divergence_kinds.implicit_balance_shift >= 1);
  assert.strictEqual(doc.summary.run.incomplete, doc.diagnostics.incomplete_entries.length);
});
test('terminal prints only the process summary (no tables)', () => {
  const out = path.join(os.tmpdir(), `tw-term-${process.pid}.json`);
  const r = cli([fx('Semantics.sol'), '-o', out, '--no-timestamp']); fs.unlinkSync(out);
  assert.match(r.stderr, /^warnings=\d+ unresolved=\d+ unsupported=\d+ truncated=\d+ incomplete=\d+ parse_errors=\d+ failed_files=\d+/m);
  assert.match(r.stderr, /^wrote .*\.json \(\d+ KB\)$/m);
  assert.ok(!/entrypoint\s+access/.test(r.stderr) && !/^==/m.test(r.stderr) && !/sequences:/.test(r.stderr));
});
