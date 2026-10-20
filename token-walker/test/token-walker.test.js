const { test } = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path');
const bin = path.join(__dirname, '..', 'dist', 'index.js');
function run(fixture) {
  const out = path.join(os.tmpdir(), `tw-${process.pid}-${fixture}.json`);
  execFileSync('node', [bin, path.join(__dirname, 'fixtures', fixture), '-o', out, '--quiet', '--no-timestamp']);
  const raw = fs.readFileSync(out, 'utf8'); fs.unlinkSync(out);
  return { raw, doc: JSON.parse(raw) };
}
test('reflection: deliver() is flagged as unscaled user-controlled rate-driver write', () => {
  const t = run('Reflection.sol').doc.targets[0];
  assert.ok(t.token_model.ledger_types.includes('reflection') || t.token_model.rate_drivers.includes('_rTotal'));
  const d = t.divergence_sites.find(x => x.entry.endsWith('.deliver') && x.kind === 'implicit_balance_shift');
  assert.ok(d, 'deliver implicit_balance_shift missing');
  assert.strictEqual(d.magnitude_hint, 'user_controlled_unscaled');
});
test('reflection: deliver -> ENV:pair.skim sequence exists and ranks high', () => {
  const t = run('Reflection.sol').doc.targets[0];
  const i = t.sequences.items.findIndex(s => s.steps[0].endsWith('.deliver') && s.steps[1].startsWith('ENV:pair.skim'));
  assert.ok(i >= 0 && i < 3, `deliver->skim rank ${i}`);
});
test('reflection: owner-gated setPair is classified owner-only and not a sequence start', () => {
  const t = run('Reflection.sol').doc.targets[0];
  const e = t.entrypoints.find(x => x.name === 'setPair');
  assert.ok(['owner-only', 'role-gated'].includes(e.access.class), e.access.class);
  assert.ok(!t.sequences.items.some(s => s.steps.some(x => x.endsWith('.setPair'))));
});
test('burn-from-pair: pair balance debit is a definite divergence site', () => {
  const t = run('BurnFromPair.sol').doc.targets[0];
  const d = t.divergence_sites.find(x => x.kind === 'pair_balance_written_by_token_logic' && x.detail.includes('bal[pair]'));
  assert.ok(d && d.confidence === 'definite');
});
test('deterministic: two runs are byte-identical', () => {
  assert.strictEqual(run('Reflection.sol').raw, run('Reflection.sol').raw);
});
