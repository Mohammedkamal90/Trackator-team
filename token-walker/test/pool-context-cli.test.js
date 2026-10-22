const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const bin = path.resolve(__dirname, '../dist/index.js');
const src = '/run/media/glitch/Glitch/BUG-Bounty/PRIVATE/TKN/ARK/src';
const pair = path.join(src, 'Pancake/PancakePair/PancakePair.sol');
const token = path.join(src, 'ARK/ARK.sol');
const available = fs.existsSync(pair) && fs.existsSync(token);

function runPool(scenario) {
  const out = path.join(os.tmpdir(), `token-walker-pool-${process.pid}-${Math.random().toString(16).slice(2)}.json`);
  const args = [bin, pair, token, '--amm', 'v2', '--bind-token', 'token0=ARK', '--bind-token', 'token1=ARK', '--max-paths', '10', '-o', out];
  if (scenario !== undefined) args.push('--scenario', JSON.stringify(scenario));
  const result = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 60000 });
  const report = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')) : null;
  fs.rmSync(out, { force: true });
  return { result, report };
}

test('two-input V2 CLI emits traced skim/sync/swap reports from real Pair and ARK sources', t => {
  if (!available) return t.skip('ARK V2 source checkout is not available at the configured path');
  const { result, report } = runPool({
    skim: { to: 'recipient' },
    swap: { amount0Out: 1, amount1Out: 0, to: 'recipient', data: '0x' },
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.ok(report, 'CLI wrote JSON output');
  assert.equal(report.schema_version, 'pool-context-v1');
  assert.equal(report.report_kind, 'static_source_interpretation');
  assert.equal(report.pool_context.pair_contract, 'PancakePair');
  assert.deepEqual(report.pool_context.bindings.map(b => [b.slot, b.contract, b.proves_deployed_address]), [
    ['token0', 'ARK', false], ['token1', 'ARK', false],
  ]);
  assert.deepEqual(report.entrypoints.map(e => e.id), ['PancakePair.skim', 'PancakePair.sync', 'PancakePair.swap']);
  assert.equal(report.entrypoints.every(e => e.full_analysis === false), true);
  assert.ok(report.entrypoints.every(e => e.paths.length <= 10 && e.generated_path_count >= e.path_count));
  assert.ok(report.entrypoints[0].paths.some(p => p.call_trace.some(e => e.contractInstance === 'ARK' || e.contractInstance === 'token0')));
  assert.ok(report.entrypoints[2].summary.normal_return_candidates > 0);
  assert.equal(JSON.stringify(report).includes('ENV:pair.'), false);
  assert.ok(report.entrypoints.flatMap(e => e.paths).every(p => p.execution_evidence.kind === 'none'));
});

test('non-empty swap callback without a supplied callback source remains unresolved in the CLI report', t => {
  if (!available) return t.skip('ARK V2 source checkout is not available at the configured path');
  const { result, report } = runPool({
    skim: { to: 'recipient' },
    swap: { amount0Out: 1, amount1Out: 0, to: 'callback', data: '0x01' },
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  const swap = report.entrypoints.find(e => e.id === 'PancakePair.swap');
  assert.ok(swap.summary.unresolved_paths > 0);
  assert.equal(swap.analysis_status, 'partial');
  assert.ok(swap.paths.some(p => p.status === 'unresolved_path' && p.unresolved_operations.some(x => /external receiver/.test(x))));
  assert.equal(swap.paths.some(p => p.modeled_outcome === 'normal_return_candidate'), false);
});
