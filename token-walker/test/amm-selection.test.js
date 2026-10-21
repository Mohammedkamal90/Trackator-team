const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Ajv = require('ajv');
const bin = path.resolve(__dirname, '../dist/index.js');
const fixture = path.resolve(__dirname, 'fixtures/Reflection.sol');
const schema = require('../schema/token-state-graph.schema.json');
const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);

function tempOut() { return path.join(os.tmpdir(), `token-walker-amm-${process.pid}-${Math.random().toString(16).slice(2)}.json`); }
function cli(args, options = {}) { return spawnSync(process.execPath, [bin, fixture, '-o', tempOut(), '--quiet', '--no-timestamp', ...args], { encoding: 'utf8', ...options }); }
function runWithOutput(args, options = {}) {
  const out = tempOut();
  const result = spawnSync(process.execPath, [bin, fixture, '-o', out, '--quiet', '--no-timestamp', ...args], { encoding: 'utf8', ...options });
  if (result.status === 0) {
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    const reverted = path.join(path.dirname(out), `R-${path.basename(out)}`);
    fs.rmSync(out, { force: true }); fs.rmSync(reverted, { force: true });
    return { result, doc };
  }
  return { result };
}

test('--amm selects one model and records CLI source; output validates against schema', () => {
  const { result, doc } = runWithOutput(['--amm', 'v2']);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(doc.amm_selection, { models: ['v2'], source: 'cli_argument' });
  assert.deepEqual(doc.targets[0].amm_models.map(x => [x.model, x.status]), [['v2', 'implemented']]);
  assert.equal(validate(doc), true, JSON.stringify(validate.errors));
});

test('--amm accepts multiple models and reports V3/V4 unsupported without V2 fallback', () => {
  const { result, doc } = runWithOutput(['--amm', 'v4,v3,v2']);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(doc.amm_selection.models, ['v2', 'v3', 'v4']);
  assert.deepEqual(doc.targets[0].amm_models.map(x => [x.model, x.status]), [['v2', 'implemented'], ['v3', 'unsupported'], ['v4', 'unsupported']]);
  assert.match(doc.targets[0].amm_models[1].reason, /not implemented/);
  assert.equal(validate(doc), true, JSON.stringify(validate.errors));
});

test('V3-only selection does not enable V2 synthetic environment', () => {
  const { result, doc } = runWithOutput(['--amm', 'v3']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(doc.targets[0].env_model.enabled, false);
  assert.deepEqual(doc.targets[0].env_model.nodes, []);
  assert.equal(doc.targets[0].amm_models[0].status, 'unsupported');
});

test('--amm rejects invalid, empty, and duplicate values with usage exit code 2', () => {
  for (const value of ['v5', 'v2,,v3', 'v2,v2']) {
    const { result } = runWithOutput(['--amm', value]);
    assert.equal(result.status, 2, `${value}: ${result.stderr}`);
    assert.match(result.stderr, /AMM model|--amm expects/);
  }
});

test('piped non-interactive execution does not prompt and retains V2 default', () => {
  const { result, doc } = runWithOutput([], { input: '' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(doc.amm_selection, { models: ['v2'], source: 'backward_compatible_default' });
  assert.ok(doc.targets[0].env_model.nodes.some(n => n.id.startsWith('ENV:pair.')));
  assert.doesNotMatch(result.stdout + result.stderr, /Select AMM model/);
});

test('interactive terminal accepts a multiple-model selection', t => {
  const probe = spawnSync('script', ['-qec', 'true', '/dev/null'], { encoding: 'utf8' });
  if (probe.error || probe.status !== 0) return t.skip('util-linux script is unavailable');
  const out = tempOut();
  const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(bin)} ${JSON.stringify(fixture)} -o ${JSON.stringify(out)} --quiet --no-timestamp`;
  const result = spawnSync('script', ['-qec', command, '/dev/null'], { encoding: 'utf8', input: 'v3,v4\n', timeout: 30000 });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
  const reverted = path.join(path.dirname(out), `R-${path.basename(out)}`);
  fs.rmSync(out, { force: true }); fs.rmSync(reverted, { force: true });
  assert.deepEqual(doc.amm_selection, { models: ['v3', 'v4'], source: 'interactive_user_input' });
  assert.deepEqual(doc.targets[0].amm_models.map(x => x.status), ['unsupported', 'unsupported']);
  assert.match(result.stdout + result.stderr, /Select AMM model/);
});
