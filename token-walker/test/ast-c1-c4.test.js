const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { AstTransactionAdapter } = require('../dist/ast-transaction.js');
const { Index } = require('../dist/parse.js');
const { knownValue, symbolicValue } = require('../dist/transaction.js');

const fixture = path.join(__dirname, 'fixtures', 'ast-c1-c4');
function setup() {
  const index = new Index();
  index.addFile(path.join(fixture, 'BranchCaller.sol'));
  index.addFile(path.join(fixture, 'StorageCases.sol'));
  assert.deepEqual(index.failedFiles, []);
  assert.deepEqual(index.parseErrors, []);
  const instances = [
    { id: 'caller', contract: 'BranchCaller', source: 'BranchCaller.sol' },
    { id: 'token', contract: 'BranchValues', source: 'BranchCaller.sol' },
    { id: 'store', contract: 'StorageCases', source: 'StorageCases.sol' },
  ];
  return { index, adapter: new AstTransactionAdapter(index, instances, { receivers: { 'caller.token': 'token' } }) };
}

test('C1: existing and declared locals remain branch-specific across external return forks', () => {
  const { adapter } = setup();
  for (const fn of ['existingLocal', 'declaredLocal']) {
    const runs = adapter.runRoot('caller', fn, [], knownValue('user', 'user', 'user_assumption'));
    assert.equal(runs.length, 2);
    assert.deepEqual(runs.map(r => r.status), ['returned', 'returned']);
    assert.deepEqual(runs.map(r => r.returnValue.value).sort((a, b) => Number(a) - Number(b)), [11, 22]);
    assert.equal(new Set(runs.map(r => r.returnValue.value)).size, 2);
  }
});

test('C2: all six unsigned compound assignments write state and subsequent reads observe those writes', () => {
  const { adapter } = setup();
  const [run] = adapter.runRoot('store', 'compoundOps', [], knownValue('user', 'user', 'user_assumption'));
  assert.equal(run.status, 'returned');
  assert.equal(run.path.writes.length, 6);
  assert.deepEqual(run.path.writes.map(w => w.cell.variable), ['flags', 'cnt', 'flags', 'flags', 'flags', 'flags']);
  assert.match(run.path.writes[0].after.expression, /\|/);
  assert.match(run.path.writes[1].after.expression, /%/);
  assert.match(run.path.writes[2].after.expression, /&/);
  assert.match(run.path.writes[3].after.expression, /\^/);
  assert.match(run.path.writes[4].after.expression, /<</);
  assert.match(run.path.writes[5].after.expression, />>/);
  for (const name of ['flags', 'cnt']) {
    assert.equal(run.path.trace.filter(e => e.kind === 'read' && e.detail.cell.variable === name).at(-1).detail.value.provenance, 'prior_modeled_write');
  }
});

test('unsupported compound-assignment type is unresolved instead of silently omitted', () => {
  const { adapter } = setup();
  const [run] = adapter.runRoot('store', 'unsupportedSignedCompound', [], knownValue('user', 'user', 'user_assumption'));
  assert.equal(run.status, 'unresolved');
  assert.equal(run.path.classification.modeled_outcome, 'unresolved');
  assert.equal(run.path.writes.length, 0);
});

test('C3: wei, gwei, ether are exact denominations and never bare numeric one', () => {
  const { adapter } = setup();
  const [units] = adapter.runRoot('store', 'units', [], knownValue('user', 'user', 'user_assumption'));
  assert.equal(units.status, 'returned');
  assert.deepEqual(units.returnValue.value.map(v => v.value), [1n, 1_000_000_000n, 1_000_000_000_000_000_000n]);

  const [guard] = adapter.runRoot('store', 'unitGuard', [], knownValue('user', 'user', 'user_assumption'));
  assert.equal(guard.status, 'returned');
  assert.equal(guard.path.writes.some(w => w.cell.variable === 'marker'), false);
});

test('C4: equivalent address(this) mapping keys alias, while distinct symbolic keys stay distinct', () => {
  const { adapter } = setup();
  const [same] = adapter.runRoot('store', 'sameKey', [], knownValue('user', 'user', 'user_assumption'));
  assert.equal(same.status, 'returned');
  assert.equal(same.returnValue.value, 7);
  const mappingWrites = same.path.writes.filter(w => w.cell.variable === 'bal');
  const mappingReads = same.path.trace.filter(e => e.kind === 'read' && e.detail.cell.variable === 'bal');
  assert.equal(mappingWrites.length, 1);
  assert.ok(mappingReads.length >= 2);
  assert.equal(mappingWrites[0].cell.keys[0], mappingReads[0].detail.cell.keys[0]);
  assert.equal(mappingWrites[0].cell.keys[0], mappingReads[1].detail.cell.keys[0]);

  const distinct = adapter.runRoot('store', 'distinctKeys', [symbolicValue('symbolic.a'), symbolicValue('symbolic.b')], knownValue('user', 'user', 'user_assumption'));
  assert.equal(distinct.length, 2);
  assert.deepEqual(new Set(distinct.map(r => r.status)), new Set(['returned', 'reverted']));
  for (const outcome of distinct) {
    const p = outcome.path;
    const write = p.writes.find(w => w.cell.variable === 'values');
    const read = p.trace.filter(e => e.kind === 'read' && e.detail.cell.variable === 'values').at(-1);
    assert.notEqual(write.cell.keys[0], read.detail.cell.keys[0]);
    assert.equal(read.detail.value.provenance, 'unknown_initial_state');
  }
});
