const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {
  AstTransactionAdapter,
} = require('../dist/ast-transaction.js');
const { Index } = require('../dist/parse.js');
const { knownValue } = require('../dist/transaction.js');

const fixture = path.join(__dirname, 'fixtures', 'ast-runtime');
function setup() {
  const index = new Index();
  index.addFile(path.join(fixture, 'Caller.sol'));
  index.addFile(path.join(fixture, 'Token.sol'));
  assert.deepEqual(index.failedFiles, []);
  assert.deepEqual(index.parseErrors, []);
  assert.ok(index.contracts.get('Caller').fns.some(f => f.name === 'run' && f.node.body));
  assert.ok(index.contracts.get('Token').fns.some(f => f.name === 'transfer' && f.node.body));
  const instances = [
    { id: 'caller-instance', contract: 'Caller', source: 'Caller.sol' },
    { id: 'token-instance', contract: 'Token', source: 'Token.sol' },
  ];
  const adapter = new AstTransactionAdapter(index, instances, {
    receivers: { 'caller-instance.token': 'token-instance' },
  });
  return { index, adapter };
}

test('parsed Solidity AST executes nested calls in source order with isolated contract storage', () => {
  const { adapter } = setup();
  const [run] = adapter.runRoot('caller-instance', 'run', [
    knownValue(false, 'shouldFail', 'user_assumption'),
  ], knownValue('user', 'user', 'user_assumption'));

  assert.equal(run.status, 'returned');
  assert.equal(run.path.classification.path_source, 'static_interpretation');
  assert.equal(run.path.classification.modeled_outcome, 'normal_return_candidate');
  assert.deepEqual(run.path.classification.execution_evidence, { kind: 'none' });

  const writes = run.path.writes;
  assert.deepEqual(writes.map(w => [w.cell.contractInstance, w.cell.variable]), [
    ['caller-instance', 'beforeCall'],
    ['token-instance', 'balances'],
    ['token-instance', 'balances'],
    ['caller-instance', 'afterCall'],
  ]);
  assert.ok(writes.filter(w => w.cell.contractInstance === 'token-instance').every(w => w.cell.keys[0] === 'caller-instance'));
  assert.equal(writes[2].before.provenance, 'prior_modeled_write');
  assert.equal(writes[2].before.expression, writes[1].after.expression);
  assert.ok(run.path.trace.some(e => e.kind === 'branch' && e.detail.condition === 'shouldFail' && e.detail.arm === 'false'));

  const enter = run.path.trace.find(e => e.kind === 'call_enter');
  const returned = run.path.trace.find(e => e.kind === 'call_return');
  assert.equal(enter.contractInstance, 'token-instance');
  assert.equal(enter.function, 'transfer');
  assert.equal(enter.detail.callerInstance, 'caller-instance');
  assert.equal(enter.detail.args[0].value, false);
  assert.equal(writes.some(w => w.cell.variable === 'callShouldFail'), false);
  assert.equal(returned.detail.resumedAt.source, path.join(fixture, 'Caller.sol'));
  assert.match(returned.detail.resumedAt.expression, /token\.transfer\(callShouldFail\)/);

  const writeSteps = run.path.trace.filter(e => e.kind === 'write').map(e => e.step);
  assert.deepEqual(writeSteps, [...writeSteps].sort((a, b) => a - b));
});

test('a parsed callee revert preserves attempted trace and rolls back caller and token writes', () => {
  const { adapter } = setup();
  const [run] = adapter.runRoot('caller-instance', 'run', [
    knownValue(true, 'shouldFail', 'user_assumption'),
  ], knownValue('user', 'user', 'user_assumption'));

  assert.equal(run.status, 'reverted');
  assert.equal(run.path.transactionStatus, 'reverted');
  assert.equal(run.path.classification.modeled_outcome, 'revert_candidate');
  assert.deepEqual(run.path.classification.execution_evidence, { kind: 'none' });
  assert.ok(run.path.writes.length >= 2);
  assert.ok(run.path.writes.every(w => w.disposition === 'rolled_back'));
  assert.ok(run.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'token-instance'));
  assert.ok(run.path.trace.some(e => e.kind === 'call_revert'));
  assert.ok(run.path.trace.some(e => e.kind === 'rollback' && e.detail.scope === 'transaction'));
  assert.equal(run.path.writes.some(w => w.cell.variable === 'afterCall'), false);
  assert.ok(run.path.trace.some(e => e.kind === 'branch' && e.detail.condition === 'shouldFail' && e.detail.arm === 'true'));
  assert.equal(run.path.storage.size, 0);
});

test('an unbound external receiver stays unresolved rather than being treated as a successful call', () => {
  const { index } = setup();
  const adapter = new AstTransactionAdapter(index, [
    { id: 'caller-instance', contract: 'Caller', source: 'Caller.sol' },
    { id: 'token-instance', contract: 'Token', source: 'Token.sol' },
  ]);
  const [run] = adapter.runRoot('caller-instance', 'run', [
    knownValue(false, 'shouldFail', 'user_assumption'),
  ], knownValue('user', 'user', 'user_assumption'));
  assert.equal(run.status, 'unresolved');
  assert.equal(run.path.classification.modeled_outcome, 'unresolved');
  assert.deepEqual(run.path.classification.execution_evidence, { kind: 'none' });
});
