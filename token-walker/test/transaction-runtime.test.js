const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  TransactionPath, knownValue, symbolicValue,
} = require('../dist/transaction.js');

const instances = [
  { id: 'pair', contract: 'Pair', source: 'Pair.sol' },
  { id: 'token', contract: 'Token', source: 'Token.sol', binding: { kind: 'user_supplied_source_analysis', detail: 'token0=Token' } },
];
const root = () => new TransactionPath(instances, { instanceId: 'pair', fn: 'root', caller: knownValue('user') });

test('nested calls push contract-aware frames and return to the exact caller site', () => {
  const p = root();
  const result = p.invoke('token', 'transfer', [knownValue('recipient'), knownValue(7)], { source: 'Pair.sol', line: 40, expression: 'token.transfer(to, amount)' }, 'high_level', (child, args) => {
    assert.equal(child.frame.contractInstance, 'token');
    assert.equal(child.frame.function, 'transfer');
    assert.equal(child.frame.msgSender.value, 'pair');
    assert.equal(args[1].value, 7);
    return { status: 'returned', value: knownValue(true), returnData: TransactionPath.encodeBoolReturn(true) };
  })[0];
  assert.equal(result.status, 'returned');
  assert.equal(result.path.frame.contractInstance, 'pair');
  const returned = result.path.trace.find(e => e.kind === 'call_return');
  assert.equal(returned.detail.resumedAt.expression, 'token.transfer(to, amount)');
  assert.equal(returned.detail.resumedAt.line, 40);
});

test('contract storage is isolated and reads observe prior writes in the same instance', () => {
  const p = root();
  p.write('count', knownValue(1));
  assert.equal(p.read('count').value, 1);
  const child = p.invoke('token', 'touch', [], { source: 'Pair.sol', line: 8 }, 'high_level', q => {
    q.write('count', knownValue(9));
    return { status: 'returned' };
  })[0].path;
  assert.equal(child.read('count').value, 1);
  const tokenPath = child.clone();
  tokenPath.frames[0] = { ...tokenPath.frames[0], contractInstance: 'token', contract: 'Token' };
  assert.equal(tokenPath.read('count').value, 9);
  assert.equal(p.read('count').value, 1);
});

test('unknown predicates fork conditional arms without claiming reachability', () => {
  const [yes, no] = root().branch('whitelist[user]');
  assert.equal(yes.path.classification.reachability, 'conditional');
  assert.equal(no.path.classification.reachability, 'conditional');
  assert.deepEqual(yes.path.constraints, ['whitelist[user]']);
  assert.deepEqual(no.path.constraints, ['!(whitelist[user])']);
});

test('&& and || evaluate the right side only when Solidity short-circuit rules require it', () => {
  let andCalls = 0; let orCalls = 0;
  const p = root();
  const andFalse = p.and(knownValue(false), q => { andCalls++; return [{ path: q, value: knownValue(true) }]; });
  const orTrue = p.or(knownValue(true), q => { orCalls++; return [{ path: q, value: knownValue(false) }]; });
  assert.equal(andCalls, 0); assert.equal(orCalls, 0);
  assert.equal(andFalse[0].value.value, false); assert.equal(orTrue[0].value.value, true);
  const unknownAnd = p.and(symbolicValue('call.success'), q => {
    andCalls++;
    return [{ path: q, value: knownValue(true) }];
  });
  assert.equal(andCalls, 1);
  assert.equal(unknownAnd.length, 2);
  assert.deepEqual(unknownAnd.find(x => x.value.value === true).path.constraints, ['call.success']);
  assert.deepEqual(unknownAnd.find(x => x.value.value === false).path.constraints, ['!(call.success)']);
});

test('low-level success with ABI bool false differs from a reverted low-level call', () => {
  const p = root();
  const returnedFalse = p.invoke('token', 'transfer', [], { source: 'Pair.sol', line: 21 }, 'low_level', () => ({
    status: 'returned', value: knownValue(false), returnData: TransactionPath.encodeBoolReturn(false),
  }))[0];
  assert.equal(returnedFalse.status, 'returned');
  assert.equal(returnedFalse.success.value, true);
  assert.equal(TransactionPath.decodeBoolReturn(returnedFalse.returnData).value, false);

  const reverted = p.invoke('token', 'transfer', [], { source: 'Pair.sol', line: 21 }, 'low_level', q => {
    q.write('balance', knownValue(0));
    return { status: 'reverted', reason: 'token denied' };
  })[0];
  assert.equal(reverted.status, 'reverted');
  assert.equal(reverted.success.value, false);
  assert.equal(reverted.path.transactionStatus, 'active');
  assert.ok(reverted.path.writes.some(w => w.disposition === 'rolled_back'));
  assert.equal(reverted.path.read('balance').provenance, 'unknown_initial_state');
});

test('explicit storage assumptions seed initial state without becoming modeled writes', () => {
  const p = root();
  p.assumeStorage('whitelist', knownValue(true), ['alice']);
  assert.equal(p.read('whitelist', ['alice']).value, true);
  assert.equal(p.writes.length, 0);
});

test('static calls that attempt writes produce a revert candidate and roll back the callee write', () => {
  const result = root().invoke('token', 'balanceOf', [], { source: 'Pair.sol', line: 12 }, 'static_call', q => {
    q.write('counter', knownValue(1));
    return { status: 'returned', value: knownValue(0) };
  })[0];
  assert.equal(result.status, 'reverted');
  assert.equal(result.success.value, false);
  assert.ok(result.path.writes.every(w => w.disposition === 'rolled_back'));
});

test('unresolved child effects remain unresolved rather than being reported as rolled back', () => {
  const result = root().invoke('token', 'transfer', [], { source: 'Pair.sol', line: 22 }, 'low_level', q => {
    q.write('balance', symbolicValue('balance - amount'));
    return { status: 'unresolved', reason: 'branch depends on unknown initial balance' };
  })[0];
  assert.equal(result.status, 'unresolved');
  assert.ok(result.path.writes.some(w => w.disposition === 'unresolved'));
  assert.equal(result.path.classification.execution_evidence.kind, 'none');
});

test('high-level revert rolls back earlier caller and callee writes transaction-wide', () => {
  const p = root();
  p.write('before', knownValue(1));
  const result = p.invoke('token', 'transfer', [], { source: 'Pair.sol', line: 30 }, 'high_level', q => {
    q.write('balance', knownValue(0));
    return { status: 'reverted', reason: 'revert token transfer' };
  })[0];
  assert.equal(result.status, 'reverted');
  assert.equal(result.path.transactionStatus, 'reverted');
  assert.ok(result.path.writes.every(w => w.disposition === 'rolled_back'));
  assert.equal(result.path.classification.modeled_outcome, 'revert_candidate');
  assert.deepEqual(result.path.classification.execution_evidence, { kind: 'none' });
});

test('root normal return stays a candidate, while root revert rolls back the entire transaction', () => {
  const normal = root(); normal.write('x', knownValue(1)); normal.finishRoot();
  assert.equal(normal.classification.modeled_outcome, 'normal_return_candidate');
  assert.deepEqual(normal.classification.execution_evidence, { kind: 'none' });
  assert.equal(normal.writes[0].disposition, 'transaction_local');
  const failed = root(); failed.write('x', knownValue(1)); failed.revertRoot('pair invariant failed');
  assert.equal(failed.classification.modeled_outcome, 'revert_candidate');
  assert.equal(failed.writes[0].disposition, 'rolled_back');
  assert.equal(failed.trace.at(-1).kind, 'rollback');
});

test('unresolved call targets stay unresolved and do not become successful', () => {
  const result = root().invoke('missing', 'balanceOf', [], { source: 'Pair.sol', line: 10 }, 'high_level', () => ({ status: 'returned' }))[0];
  assert.equal(result.status, 'unresolved');
  assert.equal(result.path.classification.modeled_outcome, 'unresolved');
  assert.deepEqual(result.path.classification.execution_evidence, { kind: 'none' });
});

test('return-data helpers distinguish empty, unknown, valid bool, and malformed bool bytes', () => {
  assert.equal(TransactionPath.isEmptyReturnData({ status: 'known', bytesHex: '0x' }).value, true);
  assert.equal(TransactionPath.isEmptyReturnData({ status: 'known', bytesHex: '0x01' }).value, false);
  assert.equal(TransactionPath.isEmptyReturnData({ status: 'unknown', reason: 'opaque' }).known, false);
  assert.equal(TransactionPath.decodeBoolReturn({ status: 'known', bytesHex: '0x' + '0'.repeat(63) + '1' + '0'.repeat(64) }).value, true);
  assert.equal(TransactionPath.decodeBoolReturnResult({ status: 'known', bytesHex: '0x12' }).status, 'revert_candidate');
  assert.equal(TransactionPath.decodeBoolReturnResult({ status: 'unknown', reason: 'opaque call' }).status, 'unresolved');
});
