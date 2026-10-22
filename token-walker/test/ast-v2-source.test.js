const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Index } = require('../dist/parse.js');
const { AstTransactionAdapter } = require('../dist/ast-transaction.js');
const { knownValue } = require('../dist/transaction.js');

const sourceRoot = '/run/media/glitch/Glitch/BUG-Bounty/PRIVATE/TKN/ARK/src';
const pancakeFile = path.join(sourceRoot, 'Pancake/PancakePair/PancakePair.sol');
const uniswapFile = path.join(sourceRoot, 'Uniswap/UniswapV2Pair/UniswapV2Pair.sol');
const arkFile = path.join(sourceRoot, 'ARK/ARK.sol');
const sourceAvailable = [pancakeFile, uniswapFile, arkFile].every(fs.existsSync);

function load(files) {
  const index = new Index();
  for (const file of files) index.addFile(file);
  assert.deepEqual(index.failedFiles, []);
  assert.deepEqual(index.parseErrors, []);
  return index;
}

test('real Pancake and Uniswap V2 swap/skim/sync and helpers resolve uniquely from parsed source', t => {
  if (!sourceAvailable) return t.skip('ARK V2 source checkout is not available at the configured path');
  const index = load([pancakeFile, uniswapFile]);
  for (const [contract, names] of [
    ['PancakePair', ['swap', 'skim', 'sync', 'getReserves', '_safeTransfer', '_update']],
    ['UniswapV2Pair', ['swap', 'skim', 'sync', 'getReserves', '_safeTransfer', '_update']],
  ]) {
    for (const name of names) assert.equal(index.findFns(contract, name, name === 'swap' ? 4 : name === 'skim' ? 1 : name === 'getReserves' ? 0 : name === '_safeTransfer' ? 3 : name === '_update' ? 4 : 0).length, 1, `${contract}.${name}`);
    assert.ok(index.findModifier(contract, 'lock'), `${contract}.lock`);
  }
  const lock = index.findModifier('PancakePair', 'lock');
  assert.deepEqual(lock.node.body.statements.map(s => s.type === 'ExpressionStatement' && s.expression?.type === 'Identifier' && s.expression.name === '_' ? 'placeholder' : s.type), [
    'ExpressionStatement', 'ExpressionStatement', 'placeholder', 'ExpressionStatement',
  ]);
  assert.equal(index.contracts.get('PancakePair').fns.find(f => f.name === 'swap').line, 452);
  assert.equal(index.contracts.get('UniswapV2Pair').fns.find(f => f.name === 'swap').line, 454);
  const pancakeSwap = index.contracts.get('PancakePair').fns.find(f => f.name === 'swap').node;
  const uniswapSwap = index.contracts.get('UniswapV2Pair').fns.find(f => f.name === 'swap').node;
  const pancakeText = index.fileSrc.get(pancakeFile).slice(pancakeSwap.range[0], pancakeSwap.range[1] + 1);
  const uniswapText = index.fileSrc.get(uniswapFile).slice(uniswapSwap.range[0], uniswapSwap.range[1] + 1);
  assert.match(pancakeText, /mul\(10000\).*mul\(25\)/s, 'Pancake fee arithmetic stays source-specific');
  assert.match(uniswapText, /mul\(1000\).*mul\(3\)/s, 'Uniswap fee arithmetic stays source-specific');
});

test('real getReserves executes its AST and returns named tuple values to the caller', t => {
  if (!sourceAvailable) return t.skip('ARK V2 source checkout is not available at the configured path');
  const index = load([pancakeFile]);
  const adapter = new AstTransactionAdapter(index, [{ id: 'pair', contract: 'PancakePair', source: pancakeFile }]);
  const [run] = adapter.runRoot('pair', 'getReserves', [], knownValue('caller', 'caller', 'user_assumption'));
  assert.equal(run.status, 'returned');
  assert.equal(run.path.classification.path_source, 'static_interpretation');
  assert.deepEqual(run.path.classification.execution_evidence, { kind: 'none' });
  assert.ok(run.returnValue?.known && Array.isArray(run.returnValue.value));
  assert.equal(run.returnValue.value.length, 3);
  assert.match(run.returnValue.value[0].expression, /reserve0/);
  assert.match(run.returnValue.value[1].expression, /reserve1/);
  assert.ok(run.path.trace.some(e => e.kind === 'read' && e.detail.cell.variable === 'reserve0'));
});

test('real swap lock modifier writes before body revert and transaction rollback preserves attempt trace', t => {
  if (!sourceAvailable) return t.skip('ARK V2 source checkout is not available at the configured path');
  const index = load([pancakeFile]);
  const adapter = new AstTransactionAdapter(index, [{ id: 'pair', contract: 'PancakePair', source: pancakeFile }]);
  const runs = adapter.runRoot('pair', 'swap', [knownValue(0), knownValue(0), knownValue('recipient'), knownValue('0x')], knownValue('caller'));
  const run = runs.find(r => r.status === 'reverted' && r.path.writes.some(w => w.cell.variable === 'unlocked'));
  assert.ok(run, 'expected the modifier-true path to write the lock before the body guard reverts');
  const trace = run.path.trace;
  assert.ok(trace.findIndex(e => e.kind === 'modifier_enter' && e.detail.modifier === 'PancakePair.lock') < trace.findIndex(e => e.kind === 'write' && e.detail.cell.variable === 'unlocked'));
  assert.ok(trace.findIndex(e => e.kind === 'write' && e.detail.cell.variable === 'unlocked') < trace.findIndex(e => e.kind === 'call_revert'));
  assert.ok(trace.some(e => e.kind === 'rollback' && e.detail.scope === 'transaction'));
  assert.ok(run.path.writes.every(w => w.disposition === 'rolled_back'));
  assert.equal(run.path.storage.size, 0);
  assert.deepEqual(run.path.classification.execution_evidence, { kind: 'none' });
});

test('real swap resolves internal getReserves, binds tuple components, then remains unresolved at unsupported transfer', t => {
  if (!sourceAvailable) return t.skip('ARK V2 source checkout is not available at the configured path');
  const index = load([pancakeFile]);
  const adapter = new AstTransactionAdapter(index, [{ id: 'pair', contract: 'PancakePair', source: pancakeFile }]);
  const runs = adapter.runRoot('pair', 'swap', [knownValue(1), knownValue(0), knownValue('recipient'), knownValue('0x')], knownValue('caller'));
  const run = runs.find(r => r.status === 'unresolved' && r.path.trace.some(e => e.kind === 'call_enter' && e.function === 'getReserves'));
  assert.ok(run, 'expected parsed swap to enter parsed getReserves');
  assert.ok(run.path.trace.some(e => e.kind === 'call_return' && e.detail.calleeInstance === 'pair'));
  assert.ok(run.path.trace.some(e => e.kind === 'branch' && /storage\[pair\]\.reserve0/.test(e.detail.condition)));
  assert.ok(run.path.trace.some(e => e.kind === 'branch' && /storage\[pair\]\.reserve1/.test(e.detail.condition)));
  assert.ok(run.path.flags.some(flag => /unresolved_call:unresolved low-level call target token/.test(flag)), 'without an explicit token binding, low-level transfer target remains unresolved');
  assert.equal(run.path.classification.modeled_outcome, 'unresolved');
  assert.deepEqual(run.path.classification.execution_evidence, { kind: 'none' });
  assert.equal(run.path.writes.some(w => w.cell.variable === '_reserve0' || w.cell.variable === '_reserve1'), false, 'tuple locals must not become storage writes');
});

test('real sync and skim enter explicitly bound ARK source and keep cross-contract results separate', t => {
  if (!sourceAvailable) return t.skip('ARK source checkout is not available at the configured path');
  const index = load([pancakeFile, arkFile]);
  const instances = [
    { id: 'pair', contract: 'PancakePair', source: pancakeFile, binding: { kind: 'user_supplied_source_analysis', detail: 'token0=ARK, token1=ARK for source analysis only' } },
    { id: 'ark', contract: 'ARK', source: arkFile },
  ];
  const adapter = new AstTransactionAdapter(index, instances, { receivers: { 'pair.token0': 'ark', 'pair.token1': 'ark' } });
  const syncRuns = adapter.runRoot('pair', 'sync', [], knownValue('caller'));
  const sync = syncRuns.find(r => r.path.trace.some(e => e.kind === 'write' && e.detail.cell.contractInstance === 'pair' && e.detail.cell.variable === 'reserve0'));
  assert.ok(sync, 'at least one symbolic branch reaches reserve updates');
  const balanceCalls = sync.path.trace.filter(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === 'balanceOf');
  assert.ok(balanceCalls.length >= 2, 'sync enters both parsed ARK balanceOf calls');
  assert.ok(balanceCalls.every(e => e.detail.msgSender.expression === 'pair'), 'token sees Pair as msg.sender');
  assert.ok(sync.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'pair' && e.function === '_update'));
  assert.ok(sync.path.trace.some(e => e.kind === 'write' && e.detail.cell.contractInstance === 'pair' && e.detail.cell.variable === 'reserve0'));
  assert.ok(sync.path.trace.some(e => e.kind === 'event' && e.detail.name === 'Sync'));
  assert.equal(sync.path.classification.path_source, 'static_interpretation');
  assert.deepEqual(sync.path.classification.execution_evidence, { kind: 'none' });

  const skimRuns = adapter.runRoot('pair', 'skim', [knownValue('recipient')], knownValue('caller'));
  const intoArkTransfer = skimRuns.find(r => r.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === 'transfer'));
  assert.ok(intoArkTransfer, 'skim reaches parsed _safeTransfer, selector dispatch, and ARK.transfer');
  assert.ok(intoArkTransfer.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === '_collectGovernance'));
  assert.ok(intoArkTransfer.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === '_update'));
  assert.ok(intoArkTransfer.path.trace.some(e => e.kind === 'call_unresolved' || e.kind === 'call_revert'), 'unsupported token behavior remains unresolved or a modeled revert candidate');
  assert.ok(intoArkTransfer.path.writes.every(w => w.cell.contractInstance === 'ark' || w.cell.contractInstance === 'pair'));
  assert.equal(intoArkTransfer.path.classification.execution_evidence.kind, 'none');
});

test('real Uniswap V2 skim dispatches its parsed low-level transfer into bound ARK source', t => {
  if (!sourceAvailable) return t.skip('ARK source checkout is not available at the configured path');
  const index = load([uniswapFile, arkFile]);
  const adapter = new AstTransactionAdapter(index, [
    { id: 'pair', contract: 'UniswapV2Pair', source: uniswapFile, binding: { kind: 'user_supplied_source_analysis', detail: 'token0=ARK, token1=ARK for source analysis only' } },
    { id: 'ark', contract: 'ARK', source: arkFile },
  ], { receivers: { 'pair.token0': 'ark', 'pair.token1': 'ark' } });
  const runs = adapter.runRoot('pair', 'skim', [knownValue('recipient')], knownValue('caller'));
  const pathIntoArk = runs.find(r => r.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === 'transfer'));
  assert.ok(pathIntoArk, 'Uniswap skim follows its actual _safeTransfer selector into ARK.transfer');
  assert.ok(pathIntoArk.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === 'balanceOf'));
  assert.equal(pathIntoArk.path.classification.path_source, 'static_interpretation');
  assert.deepEqual(pathIntoArk.path.classification.execution_evidence, { kind: 'none' });
});

test('parsed lock modifier executes its suffix after normal body completion and rolls all writes back on revert', () => {
  const file = path.join(__dirname, 'fixtures', 'ast-runtime', 'ModifierFixture.sol');
  const index = load([file]);
  const adapter = new AstTransactionAdapter(index, [{ id: 'fixture', contract: 'ModifierFixture', source: file }]);
  const [normal] = adapter.runRoot('fixture', 'run', [knownValue(false)], knownValue('caller'));
  assert.equal(normal.status, 'returned');
  assert.deepEqual(normal.path.writes.map(w => w.cell.variable), ['unlocked', 'count', 'unlocked']);
  assert.equal(normal.path.writes[0].after.value, 0);
  assert.match(normal.path.writes[1].after.expression, /storage\[fixture\]\.count \+ 1/);
  assert.equal(normal.path.writes[2].after.value, 1);
  const enter = normal.path.trace.findIndex(e => e.kind === 'modifier_enter');
  const exit = normal.path.trace.findIndex(e => e.kind === 'modifier_exit');
  assert.ok(enter >= 0 && exit > enter);
  assert.ok(normal.path.trace.findIndex(e => e.kind === 'write' && e.detail.cell.variable === 'count') < exit);

  const [failed] = adapter.runRoot('fixture', 'run', [knownValue(true)], knownValue('caller'));
  assert.equal(failed.status, 'reverted');
  assert.ok(failed.path.writes.some(w => w.cell.variable === 'unlocked' && w.disposition === 'rolled_back'));
  assert.equal(failed.path.writes.some(w => w.cell.variable === 'count'), false);
  assert.ok(failed.path.trace.some(e => e.kind === 'rollback' && e.detail.scope === 'transaction'));
});

test('ARK inherited _msgSender resolves and preserves the root caller; transfer enters its parsed helper chain', t => {
  if (!sourceAvailable) return t.skip('ARK source checkout is not available at the configured path');
  const index = load([arkFile]);
  const instances = [{ id: 'ark', contract: 'ARK', source: arkFile }];
  assert.equal(index.findFns('ARK', '_msgSender', 0).length, 1);
  assert.equal(index.findFns('ARK', 'transfer', 2).length, 1);
  assert.equal(index.findFns('ARK', '_collectGovernance', 3).length, 1);
  assert.equal(index.findFns('ARK', '_transfer', 3).length, 1);
  assert.equal(index.findFns('ARK', '_update', 3).length, 1);
  assert.equal(index.findFns('ARK', '_update', 3)[0].contract, 'ERC20', 'inherited implementation resolves to ERC20 source');
  const adapter = new AstTransactionAdapter(index, instances);
  const [sender] = adapter.runRoot('ark', '_msgSender', [], knownValue('caller', 'caller', 'user_assumption'));
  assert.equal(sender.status, 'returned');
  assert.equal(sender.returnValue.value, 'caller');
  assert.equal(sender.path.classification.execution_evidence.kind, 'none');

  const transferRuns = adapter.runRoot('ark', 'transfer', [knownValue('recipient'), knownValue(10)], knownValue('caller'));
  assert.ok(transferRuns.some(r => r.path.trace.some(e => e.kind === 'call_enter' && e.function === '_msgSender')));
  assert.ok(transferRuns.some(r => r.path.trace.some(e => e.kind === 'call_enter' && e.function === '_collectGovernance')));
  assert.ok(transferRuns.some(r => r.path.trace.some(e => e.kind === 'call_enter' && e.function === '_transfer')));
  assert.ok(transferRuns.some(r => r.path.trace.some(e => e.kind === 'call_enter' && e.function === '_update' && e.detail.implementation.contract === 'ERC20' && e.detail.implementation.source === arkFile)));
  assert.ok(transferRuns.some(r => r.path.writes.some(w => w.cell.contractInstance === 'ark' && w.cell.variable === '_balances')),
    'inherited _update performs parsed mapping writes in the ARK instance namespace');
  assert.ok(transferRuns.some(r => r.path.writes.some(w => w.cell.contractInstance === 'ark' && w.cell.variable === '_totalSupply')),
    'the parsed governance/update call chain reaches the inherited supply write when its source branch is selected');
  assert.ok(transferRuns.some(r => r.path.trace.some(e => e.kind === 'event' && e.detail.name === 'Transfer')),
    'inherited _update emits its parsed Transfer event after balance updates');
  assert.ok(transferRuns.some(r => r.status === 'returned') && transferRuns.some(r => r.status === 'reverted'));
  assert.ok(transferRuns.every(r => r.path.classification.execution_evidence.kind === 'none'));
});

test('real Pancake skim reaches parsed ARK balance writes and returns through Pair lock cleanup', t => {
  if (!sourceAvailable) return t.skip('ARK V2 source checkout is not available at the configured path');
  const index = load([pancakeFile, arkFile]);
  const adapter = new AstTransactionAdapter(index, [
    { id: 'pair', contract: 'PancakePair', source: pancakeFile },
    { id: 'ark', contract: 'ARK', source: arkFile },
  ], { receivers: { 'pair.token0': 'ark', 'pair.token1': 'ark' } });
  const runs = adapter.runRoot('pair', 'skim', [knownValue('recipient')], knownValue('caller'));
  const run = runs.find(r => r.status === 'returned' && r.path.trace.some(e => e.contractInstance === 'ark' && e.function === '_update'));
  assert.ok(run, 'a modeled normal-return candidate traverses skim -> _safeTransfer -> ARK.transfer -> inherited _update');
  assert.ok(run.path.writes.some(w => w.cell.contractInstance === 'ark' && w.cell.variable === '_balances'));
  assert.ok(run.path.trace.some(e => e.kind === 'event' && e.detail.name === 'Transfer'));
  const lockWrites = run.path.trace.filter(e => e.kind === 'write' && e.detail.cell.contractInstance === 'pair' && e.detail.cell.variable === 'unlocked');
  assert.equal(lockWrites.length, 2, 'lock is acquired before skim body and reset after return');
  assert.ok(run.path.trace.findIndex(e => e.kind === 'event' && e.detail.name === 'Transfer') < run.path.trace.findLastIndex(e => e.kind === 'write' && e.detail.cell.variable === 'unlocked'));
  assert.equal(run.path.classification.modeled_outcome, 'normal_return_candidate');
  assert.deepEqual(run.path.classification.execution_evidence, { kind: 'none' });
});

test('real Pancake and Uniswap sync resolve UQ112x112 calls, write reserves and emit Sync only on normal candidates', t => {
  if (!sourceAvailable) return t.skip('ARK V2 source checkout is not available at the configured path');
  for (const [file, contract] of [[pancakeFile, 'PancakePair'], [uniswapFile, 'UniswapV2Pair']]) {
    const index = load([file, arkFile]);
    const adapter = new AstTransactionAdapter(index, [
      { id: 'pair', contract, source: file }, { id: 'ark', contract: 'ARK', source: arkFile },
    ], { receivers: { 'pair.token0': 'ark', 'pair.token1': 'ark' } });
    const runs = adapter.runRoot('pair', 'sync', [], knownValue('caller'));
    assert.ok(runs.some(r => r.status === 'returned' && r.path.trace.some(e => e.function === 'encode') && r.path.trace.some(e => e.function === 'uqdiv')));
    const normal = runs.find(r => r.status === 'returned' && r.path.trace.some(e => e.kind === 'event' && e.detail.name === 'Sync'));
    assert.ok(normal, `${contract} normal-return candidate`);
    assert.ok(normal.path.trace.some(e => e.kind === 'write' && e.detail.cell.contractInstance === 'pair' && e.detail.cell.variable === 'reserve0'));
    assert.ok(normal.path.trace.some(e => e.kind === 'write' && e.detail.cell.contractInstance === 'pair' && e.detail.cell.variable === 'reserve1'));
    assert.ok(normal.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === 'balanceOf'));
    assert.deepEqual(normal.path.classification.execution_evidence, { kind: 'none' });
    const failed = runs.find(r => r.status === 'reverted');
    assert.ok(failed);
    assert.ok(failed.path.writes.every(w => w.disposition === 'rolled_back'));
    assert.equal(failed.path.trace.some(e => e.kind === 'event' && e.detail.name === 'Sync'), false, 'reverted path cannot contain a post-revert Sync event');
  }
});

test('real Pancake and Uniswap swaps reach their parsed balance/invariant checks with distinct fee formulas', t => {
  if (!sourceAvailable) return t.skip('ARK V2 source checkout is not available at the configured path');
  for (const [file, contract, feeFactor, feeAmount] of [
    [pancakeFile, 'PancakePair', '10000', '25'],
    [uniswapFile, 'UniswapV2Pair', '1000', '3'],
  ]) {
    const index = load([file, arkFile]);
    const adapter = new AstTransactionAdapter(index, [
      { id: 'pair', contract, source: file }, { id: 'ark', contract: 'ARK', source: arkFile },
    ], { receivers: { 'pair.token0': 'ark', 'pair.token1': 'ark' } });
    const runs = adapter.runRoot('pair', 'swap', [knownValue(1), knownValue(0), knownValue('recipient'), knownValue('0x')], knownValue('caller'));
    const normal = runs.find(r => r.status === 'returned' && r.path.trace.some(e => e.kind === 'event' && e.detail.name === 'Swap'));
    assert.ok(normal, `${contract} has a source-interpreted normal-return candidate`);
    const invariant = normal.path.trace.find(e => e.kind === 'branch' && String(e.detail.condition).includes(' >= ') && String(e.detail.condition).includes(`(${feeFactor} ** 2)`));
    assert.ok(invariant, `${contract} executes its parsed invariant expression`);
    assert.match(String(invariant.detail.condition), new RegExp(`mul ${feeFactor}.*mul ${feeAmount}`, 's'));
    assert.ok(normal.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === 'transfer'));
    assert.ok(normal.path.trace.some(e => e.kind === 'call_enter' && e.contractInstance === 'ark' && e.function === 'balanceOf'));
    assert.ok(normal.path.trace.some(e => e.kind === 'event' && e.detail.name === 'Sync'));
    assert.ok(normal.path.trace.findIndex(e => e.kind === 'branch' && String(e.detail.condition).includes(' >= ') && String(e.detail.condition).includes(`(${feeFactor} ** 2)`)) < normal.path.trace.findIndex(e => e.kind === 'event' && e.detail.name === 'Swap'));
    assert.equal(normal.path.classification.modeled_outcome, 'normal_return_candidate');
    assert.deepEqual(normal.path.classification.execution_evidence, { kind: 'none' });
    const reverted = runs.find(r => r.status === 'reverted');
    assert.ok(reverted && reverted.path.writes.every(w => w.disposition === 'rolled_back'));
    assert.equal(reverted.path.trace.some(e => e.kind === 'event' && e.detail.name === 'Swap'), false);
  }
});

test('a real non-empty swap callback is unresolved without a bound callback contract source', t => {
  if (!sourceAvailable) return t.skip('ARK V2 source checkout is not available at the configured path');
  const index = load([pancakeFile, arkFile]);
  const adapter = new AstTransactionAdapter(index, [
    { id: 'pair', contract: 'PancakePair', source: pancakeFile }, { id: 'ark', contract: 'ARK', source: arkFile },
  ], { receivers: { 'pair.token0': 'ark', 'pair.token1': 'ark' } });
  const runs = adapter.runRoot('pair', 'swap', [knownValue(1), knownValue(0), knownValue('callback'), knownValue('0x01')], knownValue('caller'));
  assert.ok(runs.some(r => r.status === 'unresolved' && r.path.trace.some(e => e.kind === 'call_unresolved' && String(e.detail.reason).includes('external receiver'))));
  assert.equal(runs.some(r => r.status === 'returned'), false, 'an unresolved callback cannot become a normal-return candidate');
  assert.ok(runs.every(r => r.path.classification.execution_evidence.kind === 'none'));
});
