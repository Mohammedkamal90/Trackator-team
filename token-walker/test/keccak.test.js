const { test } = require('node:test');
const assert = require('node:assert/strict');
const { keccak256Utf8, selectorForSignature } = require('../dist/keccak.js');

test('selector derivation uses Ethereum Keccak padding', () => {
  assert.equal(keccak256Utf8(''), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(selectorForSignature('transfer(address,uint256)'), '0xa9059cbb');
});
