# Foundry concrete-reference tests

The Phase 1.5 EVM tests execute the same Solidity source files parsed by the static AST adapter under `test/fixtures/ast-runtime/`. Their concrete results are an independent reference and are not attached as execution evidence to static paths.

Run from the token-walker repository root:

```sh
FOUNDRY_TEST=test/foundry/test FOUNDRY_SRC=test/fixtures/ast-runtime forge test --root . --match-path test/foundry/test/RuntimeReference.t.sol
```

Keep Foundry results separate from the static interpreter suite. Future Phase 2 differential fixtures can be added here after review.
