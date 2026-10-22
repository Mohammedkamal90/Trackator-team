// Concrete EVM reference for the source fixture used by the static AST adapter.
// Results from this suite are independent of token-walker's static classifications.
pragma solidity ^0.8.20;

import "../../fixtures/ast-runtime/Caller.sol";
import "../../fixtures/ast-runtime/Token.sol";

contract RuntimeReferenceTest {
    function testSuccessfulCallCommitsBothContractsInOrder() public {
        Token token = new Token();
        Caller caller = new Caller(IToken(address(token)));
        caller.run(false);
        require(caller.beforeCall() == 1, "caller pre-call write");
        require(token.balances(address(caller)) == 2, "token writes keyed by msg.sender");
        require(caller.afterCall() == 1, "caller post-call write");
    }

    function testCalleeRevertRollsBackTheWholeTransaction() public {
        Token token = new Token();
        Caller caller = new Caller(IToken(address(token)));
        (bool success, ) = address(caller).call(abi.encodeCall(caller.run, (true)));
        require(!success, "expected propagated revert");
        require(caller.beforeCall() == 0, "pre-call write rolled back");
        require(token.balances(address(caller)) == 0, "callee write rolled back");
        require(caller.afterCall() == 0, "post-call write not reached");
    }
}
