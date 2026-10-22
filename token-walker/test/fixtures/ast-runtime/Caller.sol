// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {
    function transfer(bool shouldFail) external returns (bool);
}

contract Caller {
    uint256 public beforeCall;
    uint256 public afterCall;
    IToken public token;

    constructor(IToken token_) {
        token = token_;
    }

    function run(bool shouldFail) external {
        beforeCall += 1;
        bool callShouldFail = shouldFail;
        callShouldFail = shouldFail;
        token.transfer(callShouldFail);
        afterCall += 1;
    }
}
