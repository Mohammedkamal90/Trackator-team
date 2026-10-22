// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Token {
    mapping(address => uint256) public balances;

    function transfer(bool shouldFail) external returns (bool) {
        balances[msg.sender] += 1;
        if (shouldFail) {
            revert("fixture failure");
        }
        balances[msg.sender] += 1;
        return true;
    }
}
