// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// sell-side "burn from pair" pattern: token logic debits the pair's own balance
contract BurnFromPair {
    mapping(address => uint256) bal;
    address public pair;
    uint256 total = 1e18;
    function balanceOf(address a) public view returns (uint256) { return bal[a]; }
    function totalSupply() public view returns (uint256) { return total; }
    function transfer(address to, uint256 amt) public returns (bool) {
        if (to == pair) { bal[pair] -= amt / 10; total -= amt / 10; }
        bal[msg.sender] -= amt;
        bal[to] += amt;
        return true;
    }
}
