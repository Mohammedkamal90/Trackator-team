// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract AccessSem {
    address public owner; address public lastCaller; address public opsManager;
    mapping(address => bool) public registered; mapping(address => bool) public adminSet;
    uint256 public a; uint256 public b; uint256 public c; uint256 public d;
    function eqPlainVar() public { require(msg.sender == lastCaller); a = 1; }
    function registered() public { require(registered[msg.sender]); b = 1; }
    function rolenamed() public { require(msg.sender == opsManager); c = 1; }
    function ownerOnly() public { require(msg.sender == owner); d = 1; }
}
contract PairAlias {
    mapping(address => uint256) bal; address public pair;
    function balanceOf(address a) public view returns (uint256) { return bal[a]; }
    function transfer(address to, uint256 amt) public returns (bool) {
        if (to == pair) { bal[msg.sender] -= amt; bal[to] += amt; } else { bal[msg.sender] -= amt; bal[to] += amt; }
        return true;
    }
}
contract TryBody {
    uint256 public s; ITry public t;
    function f() public { try t.go() returns (uint256) { s = 1; } catch { s = 2; } }
}
interface ITry { function go() external returns (uint256); }
