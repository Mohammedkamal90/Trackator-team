// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// minimal reflection token: public deliver() shrinks _rTotal -> every holder (incl. the pair) is re-priced
contract Reflection {
    mapping(address => uint256) _rOwned;
    mapping(address => uint256) _tOwned;
    mapping(address => bool) _isExcluded;
    uint256 _tTotal = 1e12;
    uint256 _rTotal = 1e30;
    address public uniswapV2Pair;
    address public owner;
    function totalSupply() public view returns (uint256) { return _tTotal; }
    function balanceOf(address a) public view returns (uint256) {
        if (_isExcluded[a]) return _tOwned[a];
        return _rOwned[a] / _rate();
    }
    function _rate() internal view returns (uint256) { return _rTotal / _tTotal; }
    function transfer(address to, uint256 amt) public returns (bool) {
        uint256 r = amt * _rate();
        _rOwned[msg.sender] -= r;
        _rOwned[to] += r;
        return true;
    }
    function deliver(uint256 amt) public {
        require(!_isExcluded[msg.sender]);
        uint256 r = amt * _rate();
        _rOwned[msg.sender] -= r;
        _rTotal -= r;
    }
    function setPair(address p) public { require(msg.sender == owner); uniswapV2Pair = p; }
}
