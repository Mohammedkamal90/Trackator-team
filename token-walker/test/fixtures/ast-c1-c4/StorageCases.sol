pragma solidity ^0.8.20;

contract StorageCases {
    uint256 flags;
    uint256 cnt;
    uint256 marker;
    int256 signedFlags;
    mapping(address => uint256) bal;
    mapping(uint256 => uint256) values;

    function compoundOps() external returns (uint256) {
        flags |= 4;
        cnt %= 7;
        flags &= 6;
        flags ^= 2;
        flags <<= 1;
        flags >>= 1;
        uint256 lastCount = cnt;
        return flags + lastCount;
    }

    function units() external returns (uint256 weiValue, uint256 gweiValue, uint256 etherValue) {
        weiValue = 1 wei;
        gweiValue = 1 gwei;
        etherValue = 1 ether;
    }

    function unitGuard() external {
        if (1 ether == 1) marker = 9;
    }

    function unsupportedSignedCompound() external {
        signedFlags |= 1;
    }

    function sameKey() external returns (uint256 result) {
        bal[address(this)] = 7;
        require(bal[address(this)] == 7);
        result = bal[address(this)];
    }

    function distinctKeys(uint256 a, uint256 b) external {
        values[a] = 7;
        require(values[b] == 7);
    }
}
