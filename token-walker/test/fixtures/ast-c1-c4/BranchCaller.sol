pragma solidity ^0.8.20;

interface IBranchValues {
    function balanceOf(address account) external view returns (uint256);
}

contract BranchCaller {
    address token;

    function existingLocal() external returns (uint256 b) {
        b = 0;
        b = IBranchValues(token).balanceOf(address(this));
        return b;
    }

    function declaredLocal() external returns (uint256) {
        uint256 b = IBranchValues(token).balanceOf(address(this));
        return b;
    }
}

contract BranchValues {
    bool chooseFirst;

    function balanceOf(address) external view returns (uint256) {
        if (chooseFirst) return 11;
        return 22;
    }
}
