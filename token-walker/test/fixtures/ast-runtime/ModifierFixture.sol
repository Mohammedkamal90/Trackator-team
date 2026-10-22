pragma solidity ^0.8.20;

contract ModifierFixture {
    uint256 public unlocked = 1;
    uint256 public count;

    modifier lock() {
        require(unlocked == 1, "locked");
        unlocked = 0;
        _;
        unlocked = 1;
    }

    function run(bool shouldRevert) external lock {
        if (shouldRevert) revert("fixture revert");
        count = count + 1;
    }
}
