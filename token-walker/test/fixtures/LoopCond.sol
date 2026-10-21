// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract LoopCond {
    uint256 public x; uint256 public y;
    function alwaysFalse() external { while (false) { x = 1; } }
    function alwaysTrueBreak() external { while (true) { x = 2; break; } }
    function alwaysTrueNoBreak() external { while (true) { x = 9; } }
    function forInit() external { for (uint256 i = 1; i < 2; i++) { x = i; break; } }
    function doOnce() external { do { x = 3; } while (false); }
    function doTrue() external { do { x = 4; } while (true); }
    function pureLoop(uint256 n) external view returns (uint256 s) { for (uint256 i = 0; i < n; i++) { s += i; } }
    function effectLoop(uint256 n) external { for (uint256 i = 0; i < n; i++) { y += 1; } }
}
