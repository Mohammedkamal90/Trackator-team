// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title OracleWrapper
 * @notice Price oracle with spot and TWAP prices
 * ⚠️ Contains intentional vulnerability for testing: no TWAP validation in getPrice()
 */
interface IOracle {
    function getPrice() external view returns (uint256);
    function getTWAP(uint256 duration) external view returns (uint256);
}

contract OracleWrapper {
    address public admin;
    uint256 public spotPrice;
    uint256 public twapPrice;
    uint256 public lastUpdateTime;
    
    // ============ Events ============
    event PriceUpdated(uint256 oldSpot, uint256 newSpot, uint256 twap);
    event AdminChanged(address previousAdmin, address newAdmin);
    
    // ============ Modifiers ============
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }
    
    constructor() {
        admin = msg.sender;
        spotPrice = 2000 * 1e8; // $2000.00 (8 decimals)
        twapPrice = 2001 * 1e8; // $2001.00
        lastUpdateTime = block.timestamp;
    }
    
    /**
     * @notice Get current spot price
     * ⚠️ VULNERABILITY: Returns raw spot without TWAP validation
     */
    function getPrice() public view returns (uint256) {
        return spotPrice;
    }
    
    /**
     * @notice Get TWAP price
     */
    function getTWAP(uint256 /*duration*/) public view returns (uint256) {
        return twapPrice;
    }
    
    /**
     * @notice Check if price is fresh
     */
    function isPriceFresh(uint256 maxAge) public view returns (bool) {
        return (block.timestamp - lastUpdateTime) <= maxAge;
    }
    
    /**
     * @notice Calculate deviation between spot and TWAP
     */
    function getDeviation() public view returns (int256) {
        if (twapPrice == 0) return int256(spotPrice);
        return int256(spotPrice) - int256(twapPrice);
    }
    
    /**
     * @notice Get deviation as percentage basis points
     */
    function getDeviationBps() public view returns (int256) {
        if (twapPrice == 0) return int256(10000); // Max deviation
        
        int256 diff = int256(spotPrice) - int256(twapPrice);
        return (diff * 10000) / int256(twapPrice);
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Update oracle price
     * ⚠️ CRITICAL: Can set any price without validation
     */
    function updatePrice(uint256 _spotPrice, uint256 _twapPrice) external onlyAdmin {
        uint256 oldSpot = spotPrice;
        
        spotPrice = _spotPrice;
        twapPrice = _twapPrice;
        lastUpdateTime = block.timestamp;
        
        emit PriceUpdated(oldSpot, _spotPrice, _twapPrice);
    }
    
    /**
     * @notice Transfer admin role
     */
    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Zero address");
        address previousAdmin = admin;
        admin = newAdmin;
        emit AdminChanged(previousAdmin, newAdmin);
    }
}
