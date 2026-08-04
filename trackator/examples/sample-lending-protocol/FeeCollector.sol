// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title FeeCollector
 * @notice Collects and distributes protocol fees
 */
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract FeeCollector is ReentrancyGuard {
    using SafeERC20 for IERC20;
    
    address public protocol;
    address public treasury;
    address public admin;
    
    uint256 public totalFeesCollected;
    mapping(address => uint256) public feesByToken;
    
    // ============ Events ============
    event FeeCollected(address indexed token, uint256 amount);
    event FeesWithdrawn(address indexed token, address to, uint256 amount);
    event TreasuryUpdated(address oldTreasury, address newTreasury);
    event AdminChanged(address previousAdmin, address newAdmin);
    
    // ============ Modifiers ============
    modifier onlyProtocol() {
        require(msg.sender == protocol, "Only protocol");
        _;
    }
    
    modifier onlyAdmin() {
        require(msg.sender == admin || msg.sender == treasury, "Only admin/treasury");
        _;
    }
    
    constructor(address _treasury) {
        require(_treasury != address(0), "Zero address");
        admin = msg.sender;
        treasury = _treasury;
    }
    
    /**
     * @notice Set protocol address (once)
     */
    function setProtocol(address _protocol) external {
        require(protocol == address(0), "Already set");
        require(msg.sender == admin, "Only admin");
        
        protocol = _protocol;
    }
    
    /**
     * @notice Collect fees from protocol operations
     */
    function collectFees(address token, uint256 amount) external onlyProtocol nonReentrant {
        require(amount > 0, "Amount > 0");
        
        // Transfer fee tokens
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        
        // Update accounting
        totalFeesCollected += amount;
        feesByToken[token] += amount;
        
        emit FeeCollected(token, amount);
    }
    
    /**
     * @notice Withdraw accumulated fees to treasury
     */
    function withdrawFees(address token) external onlyAdmin nonReentrant {
        uint256 balance = feesByToken[token];
        require(balance > 0, "No fees to withdraw");
        
        // Update state before transfer (correct CEI)
        feesByToken[token] = 0;
        totalFeesCollected -= balance;
        
        // Transfer
        IERC20(token).safeTransfer(treasury, balance);
        
        emit FeesWithdrawn(token, treasury, balance);
    }
    
    /**
     * @notice Emergency withdraw (if token gets stuck)
     * ⚠️ Can withdraw any token - trust required
     */
    function emergencyWithdraw(address token, address to, uint256 amount) external onlyAdmin {
        require(to != address(0), "Zero address");
        IERC20(token).safeTransfer(to, amount);
    }
    
    // ============ Admin Functions ============
    
    function updateTreasury(address newTreasury) external onlyAdmin {
        require(newTreasury != address(0), "Zero address");
        address oldTreasury = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(oldTreasury, newTreasury);
    }
    
    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Zero address");
        address previousAdmin = admin;
        admin = newAdmin;
        emit AdminChanged(previousAdmin, newAdmin);
    }
}
