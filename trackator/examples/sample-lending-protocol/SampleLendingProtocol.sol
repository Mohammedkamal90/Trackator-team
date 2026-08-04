// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SampleLendingProtocol
 * @notice A simplified lending protocol for testing Trackator
 */
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./OracleWrapper.sol";
import "./FeeCollector.sol";

contract SampleLendingProtocol is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ============ State Variables ============
    
    // Core accounting
    uint256 public totalSupply;
    uint256 public totalBorrowed;
    uint256 public reserveBalance;
    
    // Oracle
    OracleWrapper public oracle;
    
    // Fee configuration
    uint256 public collateralFactor;     // e.g., 75% = 7500 (basis points)
    uint256 public liquidationBonus;   // e.g., 8% = 800 (basis points)
    uint256 public interestRate;       // Annual rate in basis points
    
    // User positions
    mapping(address => uint256) public userCollateral;
    mapping(address => uint256) public userDebt;
    mapping(address => bool) public hasDeposited;
    
    // Protocol state
    address public owner;
    address public guardian;
    bool public paused;
    
    // Supported assets
    IERC20 public collateralToken;
    IERC20 public borrowToken;
    
    FeeCollector public feeCollector;
    
    // ============ Events ============
    
    event Deposit(address indexed user, uint256 amount, uint256 shares);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);
    event Liquidation(
        address indexed victim, 
        address indexed liquidator, 
        uint256 debtRepaid, 
        uint256 collateralSeized
    );
    event Withdrawal(address indexed user, uint256 amount);
    event PriceUpdate(uint256 oldPrice, uint256 newPrice);
    event PauseChanged(bool paused, address account);
    event OwnershipTransferred(address previousOwner, address newOwner);
    
    // ============ Modifiers ============
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    modifier onlyGuardian() {
        require(msg.sender == guardian || msg.sender == owner, "Only guardian");
        _;
    }
    
    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }
    
    // ============ Constructor ============
    
    constructor(
        address _collateralToken,
        address _borrowToken,
        address _oracle,
        address _feeCollector,
        uint256 _collateralFactor,
        uint256 _liquidationBonus
    ) {
        require(_collateralFactor <= 9000, "CF too high");
        require(_liquidationBonus <= 1500, "Bonus too high");
        
        owner = msg.sender;
        guardian = msg.sender;
        
        collateralToken = IERC20(_collateralToken);
        borrowToken = IERC20(_borrowToken);
        oracle = OracleWrapper(_oracle);
        feeCollector = FeeCollector(_feeCollector);
        
        collateralFactor = _collateralFactor;
        liquidationBonus = _liquidationBonus;
        interestRate = 500; // 5%
    }
    
    // ============ User Functions ============
    
    /**
     * @notice Deposit collateral into the protocol
     * @param amount Amount of collateral token to deposit
     */
    function deposit(uint256 amount) external whenNotPaused nonReentrant {
        require(amount > 0, "Amount > 0");
        
        // Transfer collateral from user
        collateralToken.safeTransferFrom(msg.sender, address(this), amount);
        
        // Update state
        totalSupply += amount;
        userCollateral[msg.sender] += amount;
        hasDeposited[msg.sender] = true;
        
        emit Deposit(msg.sender, amount, amount);
    }
    
    /**
     * @notice Borrow tokens against collateral
     * @param amount Amount to borrow
     */
    function borrow(uint256 amount) external whenNotPaused nonReentrant {
        require(amount > 0, "Amount > 0");
        require(totalBorrowed + amount <= totalSupply, "Insufficient liquidity");
        
        // Check health factor after borrow
        uint256 newDebt = userDebt[msg.sender] + amount;
        uint256 healthFactor = calculateHealthFactor(msg.sender, newDebt);
        require(healthFactor >= 1e18, "Insufficient collateral");
        
        // Update state
        totalBorrowed += amount;
        userDebt[msg.sender] = newDebt;
        
        // Transfer borrowed tokens
        borrowToken.safeTransfer(msg.sender, amount);
        
        emit Borrow(msg.sender, amount);
    }
    
    /**
     * @notice Repay borrowed tokens
     * @param amount Amount to repay
     */
    function repay(uint256 amount) external whenNotPaused nonReentrant {
        require(amount > 0, "Amount > 0");
        require(userDebt[msg.sender] >= amount, "Excess repayment");
        
        // Transfer tokens from user
        borrowToken.safeTransferFrom(msg.sender, address(this), amount);
        
        // Update state
        totalBorrowed -= amount;
        userDebt[msg.sender] -= amount;
        
        emit Repay(msg.sender, amount);
    }
    
    /**
     * @notice Liquidate an undercollateralized position
     * @param victim Address of the borrower to liquidate
     * @param debtToRepay Amount of debt to repay
     */
    function liquidate(address victim, uint256 debtToRepay) external whenNotPaused nonReentrant {
        require(victim != msg.sender, "Cannot self-liquidate");
        require(debtToRepay > 0, "Amount > 0");
        require(userDebt[victim] > 0, "No debt");
        
        // Check if position is liquidatable
        uint256 healthFactor = calculateHealthFactor(victim, userDebt[victim]);
        require(healthFactor < 1e18, "Position healthy");
        
        // Calculate seizure amount
        uint256 price = oracle.getPrice();
        uint256 collateralValue = (debtToRepay * 1e18) / price;
        uint256 bonusMultiplier = (10000 + liquidationBonus); // e.g., 10800
        uint256 seizeAmount = (collateralValue * bonusMultiplier) / 10000;
        
        require(seizeAmount <= userCollateral[victim], "Insufficient collateral");
        
        // ⚠️ POTENTIAL CEI VIOLATION: External transfer before state update
        borrowToken.safeTransferFrom(msg.sender, address(this), debtToRepay);
        
        // ⚠️ POTENTIAL REENTRANCY: External transfer before state clear
        collateralToken.safeTransfer(msg.sender, seizeAmount);
        
        // State updates AFTER transfers (vulnerable ordering)
        totalBorrowed -= debtToRepay;
        userDebt[victim] -= debtToRepay;
        totalSupply -= seizeAmount;
        userCollateral[victim] -= seizeAmount;
        
        // Collect fee
        uint256 fee = (seizeAmount * 50) / 10000; // 0.5% fee
        if (fee > 0) {
            // ⚠️ FEE NOT ADDED TO RESERVE - BUG
            // reserveBalance += fee; // This line is missing!
        }
        
        emit Liquidation(victim, msg.sender, debtToRepay, seizeAmount);
    }
    
    /**
     * @notice Withdraw collateral (if healthy)
     * @param amount Amount to withdraw
     */
    function withdraw(uint256 amount) external whenNotPaused nonReentrant {
        require(amount > 0, "Amount > 0");
        require(userCollateral[msg.sender] >= amount, "Insufficient balance");
        
        // Check health factor after withdrawal
        uint256 newCollateral = userCollateral[msg.sender] - amount;
        uint256 healthFactor = calculateHealthFactorWithCollateral(msg.sender, userDebt[msg.sender], newCollateral);
        require(healthFactor >= 1e18, "Would become unhealthy");
        
        // Update state first (correct CEI pattern)
        totalSupply -= amount;
        userCollateral[msg.sender] = newCollateral;
        
        // Then transfer
        collateralToken.safeTransfer(msg.sender, amount);
        
        emit Withdrawal(msg.sender, amount);
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Set oracle address
     * ⚠️ CRITICAL: No timelock or multisig required
     */
    function setOracle(address _oracle) external onlyOwner {
        oracle = OracleWrapper(_oracle);
    }
    
    /**
     * @notice Update collateral factor
     */
    function setCollateralFactor(uint256 _factor) external onlyOwner {
        require(_factor <= 9500, "Max 95%");
        collateralFactor = _factor;
    }
    
    /**
     * @notice Pause the protocol
     */
    function pause() external onlyGuardian {
        paused = true;
        emit PauseChanged(true, msg.sender);
    }
    
    /**
     * @notice Unpause the protocol
     */
    function unpause() external onlyGuardian {
        paused = false;
        emit PauseChanged(false, msg.sender);
    }
    
    /**
     * @notice Emergency withdraw (use with caution)
     * ⚠️ CRITICAL: Can drain all funds
     */
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(owner, amount);
    }
    
    /**
     * @notice Transfer ownership
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
        emit OwnershipTransferred(msg.sender, newOwner);
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Calculate health factor for a user
     * @param user User address
     * @param debt Current debt amount
     * @return Health factor (1e18 = healthy, < 1e18 = liquidatable)
     */
    function calculateHealthFactor(address user, uint256 debt) public view returns (uint256) {
        if (debt == 0) return type(uint256).max;
        
        uint256 price = oracle.getPrice();
        uint256 collateralValue = (userCollateral[user] * price) / 1e18;
        uint256 maxBorrow = (collateralValue * collateralFactor) / 10000;
        
        if (maxBorrow == 0) return 0;
        
        return (maxBorrow * 1e18) / debt;
    }
    
    /**
     * @notice Calculate health factor with custom collateral amount
     */
    function calculateHealthFactorWithCollateral(
        address user, 
        uint256 debt, 
        uint256 collateralAmount
    ) public view returns (uint256) {
        if (debt == 0) return type(uint256).max;
        
        uint256 price = oracle.getPrice();
        uint256 collateralValue = (collateralAmount * price) / 1e18;
        uint256 maxBorrow = (collateralValue * collateralFactor) / 10000;
        
        if (maxBorrow == 0) return 0;
        
        return (maxBorrow * 1e18) / debt;
    }
    
    /**
     * @notice Get user position info
     */
    function getUserPosition(address user) external view returns (
        uint256 collateral,
        uint256 debt,
        uint256 healthFactor,
        bool isLiquidatable
    ) {
        collateral = userCollateral[user];
        debt = userDebt[user];
        healthFactor = calculateHealthFactor(user, debt);
        isLiquidatable = healthFactor < 1e18 && debt > 0;
    }
}
