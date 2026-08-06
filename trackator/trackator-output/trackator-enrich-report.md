# Trackator Enrichment Report

**Generated:** 2026-08-06T04:14:42.335Z
**Protocol Type:** lending

## Table of Contents

- [Executive Summary](#executive-summary)
- [Threat Model](#threat-model)
- [Invariants](#invariants)
- [Trust Assumptions](#trust-assumptions)
- [Attack Vectors](#attack-vectors)
- [Alert Rules](#alert-rules)
- [Component Analysis](#component-analysis)
- [Money Flows](#money-flows)

## Executive Summary

| Metric | Value |
|--------|-------|
| Protocol Type | **LENDING** |
| Total Invariants | 43 |
| Alert Rules | 25 |
| Critical Alerts | 7 |
| High Alerts | 1 |
| Assets at Risk | 7 |
| Entry Points | 19 |

## Threat Model

### Assets at Risk

| Asset | Type | Location |
|-------|------|----------|
| totalSupply | erc20 | SampleLendingProtocol.totalSupply |
| totalBorrowed | erc20 | SampleLendingProtocol.totalBorrowed |
| reserveBalance | erc20 | SampleLendingProtocol.reserveBalance |
| collateralToken | erc20 | SampleLendingProtocol.collateralToken |
| borrowToken | erc20 | SampleLendingProtocol.borrowToken |
| totalFeesCollected | erc20 | FeeCollector.totalFeesCollected |
| feesByToken | erc20 | FeeCollector.feesByToken |

### Entry Points

| Function | Contract | Access | Criticality |
|----------|----------|--------|-------------|
| `deposit` | SampleLendingProtocol | anyone | critical |
| `borrow` | SampleLendingProtocol | anyone | critical |
| `repay` | SampleLendingProtocol | anyone | critical |
| `liquidate` | SampleLendingProtocol | anyone | critical |
| `withdraw` | SampleLendingProtocol | anyone | critical |
| `setOracle` | SampleLendingProtocol | owner-only | low |
| `setCollateralFactor` | SampleLendingProtocol | owner-only | low |
| `pause` | SampleLendingProtocol | anyone | low |
| `unpause` | SampleLendingProtocol | anyone | low |
| `emergencyWithdraw` | SampleLendingProtocol | owner-only | low |
| `transferOwnership` | SampleLendingProtocol | owner-only | medium |
| `updatePrice` | OracleWrapper | anyone | low |
| `transferAdmin` | OracleWrapper | anyone | medium |
| `setProtocol` | FeeCollector | anyone | low |
| `collectFees` | FeeCollector | anyone | low |
| `withdrawFees` | FeeCollector | anyone | low |
| `emergencyWithdraw` | FeeCollector | anyone | low |
| `updateTreasury` | FeeCollector | anyone | low |
| `transferAdmin` | FeeCollector | anyone | medium |

## Invariants

| ID | Category | Severity | Template | Checkable |
|----|----------|----------|----------|----------|
| INV_1 | accounting | critical | Total supply accounting must balance... | ✅ |
| INV_2 | bounds | critical | No underflow or overflow in arithmetic operations... | ✅ |
| INV_3 | accounting | critical | Collateral value must always cover borrowed amount... | ✅ |
| INV_4 | oracle | critical | Oracle prices must be within acceptable bounds... | ✅ |
| INV_5 | bounds | high | Interest rates must remain within configured bound... | ✅ |
| INV_6 | accounting | critical | Exchange rate between underlying and cToken must b... | ✅ |
| INV_NB_TOTALSUPPLY | bounds | high | totalSupply must stay within expected range... | ✅ |
| INV_NB_TOTALBORROWED | bounds | high | totalBorrowed must stay within expected range... | ✅ |
| INV_NB_RESERVEBALANCE | bounds | high | reserveBalance must stay within expected range... | ✅ |
| INV_NB_COLLATERALFACTOR | bounds | high | collateralFactor must stay within expected range... | ✅ |
| INV_NB_LIQUIDATIONBONUS | bounds | high | liquidationBonus must stay within expected range... | ✅ |
| INV_NB_INTERESTRATE | bounds | high | interestRate must stay within expected range... | ✅ |
| INV_NB_USERCOLLATERAL | bounds | high | userCollateral must stay within expected range... | ✅ |
| INV_NB_USERDEBT | bounds | high | userDebt must stay within expected range... | ✅ |
| INV_NB_SPOTPRICE | bounds | high | spotPrice must stay within expected range... | ✅ |
| INV_NB_TWAPPRICE | bounds | high | twapPrice must stay within expected range... | ✅ |
| INV_NB_LASTUPDATETIME | bounds | high | lastUpdateTime must stay within expected range... | ✅ |
| INV_NB_TOTALFEESCOLLECTED | bounds | high | totalFeesCollected must stay within expected range... | ✅ |
| INV_NB_FEESBYTOKEN | bounds | high | feesByToken must stay within expected range... | ✅ |
| INV_AUTH_TOTALSUPPLY | permission | medium | totalSupply must only be modified by authorized fu... | ❌ |
| INV_AUTH_TOTALBORROWED | permission | medium | totalBorrowed must only be modified by authorized ... | ❌ |
| INV_AUTH_RESERVEBALANCE | permission | medium | reserveBalance must only be modified by authorized... | ❌ |
| INV_AUTH_ORACLE | permission | medium | oracle must only be modified by authorized functio... | ❌ |
| INV_AUTH_COLLATERALFACTOR | permission | medium | collateralFactor must only be modified by authoriz... | ❌ |
| INV_AUTH_LIQUIDATIONBONUS | permission | medium | liquidationBonus must only be modified by authoriz... | ❌ |
| INV_AUTH_INTERESTRATE | permission | medium | interestRate must only be modified by authorized f... | ❌ |
| INV_AUTH_USERCOLLATERAL | permission | medium | userCollateral must only be modified by authorized... | ❌ |
| INV_AUTH_USERDEBT | permission | medium | userDebt must only be modified by authorized funct... | ❌ |
| INV_AUTH_HASDEPOSITED | permission | medium | hasDeposited must only be modified by authorized f... | ❌ |
| INV_AUTH_OWNER | permission | medium | owner must only be modified by authorized function... | ❌ |
| INV_AUTH_GUARDIAN | permission | medium | guardian must only be modified by authorized funct... | ❌ |
| INV_AUTH_PAUSED | permission | medium | paused must only be modified by authorized functio... | ❌ |
| INV_AUTH_COLLATERALTOKEN | permission | medium | collateralToken must only be modified by authorize... | ❌ |
| INV_AUTH_BORROWTOKEN | permission | medium | borrowToken must only be modified by authorized fu... | ❌ |
| INV_AUTH_FEECOLLECTOR | permission | medium | feeCollector must only be modified by authorized f... | ❌ |
| INV_AUTH_ADMIN | permission | medium | admin must only be modified by authorized function... | ❌ |
| INV_AUTH_SPOTPRICE | permission | medium | spotPrice must only be modified by authorized func... | ❌ |
| INV_AUTH_TWAPPRICE | permission | medium | twapPrice must only be modified by authorized func... | ❌ |
| INV_AUTH_LASTUPDATETIME | permission | medium | lastUpdateTime must only be modified by authorized... | ❌ |
| INV_AUTH_PROTOCOL | permission | medium | protocol must only be modified by authorized funct... | ❌ |
| INV_AUTH_TREASURY | permission | medium | treasury must only be modified by authorized funct... | ❌ |
| INV_AUTH_TOTALFEESCOLLECTED | permission | medium | totalFeesCollected must only be modified by author... | ❌ |
| INV_AUTH_FEESBYTOKEN | permission | medium | feesByToken must only be modified by authorized fu... | ❌ |

## Trust Assumptions

| ID | Category | Assumption | If Violated | Confidence |
|----|----------|------------|-------------|------------|
| TA_1 | oracle | Oracle prices reflect true market values | Incorrect liquidations, manipulated swaps, unfair exchanges | medium |
| TA_2 | external-contract | Integrated external contracts behave as specified | Loss of funds through unexpected behavior | medium |
| TA_3 | governance | Governance processes are not captured by malicious actors | Unauthorized parameter changes, fund drains | medium |
| TA_L1 | price-feed | Price feeds cannot be manipulated within a single transaction/block | Cheap collateral borrowed against, bad debt accumulation | low |

## Attack Vectors

| Name | Category | Likelihood | Severity | Impact |
|------|----------|------------|----------|--------|
| Reentrancy Attack | logic-error | likely | critical | Drain contract funds, corrupt state |
| Access Control Bypass | access-control | possible | critical | Unauthorized state changes, fund theft |
| Oracle Price Manipulation | oracle-manipulation | likely | critical | Incorrect pricing, stolen funds via liquidations/swaps |
| Flash Loan Attack | flash-loan | possible | high | Manipulate protocol state for profit |
| Improper Liquidation | liquidation | possible | critical | User funds lost through unjustified liquidation |
| Interest Rate Manipulation | logic-error | unlikely | medium | Manipulated interest rates, economic attack |

## Alert Rules

### Critical & High Priority

| Rule Name | Category | Condition | Mitigation |
|-----------|----------|-----------|------------|
| CEI Pattern Violation - Potential Reentrancy | reentrancy | {"type":"pattern","field":"ceiPattern","operator":... | Reorder operations to perform all extern |
| Missing Access Control on State-Changing Function | access-control | {"type":"absence","field":"modifiers","operator":"... | Add appropriate access control modifiers |
| DelegateCall Detected - Execution Context Forwarding | access-control | {"type":"presence","field":"hasDelegateCall","oper... | Ensure delegatecall target is trusted, i |
| Oracle Price Deviation Exceeds Threshold | oracle-manipulation | {"type":"threshold","field":"priceDeviationPercent... | Use TWAP oracles, implement circuit brea |
| Accounting Invariant Violation: Total supply accounting must balance... | accounting | {"type":"custom","field":"Σ balances == totalSuppl... | Review transaction that caused accountin |
| Accounting Invariant Violation: Collateral value must always cover borrowed amount... | accounting | {"type":"custom","field":"collateral[token] * pric... | Review transaction that caused accountin |
| Accounting Invariant Violation: Exchange rate between underlying and cToken must b... | accounting | {"type":"custom","field":"exchangeRate == cash + b... | Review transaction that caused accountin |
| Flash Loan Attack Pattern: Flash Loan Attack | flash-loan | {"type":"sequence","field":"balanceChanges","opera... | Check for balance changes within single  |

## Component Analysis

| Component | Type | Risk Level | Responsibility |
|-----------|------|------------|---------------|
| SampleLendingProtocol | core | critical | Token accounting, Asset custody and tran... |
| IOracle | peripheral | low | Price discovery and oracle integration... |
| OracleWrapper | core | low | Asset custody and transfers, Price disco... |
| FeeCollector | core | low | Token accounting, Asset custody and tran... |

## Money Flows

### Deposit via deposit()

**Trigger:** User calls SampleLendingProtocol.deposit()

**Steps:**
1. Transfer tokens/ETH: User → SampleLendingProtocol (Input token)
2. Update user balance/shares: SampleLendingProtocol → User (LP/staked tokens)
3. Emit Deposit event: SampleLendingProtocol → Event Log (Event)

**Conditions:**
- Contract not paused
- Amount > 0
- Allowance sufficient (for ERC20)

### Borrow via borrow()

**Trigger:** User calls SampleLendingProtocol.borrow()

**Steps:**
1. Check collateral sufficiency: SampleLendingProtocol → SampleLendingProtocol (Check)
2. Transfer borrowed assets: SampleLendingProtocol → User (Borrowed token)
3. Update borrow balance: User → SampleLendingProtocol (Debt)
4. Emit Borrow event: SampleLendingProtocol → Event Log (Event)

**Conditions:**
- Sufficient collateral
- Account healthy after borrow
- Not paused

### Liquidation via liquidate()

**Trigger:** Liquidator calls SampleLendingProtocol.liquidate()

**Steps:**
1. Verify unhealthy position: Liquidator → SampleLendingProtocol (Check)
2. Seize collateral: Borrower/Vault → Liquidator (Collateral)
3. Repay borrow: Liquidator → Protocol (Underlying)
4. Pay liquidation reward: Protocol → Liquidator (Reward)
5. Emit Liquidation event: SampleLendingProtocol → Event Log (Event)

**Conditions:**
- Position is below threshold
- Close factor respected
- Not paused

### Withdrawal via withdraw()

**Trigger:** User calls SampleLendingProtocol.withdraw()

**Steps:**
1. Burn/transfer shares: User → SampleLendingProtocol (LP/staked tokens)
2. Transfer assets: SampleLendingProtocol → User (Underlying token)
3. Emit Withdraw event: SampleLendingProtocol → Event Log (Event)

**Conditions:**
- User has sufficient balance/shares
- Contract has enough liquidity

### Withdrawal via emergencyWithdraw()

**Trigger:** User calls SampleLendingProtocol.emergencyWithdraw()

**Steps:**
1. Burn/transfer shares: User → SampleLendingProtocol (LP/staked tokens)
2. Transfer assets: SampleLendingProtocol → User (Underlying token)
3. Emit Withdraw event: SampleLendingProtocol → Event Log (Event)

**Conditions:**
- User has sufficient balance/shares
- Contract has enough liquidity

### Withdrawal via withdrawFees()

**Trigger:** User calls FeeCollector.withdrawFees()

**Steps:**
1. Burn/transfer shares: User → FeeCollector (LP/staked tokens)
2. Transfer assets: FeeCollector → User (Underlying token)
3. Emit Withdraw event: FeeCollector → Event Log (Event)

**Conditions:**
- User has sufficient balance/shares
- Contract has enough liquidity

### Withdrawal via emergencyWithdraw()

**Trigger:** User calls FeeCollector.emergencyWithdraw()

**Steps:**
1. Burn/transfer shares: User → FeeCollector (LP/staked tokens)
2. Transfer assets: FeeCollector → User (Underlying token)
3. Emit Withdraw event: FeeCollector → Event Log (Event)

**Conditions:**
- User has sufficient balance/shares
- Contract has enough liquidity

