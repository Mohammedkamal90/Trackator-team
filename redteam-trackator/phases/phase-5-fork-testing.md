# Phase 5: FORK TESTING

> **Part of**: [RedTeam Trackator SKILL.md](../SKILL.md) | **Phase**: 5 of 6
> **Previous**: [Phase 4 - Fuzzing](phase-4-fuzzing.md) | **Next**: [Phase 6 - Reporting](phase-6-reporting.md)
> **Source**: Original SKILL.md Lines 2724-3022 (~300 lines → expanded to ~694 lines with additions)

---

## Table of Contents

1. [Objective](#objective)
2. [Fork Testing Infrastructure](#fork-testing-infrastructure)
3. [Step 5.1: Smoke Fork Test](#step-51-smoke-fork-test)
4. [Step 5.2: Deep Fork Testing (with Iteration)](#step-52-deep-fork-testing-with-iteration)
5. [Hacker Visualization Analysis](#hacker-visualization-analysis)
6. [Modification Generation (How Hacker Iterates)](#modification-generation-how-hacker-iterates)
7. [Phase 5 Output](#phase-5-output)

---

## Objective

Validate findings against **REAL mainnet state** using Foundry fork testing. **This is where the hacker lives and iterates.**

**v2.0 ENHANCED**: Now includes **9-criteria reachability proof** from Evidence Validator for court-ready evidence.

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Fork Testing** | Running exploits against real mainnet state snapshot |
| **Iteration Loop** | Hacker modifies attack based on visualization feedback |
| **Trackator Integration** | Real-time analysis of fork test results |
| **Reachability Proof** | Court-ready evidence with 9 validation criteria |

### Why Fork Testing Matters

```
┌─────────────────────────────────────────────────────────────┐
│                    FORK TESTING VALUE                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Local Tests          Fork Tests           Mainnet          │
│  ┌─────────┐        ┌──────────┐        ┌─────────┐       │
│  │ Mock    │   →    │ REAL     │   →    │ ACTUAL  │       │
│  │ State   │        │ State    │        │ Exploit │       │
│  └─────────┘        └──────────┘        └─────────┘       │
│       ↑                  ↑                   ↑             │
│   Fast, Cheap      Realistic State     Production Risk     │
│   But Unrealistic  With Real Data      (What We Prevent)   │
│                                                             │
│  ★ Fork testing bridges the gap between theory and reality  │
└─────────────────────────────────────────────────────────────┘
```

---

## Fork Testing Infrastructure

### Configuration

```javascript
const FORK_CONFIG = {
    rpcUrl: process.env.MAINNET_RPC_URL || 'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
    blockNumber: process.env.FORK_BLOCK_NUMBER || 'latest',
    maxIterations: MAX_FORK_ITERATIONS || 10,
    timeoutMs: 300000  // 5 minutes max per iteration
};
```

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MAINNET_RPC_URL` | Alchemy/Infura endpoint for forking | `https://eth-mainnet.g.alchemy.com/v2/...` |
| `FORK_BLOCK_NUMBER` | Specific block to fork (optional) | `18500000` |
| `MAX_FORK_ITERATIONS` | Max exploit attempts | `10` |

### Prerequisites

- [x] Foundry installed (`forge`, `anvil`, `cast`)
- [x] RPC endpoint with archive access
- [x] Hypothesis from Phase 4 ready for testing
- [x] Trackator analyzer initialized

### Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    FORK TESTING ARCHITECTURE                      │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐   │
│   │   Hacker    │────▶│   Foundry   │────▶│  Forked Mainnet │   │
│   │   Agent     │     │   Anvil     │     │  (Real State)   │   │
│   └─────────────┘     └─────────────┘     └────────┬────────┘   │
│          ▲                                         │            │
│          │ Results                                 │ TX         │
│          │                                         ▼            │
│   ┌──────┴──────┐                         ┌─────────────────┐   │
│   │  Trackator  │◀────────────────────────│  Target Contract │   │
│   │  Analyzer   │     Visualization Data  │  (Real Code)    │   │
│   └──────┬──────┘                         └─────────────────┘   │
│          │                                                    │   │
│          ▼ Modifications                                      │   │
│   ┌─────────────┐                                            │   │
│   │  Next       │────────────────────────────────────────────┘   │
│   │  Iteration  │                                                 │
│   └─────────────┘                                                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Step 5.1: Smoke Fork Test

**Purpose**: Verify basic functionality works on forked state before deep testing.

### What It Validates

| Check | Description | Failure Action |
|-------|-------------|----------------|
| **Deploy** | Contracts deploy on fork | Check compiler version, imports |
| **Read State** | Can read contract storage | Verify address, ABI match |
| **Call Target** | Functions respond correctly | Check function signatures |

### Implementation

```javascript
async function smokeForkTest(hypothesis, context) {
    const result = {
        passed: false,
        error: null,
        contractsDeployed: [],
        basicOperations: []
    };
    
    try {
        // Deploy contracts on fork
        // Try calling target functions
        // Verify state is readable
        
        result.passed = true;
        result.basicOperations = [
            { operation: 'deploy', success: true },
            { operation: 'read_state', success: true },
            { operation: 'call_target_function', success: true }
        ];
        
    } catch (error) {
        result.error = error.message;
    }
    
    return result;
}
```

### Common Smoke Test Failures

```javascript
// Failure patterns and remedies
const SMOKE_TEST_REMEDIES = {
    'contract deployment failed': 'Check Solidity version matches target',
    'state read returned zero': 'Verify correct contract address for fork block',
    'function reverted on call': 'Check if function requires specific conditions',
    'insufficient balance': 'Impersonate whale account for testing'
};
```

### Success Criteria

Smoke test passes when:
- ✅ All target contracts deployable on fork
- ✅ Storage values readable and non-zero where expected
- ✅ Target functions callable without immediate revert
- ⚠️ *Note: Reverts during attack execution are expected and handled in deep test*

---

## Step 5.2: Deep Fork Testing (with Iteration)

**THIS IS THE HEART OF PHASE 5.**

The hacker runs exploit attempts on forked mainnet, observes Trackator visualization of results, and **ITERATES** until success or max iterations.

### The Iteration Loop

```
                    ┌──────────────────────┐
                    │   START ITERATION   │
                    └──────────┬───────────┘
                               │
                               ▼
               ┌───────────────────────────────┐
               │  Build Exploit Attempt        │
               │  (hypothesis + learnings)     │
               └──────────────┬────────────────┘
                              │
                              ▼
               ┌───────────────────────────────┐
               │  Run on Forked Mainnet        │
               │  (real state, real code)      │
               └──────────────┬────────────────┘
                              │
                              ▼
               ┌───────────────────────────────┐
               │  ★ TRACKATOR ANALYSIS ★       │
               │  - State diffs                │
               │  - Alerts triggered           │
               │  - Oracle impact              │
               │  - Invariant violations       │
               └──────────────┬────────────────┘
                              │
                              ▼
               ┌───────────────────────────────┐
               │  HACKER ASSESSMENT            │
               │  - Profit? Loss?              │
               │  - New vectors found?         │
               │  - What went wrong?           │
               └──────────────┬────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
            ┌─────────────┐     ┌─────────────┐
            │  SUCCESS?   │     │  DEAD END?  │
            │  CONFIRMED  │     │  No mods    │
            └──────┬──────┘     └──────┬──────┘
                   │                   │
                   ▼                   ▼
            ┌─────────────┐     ┌─────────────┐
            │  RETURN     │     │  RETURN     │
            │  SUCCESS    │     │  DEAD_END   │
            └─────────────┘     └─────────────┘
                    │
                    ▼ (neither)
            ┌─────────────────────┐
            │ Generate Mods       │
            │ for Next Iteration  │
            └──────────┬──────────┘
                       │
                       └──────▶ LOOP
```

### Core Implementation

```javascript
async function deepForkTestWithIteration(hypothesis, context, trackatorAnalyzer) {
    const results = [];
    let iteration = 0;
    let success = false;
    let bestResult = null;
    
    while (iteration < FORK_CONFIG.maxIterations && !success) {
        iteration++;
        console.log(`\n🔄 Fork Test Iteration ${iteration}/${FORK_CONFIG.maxIterations}`);
        
        // Build exploit attempt based on hypothesis + learnings
        const exploitAttempt = buildExploitAttempt(hypothesis, results, iteration);
        
        // Run on forked mainnet
        const forkResult = await runOnFork(exploitAttempt, FORK_CONFIG);
        
        // ★ TRACKATOR VISUALIZATION ★
        const trackatorVisualization = await trackatorAnalyzer.analyzeForkResult(forkResult);
        
        const iterationResult = {
            iteration,
            exploitAttempt: exploitAttempt.description,
            txHash: forkResult.txHash,
            success: forkResult.success,
            reverted: forkResult.reverted,
            revertReason: forkResult.revertReason,
            gasUsed: forkResult.gasUsed,
            
            // Trackator Analysis (see Visualization Analysis below)
            trackatorAnalysis: {
                stateDiff: trackatorVisualization.stateDiff,
                alertsTriggered: trackatorVisualization.alerts,
                oracleImpact: trackatorVisualization.oracleAnalysis,
                invariantViolations: trackatorVisualization.violations
            },
            
            // Hacker Assessment (filled by analyzeVisualization)
            hackerNotes: '',
            modifications: []  // Filled by generateModifications
        };
        
        // ★ HACKER ANALYSIS OF VISUALIZATION ★
        iterationResult.hackerNotes = analyzeVisualization(
            trackatorVisualization, 
            hypothesis
        );
        
        // Decide: iterate or conclude?
        if (forkResult.success && isMeaningfulExploit(forkResult, trackatorVisualization)) {
            success = true;
            iterationResult.verdict = 'CONFIRMED';
            results.push(iterationResult);
            break;
        }
        
        // Generate modifications for next attempt
        iterationResult.modifications = generateModifications(
            trackatorVisualization,
            hypothesis,
            iteration
        );
        
        if (iterationResult.modifications.length === 0) {
            // No way forward → dead end
            iterationResult.verdict = 'DEAD_END';
            results.push(iterationResult);
            break;
        }
        
        results.push(iterationResult);
        bestResult = selectBestResult(results);
    }
    
    return {
        success,
        totalIterations: iteration,
        results,
        bestResult,
        finalVerdict: success ? 'CONFIRMED' : (bestResult?.verdict || 'INCONCLUSIVE')
    };
}
```

### Verdict Types

| Verdict | Meaning | Action |
|---------|---------|--------|
| `CONFIRMED` | Exploit works on real state | Proceed to reporting |
| `PROBABLE` | Partial success, needs refinement | May iterate more |
| `DEAD_END` | No viable path forward | Archive as negative finding |
| `INCONCLUSIVE` | Max iterations reached | Review manually |

---

## Hacker Visualization Analysis

**How hacker interprets Trackator output** to decide next actions.

### Analysis Framework

The hacker examines four key dimensions from Trackator's visualization:

```
┌─────────────────────────────────────────────────────────────────┐
│                  VISUALIZATION ANALYSIS MATRIX                  │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   Dimension     │   Key Question  │   Hacker Decision           │
├─────────────────┼─────────────────┼─────────────────────────────┤
│                 │                 │                             │
│  1. STATE DIFF  │ Did I profit?   │ ✓ Continue if profitable    │
│                 │ Did protocol    │ ✗ Pivot if no gain          │
│                 │ lose funds?     │                             │
│                 │                 │                             │
│  2. ALERTS      │ Any unexpected │ ⭐ Unexpected = new vector!  │
│                 │ anomalies?     │                             │
│                 │                 │                             │
│  3. ORACLE      │ Price moved    │ Need bigger move?            │
│    IMPACT       │ enough?        │ Threshold exceeded?          │
│                 │                 │                             │
│  4. INVARIENTS  │ Any broken     │ 💥 Violations confirm       │
│                 │ rules?         │    vulnerability exists      │
│                 │                 │                             │
└─────────────────┴─────────────────┴─────────────────────────────┘
```

### Dimension 1: State Diff Analysis

```javascript
// Core logic for analyzing state changes
function analyzeStateDiff(visualization, hypothesis) {
    const notes = [];
    const { before, after } = visualization.stateDiff;
    
    // Did attacker balance increase meaningfully?
    const attackerProfit = calculateProfit(before, after, hypothesis.attackerAddress);
    
    if (attackerProfit > 0) {
        notes.push(`✅ Attacker profit: ${formatEther(attackerProfit)} ETH`);
        notes.push(attackerProfit > MINIMUM_VIABLE_PROFIT 
            ? `🎯 Profit exceeds threshold - EXPLOIT WORKING`
            : `⚠️ Profit too small - need larger position`);
    } else {
        notes.push(`❌ No profit - state changes don't benefit attacker`);
    }
    
    // Did protocol lose funds?
    const protocolLoss = calculateProtocolLoss(before, after);
    if (protocolLoss > 0) {
        notes.push(`💸 Protocol loss: ${formatEther(protocolLoss)} ETH`);
    }
    
    return notes;
}
```

### Dimension 2: Alert Analysis

```javascript
// Analyze alerts triggered during exploit attempt
function analyzeAlerts(visualization, hypothesis) {
    const notes = [];
    
    if (!visualization.alertsTriggered?.length) return ['No alerts triggered'];
    
    notes.push(`🚨 Alerts: ${visualization.alertsTriggered.length}`);
    
    for (const alert of visualization.alertsTriggered) {
        notes.push(`   - ${alert.name} (${alert.severity})`);
        
        // Unexpected alert = potential new attack vector!
        if (!hypothesis.expectedAlerts?.includes(alert.id)) {
            notes.push(`   ⭐ UNEXPECTED ALERT - new attack vector possible!`);
        }
    }
    
    return notes;
}
```

### Dimension 3: Oracle Impact

```javascript
// Analyze price oracle manipulation effects
function analyzeOracleImpact(visualization) {
    const notes = [];
    const { deviationPercent, threshold, status } = visualization.oracleImpact;
    
    if (!deviationPercent) return null;
    
    notes.push(`📊 Oracle: ${deviationPercent}% deviation (threshold: ${threshold}%)`);
    
    if (status === 'ANOMALY_DETECTED') {
        notes.push(deviationPercent < threshold
            ? `   ⚠️ Below threshold - need bigger manipulation`
            : `   ✅ Exceeds threshold - manipulation working!`);
    }
    
    return notes;
}
```

### Dimension 4: Invariant Violations

```javascript
// Check for broken protocol rules
function analyzeInvariants(visualization) {
    const notes = [];
    
    if (!visualization.invariantViolations?.length) return null;
    
    notes.push(`💥 Invariant violations: ${visualization.invariantViolations.length}`);
    for (const viol of visualization.invariantViolations) {
        notes.push(`   - ${viol.id}: ${viol.expression}`);
    }
    
    return notes;
}
```

### Complete Visualization Analyzer

```javascript
function analyzeVisualization(visualization, hypothesis) {
    const analyses = [
        analyzeStateDiff(visualization, hypothesis),
        analyzeAlerts(visualization, hypothesis),
        analyzeOracleImpact(visualization),
        analyzeInvariants(visualization)
    ];
    
    return analyses.filter(Boolean).flat().join('\n');
}
```

### Quick Reference: Interpretation Guide

| Observation | Interpretation | Hacker Response |
|-------------|----------------|-----------------|
| Profit > threshold | Exploit working! | Confirm & document |
| Profit but small | Direction correct | Scale up position |
| No profit | Wrong approach | Analyze revert reason |
| Unexpected alert | New vector found | Consider pivoting |
| Oracle below threshold | Weak manipulation | Increase flash loan |
| Invariant violation | Vulnerability confirmed | Document for report |

---

## Modification Generation (How Hacker Iterates)

**The intelligence layer**: Based on visualization analysis, generate concrete modifications for next attempt.

### Modification Types

| Type | Trigger | Description |
|------|---------|-------------|
| `fix_revert` | Transaction reverted | Address specific error |
| `increase_manipulation` | Oracle below threshold | Bigger price move needed |
| `scale_position` | Profit too small | Increase attack size |
| `add_precondition` | Missing setup tx | Add preliminary steps |
| `pivot_attack` | Unexpected alert | Try new attack vector |

### Generation Logic

```javascript
function generateModifications(visualization, hypothesis, iteration) {
    const mods = [];
    
    // Case 1: Reverted with specific error → fix it
    if (visualization.revertReason) {
        mods.push({
            type: 'fix_revert',
            description: `Address revert: "${visualization.revertReason}"`,
            suggestion: getFixForRevert(visualization.revertReason),
            priority: 'HIGH'
        });
    }
    
    // Case 2: Not enough price movement → manipulate harder
    if (visualization.oracleImpact?.deviationPercent < 
        visualization.oracleImpact?.threshold) {
        mods.push({
            type: 'increase_manipulation',
            description: 'Increase flash loan size for stronger price impact',
            suggestion: 'Double flash loan amount or add second swap leg',
            priority: 'MEDIUM'
        });
    }
    
    // Case 3: Profit too small → scale up
    if (visualization.profit > 0 && visualization.profit < MINIMUM_VIABLE_PROFIT) {
        mods.push({
            type: 'scale_position',
            description: 'Scale up attack size for meaningful profit',
            suggestion: 'Increase deposit/borrow amount proportionally',
            priority: 'MEDIUM'
        });
    }
    
    // Case 4: Missing preconditions → add setup
    if (visualization.missingPreconditions?.length > 0) {
        mods.push({
            type: 'add_precondition',
            description: 'Add missing precondition transactions',
            suggestion: `Execute first: ${visualization.missingPreconditions.join(', ')}`,
            priority: 'HIGH'
        });
    }
    
    // Case 5: Unexpected alert → new idea!
    const unexpectedAlerts = visualization.alertsTriggered?.filter(a =>
        !hypothesis.expectedAlerts?.includes(a.id)
    ) || [];
    
    if (unexpectedAlerts.length > 0) {
        mods.push({
            type: 'pivot_attack',
            description: 'Pivot to exploit newly discovered alert',
            suggestion: `Focus on ${unexpectedAlerts[0].name} instead`,
            priority: 'EXPLORATORY'
        });
    }
    
    return mods;
}
```

### Common Revert Fixes Reference

```javascript
const REVERT_FIXES = {
    // Access control failures
    'Ownable: caller is not owner': 'Use impersonation or find owner bypass',
    'not authorized': 'Check role assignments, look for privilege escalation',
    
    // State condition failures
    'insufficient liquidity': 'Try different pool or increase slippage',
    'transfer failed': 'Check token approvals, use forceApprove pattern',
    'deadline expired': 'Increase deadline, check block.timestamp usage',
    
    // Math/overflow
    'overflow/underflow': 'Adjust amounts, check for rounding issues',
    'division by zero': 'Ensure divisor is non-zero in all paths',
    
    // Protocol-specific
    'health factor': 'Add collateral or reduce borrow before attack',
    'cooldown active': 'Wait for cooldown or find bypass mechanism'
};

function getFixForRevert(revertReason) {
    // Exact match first
    if (REVERT_FIXES[revertReason]) return REVERT_FIXES[revertReason];
    
    // Partial match
    for (const [pattern, fix] of Object.entries(REVERT_FIXES)) {
        if (revertReason.toLowerCase().includes(pattern.toLowerCase())) {
            return fix;
        }
    }
    
    return 'Manual analysis required - review error context';
}
```

### Modification Selection Strategy

When multiple modifications are generated, prioritize:

```
Priority Order:
1. HIGH: fix_revert, add_precondition (must fix blockers)
2. MEDIUM: increase_manipulation, scale_position (optimize working attack)
3. EXPLORATORY: pivot_attack (when current path exhausted)
```

---

## Phase 5 Output

### Result Structure

```javascript
hypothesis.forkTestResult = {
    smokeTest: { 
        passed: boolean, 
        error: string | null 
    },
    deepTest: {
        success: boolean,
        totalIterations: number,
        results: [
            /* iteration results array */
        ],
        bestResult: {
            iteration: number,
            txHash: string,
            trackatorAnalysis: {
                stateDiff: {},
                alertsTriggered: [],
                oracleImpact: {},
                invariantViolations: []
            },
            verdict: 'CONFIRMED' | 'PROBABLE' | 'DEAD_END' | 'INCONCLUSIVE'
        },
        finalVerdict: 'CONFIRMED' | 'PROBABLE' | 'DEAD' | 'INCONCLUSIVE'
    }
};
```

### Output Validation Checklist

Before proceeding to Phase 6, verify:

- [ ] Smoke test completed (pass or documented failure)
- [ ] Deep test ran at least 1 iteration
- [ ] Final verdict assigned
- [ ] Best result captured with full Trackator analysis
- [ ] All transaction hashes recorded
- [ ] Modification history preserved for audit trail

### Integration with Next Phase

Phase 5 output feeds directly into **Phase 6: REPORTING**:

```
Phase 5 Output ──────────────────────────────────────────▶ Phase 6 Input
┌─────────────────────┐                                  ┌─────────────────────┐
│ forkTestResult      │                                  │ Report Sections     │
│ ├─ smokeTest        │────▶ Executive Summary    ──────▶│ ├─ Summary          │
│ └─ deepTest         │                                  │ ├─ Technical Details│
│    ├─ success       │────▶ Finding Verdict      ──────▶│ ├─ Evidence         │
│    ├─ totalIters    │                                  │ ├─ PoC              │
│    ├─ results[]     │────▶ Attack Timeline      ──────▶│ └─ Recommendations  │
│    ├─ bestResult    │────▶ Best Exploit Proof   ──────▶│                     │
│    └─ finalVerdict  │────▶ Severity Assessment  ──────▶│                     │
└─────────────────────┘                                  └─────────────────────┘
```

---

## References

- **Full implementation code**: See [`references/code-examples.md#fork-testing`](../references/code-examples.md#fork-testing) for complete fork testing implementation.
- **Foundry documentation**: https://book.getfoundry.sh/forge/fork-testing
- **Trackator visualization analysis**: See [Phase 5: Visualization Analysis](#visualization-analysis) for state diff and alert interpretation guidance

---

*Phase 5 of 7 | [← Phase 4: Fuzzing](./phase-4-fuzzing.md) | [Phase 6: Reporting →](./phase-6-reporting.md)*
