# Plugin: Fork Test Plugin

**Phase**: 5 (Fork Testing)
**Purpose**: Validate hypotheses against REAL mainnet state using Foundry fork testing with Trackator visualization
**Type**: Validation plugin (confirms or grades findings with real-world evidence)

---

## Overview

This is where **the Hacker agent lives and iterates**. Fork testing takes hypotheses from earlier phases and tests them against actual mainnet state. The plugin provides:

1. **Smoke test infrastructure** — verify basic functionality
2. **Deep fork testing with iteration** — run exploit attempts, observe, modify, retry
3. **Trackator visualization integration** — analyze results through Trackator's lens
4. **Evidence collection** — gather proof for Verifier

## Philosophy

> *"Theory is cheap. Fork test is truth. If it works on mainnet state, it's real."*

---

## Infrastructure

### Configuration

```javascript
const FORK_CONFIG = {
    // RPC endpoint for forking
    rpcUrl: process.env.MAINNET_RPC_URL || null,
    
    // Block to fork (default: latest)
    blockNumber: process.env.FORK_BLOCK_NUMBER || 'latest',
    
    // Iteration limits
    maxIterations: parseInt(process.env.MAX_FORK_ITERATIONS) || 10,
    maxTotalAttempts: 50,  // Safety limit across all hypotheses
    
    // Timeouts
    iterationTimeoutMs: 300000,  // 5 minutes per iteration
    phaseTimeoutMs: 3600000,     // 1 hour total for Phase 5
    
    // Attacker configuration
    attackerAddress: process.env.ATTACKER_ADDRESS || generateRandomAddress(),
    
    // Profit thresholds
    minimumViableProfitWei: parseEther('0.1'),  // 0.1 ETH minimum to consider "profitable"
    
    // Output settings
    saveFailedAttempts: true,  // Keep failed attempts for analysis
    verboseLogging: true
};
```

### Prerequisites Check

```javascript
function checkForkPrerequisites() {
    const issues = [];
    
    if (!FORK_CONFIG.rpcUrl) {
        issues.push('Missing MAINNET_RPC_URL environment variable');
    }
    
    // Test RPC connectivity
    if (FORK_CONFIG.rpcUrl) {
        try {
            const block = await provider.getBlockNumber();
            console.log(`✅ RPC connected, latest block: ${block}`);
        } catch (e) {
            issues.push(`RPC connection failed: ${e.message}`);
        }
    }
    
    // Check Foundry availability
    try {
        execSync('forge --version', { stdio: 'pipe' });
        console.log('✅ Foundry available');
    } catch (e) {
        issues.push('Foundry not installed or not in PATH');
    }
    
    return {
        ready: issues.length === 0,
        issues,
        fallbackMode: !FORK_CONFIG.rpcUrl  // Can run without RPC but limited
    };
}
```

---

## Step 1: Smoke Fork Test

### Purpose
Verify basic functionality works on forked state before attempting exploits.

```javascript
async function smokeForkTest(hypothesis, context) {
    const result = {
        passed: false,
        timestamp: new Date().toISOString(),
        checks: [],
        errors: [],
        deployedContracts: [],
        stateSnapshot: null
    };
    
    try {
        // Check 1: Deploy contracts on fork
        console.log('📦 Deploying contracts on fork...');
        const deployment = await deployOnFork(FORK_CONFIG);
        result.deployedContracts = deployment.contracts;
        result.checks.push({ check: 'deploy', status: 'success', output: deployment.contracts.length + ' contracts' });
        
        // Check 2: Read protocol state
        console.log('📖 Reading protocol state...');
        const stateRead = await readProtocolState(deployment, hypothesis);
        result.stateSnapshot = stateRead;
        result.checks.push({ check: 'read_state', status: 'success', output: Object.keys(stateRead).length + ' variables read' });
        
        // Check 3: Call target function (dry run)
        console.log('🎯 Testing target function access...');
        const functionTest = await testTargetFunction(deployment, hypothesis);
        result.checks.push({
            check: 'function_access',
            status: functionTest.accessible ? 'success' : 'failed',
            output: functionTest.reason || 'Function accessible'
        });
        
        // Check 4: Verify attacker has initial balance
        const balance = await provider.getBalance(FORK_CONFIG.attackerAddress);
        result.checks.push({
            check: 'attacker_balance',
            status: balance > 0 ? 'success' : 'warning',
            output: `Balance: ${formatEther(balance)} ETH`
        });
        
        result.passed = result.checks.every(c => c.status !== 'failed');
        
    } catch (error) {
        result.errors.push({
            phase: 'smoke_test',
            error: error.message,
            stack: error.stack
        });
    }
    
    return result;
}
```

### Smoke Test Decision Matrix

| Result | Meaning | Next Action |
|--------|---------|-------------|
| All checks pass | Ready for deep testing | Proceed to Step 2 |
| Deploy failed | Compilation/deployment issue | Fix code, retry |
| State read failed | Wrong contract addresses/ABIs | Update context |
| Function inaccessible | Access control blocking | Check if realistic bypass exists |
| No balance | Need to fund attacker | Add funding transaction |

---

## Step 2: Deep Fork Testing (with Iteration)

### Core Loop

```javascript
async function deepForkTestWithIteration(hypothesis, context, trackatorAnalyzer) {
    const session = {
        hypothesisId: hypothesis.id,
        startTime: new Date().toISOString(),
        iterations: [],
        summary: {
            totalIterations: 0,
            successfulIterations: 0,
            bestResult: null,
            finalVerdict: null
        },
        trackatorVisualizations: []
    };
    
    let iteration = 0;
    let success = false;
    let noProgressCount = 0;
    
    while (iteration < FORK_CONFIG.maxIterations && !success) {
        iteration++;
        console.log(`\n${'='.repeat(60)}`);
        console.log(`🔄 FORK TEST ITERATION ${iteration}/${FORK_CONFIG.maxIterations}`);
        console.log(`${'='.repeat(60)}`);
        
        // Build exploit attempt based on hypothesis + learnings from previous attempts
        const exploitAttempt = buildExploitAttempt(hypothesis, session.iterations, iteration);
        
        // Run attempt on forked mainnet
        const forkResult = await executeOnFork(exploitAttempt, FORK_CONFIG);
        
        // ★ TRACKATOR VISUALIZATION ★
        // Feed result into Trackator for analysis
        let trackatorVisualization = null;
        if (trackatorAnalyzer && forkResult.success !== false) {
            try {
                trackatorVisualization = await trackatorAnalyzer.analyzeForkResult(forkResult);
                session.trackatorVisualizations.push({
                    iteration,
                    visualization: trackatorVisualization
                });
            } catch (e) {
                console.warn('⚠️ Trackator visualization failed:', e.message);
            }
        }
        
        // ★ HACKER ANALYSIS OF RESULTS ★
        const hackerAnalysis = analyzeForkResult(forkResult, trackatorVisualization, hypothesis);
        
        // Record this iteration
        const iterationRecord = {
            iteration,
            timestamp: new Date().toISOString(),
            
            // Attempt details
            exploitAttempt: {
                description: exploitAttempt.description,
                functionsCalled: exploitAttempt.functionsCalled,
                estimatedGas: exploitAttempt.estimatedGas
            },
            
            // Execution result
            execution: {
                txHash: forkResult.txHash || null,
                success: forkResult.success,
                reverted: forkResult.reverted,
                revertReason: forkResult.revertReason || null,
                gasUsed: forkResult.gasUsed || 0,
                returnData: forkResult.returnData || null
            },
            
            // Trackator analysis
            trackatorAnalysis: trackatorVisualization ? {
                stateDiff: trackatorVisualization.stateDiff || null,
                alertsTriggered: trackatorVisualization.alerts || [],
                oracleImpact: trackatorVisualization.oracleAnalysis || null,
                invariantViolations: trackatorVisualization.violations || []
            } : null,
            
            // Hacker assessment
            hackerNotes: hackerAnalysis.notes,
            hackerVerdict: hackerAnalysis.verdict,
            
            // What to do next
            modifications: hackerAnalysis.modifications || []
        };
        
        session.iterations.push(iterationRecord);
        session.summary.totalIterations = iteration;
        
        // Check for success
        if (forkResult.success && isMeaningfulExploit(forkResult, trackatorVisualization)) {
            success = true;
            iterationRecord.verdict = 'CONFIRMED';
            session.summary.successfulIterations++;
            session.summary.bestResult = iterationRecord;
            session.summary.finalVerdict = 'CONFIRMED';
            
            console.log('\n🎉 EXPLOIT CONFIRMED ON FORK!');
            console.log(`   TX Hash: ${forkResult.txHash}`);
            console.log(`   Iterations: ${iteration}`);
            break;
        }
        
        // Generate modifications for next attempt
        if (hackerAnalysis.modifications.length === 0) {
            // No way forward → dead end
            iterationRecord.verdict = 'DEAD_END';
            noProgressCount++;
            
            if (noProgressCount >= 3) {
                console.log('\n💀 No progress after 3 attempts — dead end');
                session.summary.finalVerdict = 'DEAD_END';
                break;
            }
        } else {
            noProgressCount = 0;  // Reset counter
            
            // Log what we'll try next
            console.log('\n📝 Next iteration modifications:');
            hackerAnalysis.modifications.forEach((mod, i) => {
                console.log(`   ${i + 1}. [${mod.type.toUpperCase()}] ${mod.description}`);
            });
        }
        
        // Select best result so far
        session.summary.bestResult = selectBestResult(session.iterations);
        
        // Small delay between iterations (rate limiting, logging)
        await sleep(1000);
    }
    
    // If we exhausted iterations without confirmation
    if (!success && session.summary.finalVerdict !== 'DEAD_END') {
        session.summary.finalVerdict = determineFinalVericit(session);
    }
    
    session.endTime = new Date().toISOString();
    
    return session;
}
```

---

## Hacker Analysis Functions

### Analyze Fork Results

```javascript
function analyzeForkResult(forkResult, trackatorVisualization, hypothesis) {
    const analysis = {
        notes: [],
        verdict: null,  // PROGRESS, DEAD_END, PIVOT, RETRY
        modifications: []
    };
    
    // 1. State Diff Analysis
    if (trackatorVisualization?.stateDiff) {
        const { before, after } = trackatorVisualization.stateDiff;
        
        // Did attacker profit?
        const profit = calculateAttackerProfit(before, after, FORK_CONFIG.attackerAddress);
        
        if (profit > 0) {
            analysis.notes.push(`✅ Attacker profit: ${formatEther(profit)} ETH`);
            
            if (profit >= FORK_CONFIG.minimumViableProfitWei) {
                analysis.notes.push(`🎯 Profit exceeds threshold — EXPLOIT WORKING!`);
                analysis.verdict = 'SUCCESS';
            } else {
                analysis.notes.push(`⚠️ Profit too small (${formatEther(profit)} ETH)`);
                analysis.modifications.push({
                    type: 'scale_position',
                    description: 'Scale up attack size for meaningful profit',
                    suggestion: `Increase position size by ${Math.ceil(FORK_CONFIG.minimumViableProfitWei / profit)}x`
                });
            }
        } else {
            analysis.notes.push(`❌ No attacker profit detected`);
            
            // Did protocol lose funds? (might still be useful info)
            const protocolLoss = calculateProtocolLoss(before, after);
            if (protocolLoss > 0) {
                analysis.notes.push(`⚠️ Protocol lost ${formatEther(protocolLoss)} ETH but attacker didn't capture it`);
            }
        }
    }
    
    // 2. Revert Analysis
    if (forkResult.reverted) {
        analysis.notes.push(`❌ Transaction reverted: "${forkResult.revertReason}"`);
        
        // Generate fix based on revert reason
        const fixSuggestion = getFixForRevertReason(forkResult.revertReason, hypothesis);
        if (fixSuggestion) {
            analysis.modifications.push({
                type: 'fix_revert',
                description: `Address revert: "${forkResult.revertReason}"`,
                suggestion: fixSuggestion
            });
        }
        
        analysis.verdict = 'RETRY';
    }
    
    // 3. Alert Analysis
    if (trackatorVisualization?.alertsTriggered?.length > 0) {
        analysis.notes.push(`\n🚨 Alerts triggered: ${trackatorVisualization.alertsTriggered.length}`);
        
        for (const alert of trackatorVisualization.alertsTriggered) {
            analysis.notes.push(`   - ${alert.name} (${alert.severity})`);
            
            // Unexpected alert = potential pivot target
            if (!hypothesis.expectedAlerts?.includes(alert.id)) {
                analysis.notes.push(`   ⭐ UNEXPECTED ALERT — potential new attack vector!`);
                
                analysis.modifications.push({
                    type: 'pivot_attack',
                    description: `Pivot to exploit newly discovered alert: ${alert.name}`,
                    suggestion: `Focus attack on ${alert.id} instead of original hypothesis`
                });
                
                if (analysis.verdict !== 'SUCCESS') {
                    analysis.verdict = 'PIVOT';
                }
            }
        }
    }
    
    // 4. Oracle Impact Analysis
    if (trackatorVisualization?.oracleImpact) {
        const { deviationPercent, threshold, status } = trackatorVisualization.oracleImpact;
        
        analysis.notes.push(`\n📊 Oracle impact: ${deviationPercent}% deviation (threshold: ${threshold}%)`);
        
        if (status === 'ANOMALY_DETECTED') {
            if (deviationPercent >= threshold) {
                analysis.notes.push(`   ✅ Deviation exceeds threshold — manipulation working!`);
            } else {
                analysis.notes.push(`   ⚠️ Deviation detected but below threshold`);
                analysis.modifications.push({
                    type: 'increase_manipulation',
                    description: 'Increase price manipulation magnitude',
                    suggestion: 'Double flash loan size or add second swap leg'
                });
            }
        }
    }
    
    // 5. Invariant Violation Analysis
    if (trackatorVisualization?.invariantViolations?.length > 0) {
        analysis.notes.push(`\n💥 Invariant violations: ${trackatorVisualization.invariantViolations.length}`);
        
        for (const viol of trackatorVisualization.invariantViolations) {
            analysis.notes.push(`   - ${viol.id}: ${viol.expression}`);
            
            // Check if violation relates to our attack
            if (isRelatedToHypothesis(viol, hypothesis)) {
                analysis.notes.push(`     ✅ This violation supports our hypothesis!`);
            }
        }
    }
    
    // Set default verdict if not set
    if (!analysis.verdict) {
        analysis.verdict = forkResult.reverted ? 'RETRY' : 
                          (analysis.modifications.length > 0 ? 'RETRY' : 'DEAD_END');
    }
    
    return analysis;
}
```

### Modification Generation Patterns

```javascript
function getFixForRevertReason(revertReason, hypothesis) {
    const fixes = {
        // Common revert reasons and their fixes
        'Insufficient balance': 'Add deposit/seed transaction before attack',
        'Not authorized': 'Check alternative entry points or role acquisition paths',
        'Transfer failed': 'Verify token approval and balance conditions',
        'Slippage exceeded': 'Adjust swap parameters or use different DEX',
        'Deadline expired': 'Increase deadline or remove if unnecessary',
        'Already executed': 'Use fresh nonce/different input combination',
        'Invalid signature': 'Fix signature construction or permit flow',
        'Price too old': 'Execute within same block as price read',
        'Below minimum': 'Increase position size above minimum threshold',
        'Exceeds maximum': 'Split into multiple smaller transactions',
        'Paused': 'Cannot proceed — protocol paused (operational)',
        'ReentrancyGuard': 'Reentrancy guard working — cannot reenter'
    };
    
    // Exact match first
    if (fixes[revertReason]) return fixes[revertReason];
    
    // Partial match
    for (const [pattern, fix] of Object.entries(fixes)) {
        if (revertReason.toLowerCase().includes(pattern.toLowerCase())) {
            return fix;
        }
    }
    
    // Generic fallback
    return `Analyze specific revert condition: "${revertReason}"`;
}
```

---

## Evidence Collection

### What to Collect for Verifier

```javascript
function collectEvidence(session, hypothesis) {
    const bestIteration = session.summary.bestResult;
    
    return {
        // Basic info
        hypothesisId: hypothesis.id,
        sessionDuration: calculateDuration(session.startTime, session.endTime),
        totalIterations: session.summary.totalIterations,
        
        // Final verdict
        finalVerdict: session.summary.finalVerdict,
        confidence: calculateForkConfidence(session),
        
        // Best attempt evidence
        bestAttempt: bestIteration ? {
            iteration: bestIteration.iteration,
            txHash: bestIteration.execution.txHash,
            success: bestIteration.execution.success,
            gasUsed: bestIteration.execution.gasUsed,
            
            // Trackator evidence
            stateDiff: bestIteration.trackatorAnalysis?.stateDiff,
            alertsTriggered: bestIteration.trackatorAnalysis?.alertsTriggered,
            oracleImpact: bestIteration.trackatorAnalysis?.oracleImpact,
            invariantViolations: bestIteration.trackatorAnalysis?.invariantViolations,
            
            // Hacker notes
            hackerNotes: bestIteration.hackerNotes,
            hackerVerdict: bestIteration.hackerVerdict
        } : null,
        
        // Learning history (all iterations summary)
        iterationHistory: session.iterations.map(iter => ({
            iteration: iter.iteration,
            verdict: iter.verdict,
            reverted: iter.execution.reverted,
            revertReason: iter.execution.revertReason,
            keyLearning: iter.hackerNotes.slice(0, 3).join('; ')  // First 3 notes
        })),
        
        // Trackator visualizations (full set)
        allVisualizations: session.trackatorVisualizations.map(v => ({
            iteration: v.iteration,
            stateDiff: v.visualization.stateDiff,
            alerts: v.visualization.alerts,
            oracleImpact: v.visualization.oracleAnalysis
        }))
    };
}

function calculateForkConfidence(session) {
    let confidence = 0;
    
    // Base confidence on final verdict
    switch (session.summary.finalVerdict) {
        case 'CONFIRMED':
            confidence = 90;
            // Bonus for quick confirmation (fewer iterations = cleaner exploit)
            if (session.summary.totalIterations <= 3) confidence += 10;
            break;
        case 'PROBABLE':
            confidence = 60 + Math.max(0, 20 - session.summary.totalIterations * 2);
            break;
        case 'LEAD':
            confidence = 30;
            break;
        case 'DEAD_END':
            confidence = 10;  // Low but keep for record
            break;
        default:
            confidence = 40;
    }
    
    return Math.min(100, Math.max(0, confidence));
}
```

---

## Output Format

```javascript
{
    plugin: 'fork-test',
    runTimestamp: ISODateString,
    
    prerequisites: {
        ready: boolean,
        rpcAvailable: boolean,
        foundryAvailable: boolean,
        issues: string[]
    },
    
    smokeTest: {
        passed: boolean,
        checks: Array<{ check: string, status: string, output: string }>,
        errors: Array<{ phase: string, error: string }>
    },
    
    deepTest: {
        // Full session object from deepForkTestWithIteration()
        session: object,
        
        // Collected evidence for Verifier
        evidence: object
    },
    
    summary: {
        totalHypothesesTested: number,
        confirmed: number,
        probable: number,
        deadEnd: number,
        skipped: number,
        averageIterationsPerHypothesis: number
    }
}
```

---

## Integration Notes

### Relationship with Other Phases

| Phase | Input to Fork Test | Output from Fork Test |
|-------|--------------------|----------------------|
| Phase 2-3 | Traced hypotheses | Confirmation/evidence |
| Phase 4 | Fuzz-validated findings | Real-world validation |
| Verifier Agent | Receives evidence | Grades confidence |

### When to Skip

- **No RPC available**: Run without fork, mark findings as lower confidence
- **Protocol not deployed yet**: Use local deployment instead
- **Archive data needed but unavailable**: Partial fork possible

### Block Gate Application

After fork testing, apply BLOCK GATE logic:

| Fork Result | Block Gate Action | Confidence Boost |
|-------------|-------------------|------------------|
| CONFIRMED on fork | Report now | +35% |
| PROBABLE (partial success) | Report with caveats | +20% |
| LEAD (interesting failure) | Appendix only | +5% |
| DEAD END (proven impossible) | Discard silently | 0% |
| SKIPPED (no RPC) | Keep pre-fork confidence | 0% |

---

## Anti-Patterns (Avoid These)

❌ Running single attempt and giving up ("it didn't work")
❌ Ignoring revert reasons (they tell you WHAT went wrong)
❌ Not checking Trackator visualization (misses valuable insights)
❌ Assuming "reverted = impossible" (might just need precondition)
❌ Trying same thing twice without modification
❌ Reporting "confirmed" without TX hash proof

✅ Iterate up to MAX_ITERATIONS with intelligent modifications
✅ Document every attempt and learning
✅ Use Trackator visualization to understand WHY something worked/failed
✅ Only claim CONFIRMED with verifiable TX hash
✅ Return DEAD_END only after exhausting all modification strategies
