## Phase 4: FORK TESTING

### Objective
Validate findings against REAL mainnet state using Foundry fork testing. **This is where the hacker lives and iterates.**

**v2.0 ENHANCED**: Now includes **9-criteria reachability proof** from Evidence Validator for court-ready evidence.

**v2.1 ENHANCED**: Includes **Multi-Dimensional Evidence Calibration System** for consuming Evidence Validator outputs.

### 4.0: Evidence Calibration (v2.0 → v2.1 ENHANCED)

**Purpose**: Consume **Evidence Validator outputs** (Fix D) for court-ready confidence scoring.

**v2.1 ENHANCEMENT (Fix D Integration)**: Now consumes ALL output fields from enhanced `evidence-validator.ts`:
- ✅ `classificationRegistry` with full 6-class system (`proven-property`, `potential-bug`, `reachable-bug`, `false-positive`, `by-design`, `insufficient-evidence`)
- ✅ `reachabilityAnalysis[]` with execution paths, cross-contract prerequisites
- ✅ `disproofEngine` with 11 disproof strategies and confidence scores
- ✅ `confidenceAssessments[]` with multi-dimensional score breakdown
- ✅ `proofRequirements[]` with 9-criteria checklist for ReachableBug
- ✅ `finalVerdict[]` with RecommendedAction enum alignment

**When Evidence Data Available** (`context.evidence` exists):

```javascript
// ═══════════════════════════════════════════════════════════════
// v2.1 NEW: Enhanced Evidence Consumer for Fix D outputs
// ═══════════════════════════════════════════════════════════════
function calibrateEvidenceWithTrackator(finding, context) {
    if (!context.evidence) {
        console.log('⚠️ No evidence data available - using basic classification');
        return basicClassification(finding);
    }
    
    const calibration = {
        findingId: finding.id,
        
        // ═══════════════════════════════════════════════════
        // PART 1: 6-Class Classification (from Fix D)
        // ═══════════════════════════════════════════════════
        classification: null,
        classificationConfidence: 0,
        criteriaMet: [],
        criteriaFailed: [],
        
        // ═══════════════════════════════════════════════════
        // PART 2: Reachability Analysis (from Fix D)
        // ═══════════════════════════════════════════════════
        reachability: null,
        executionPath: null,
        crossContractPrereqs: [],
        blockingRequirement: null,
        
        // ═══════════════════════════════════════════════════
        // PART 3: Disproof Analysis (from Fix D)
        // ═══════════════════════════════════════════════════
        disproofResult: null,
        disproofConfidence: 0,
        disproofStrategiesAttempted: [],
        
        // ═══════════════════════════════════════════════════
        // PART 4: Multi-Dimensional Confidence (from Fix D)
        // ═══════════════════════════════════════════════════
        confidenceBreakdown: {
            overall: 0,
            evidenceStrength: 0,
            reachabilityConfidence: 0,
            impactConfidence: 0,
            falsePositiveRisk: 0
        },
        
        // ═══════════════════════════════════════════════════
        // PART 5: Proof Requirements (9-criteria from Fix D)
        // ═══════════════════════════════════════════════════
        proofRequirements: {
            met: 0,
            total: 9,
            requirements: [],
            status: 'not-proven'
        },
        
        // ═══════════════════════════════════════════════════
        // PART 6: Final Verdict & Action (from Fix D)
        // ═══════════════════════════════════════════════════
        finalVerdict: null,
        recommendedAction: null,
        remainingUnknowns: []
    };
    
    const { 
        classificationRegistry, 
        reachabilityAnalysis, 
        disproofAnalysis,
        confidenceAssessments,
        proofRequirementsList,
        finalVerdict
    } = context.evidence;
    
    // ──────────────────────────────────────────────
    // STEP 1: Apply 6-Class Classification
    // ──────────────────────────────────────────────
    if (classificationRegistry && classificationRegistry.entries) {
        // Find matching entry from Trackator's classification
        const matchingEntry = classificationRegistry.entries.find(e => 
            e.findingId === finding.id || 
            e.title === finding.title ||
            e.originalFindingId === finding.trackatorEvidence?.originalFindingId
        );
        
        if (matchingEntry) {
            calibration.classification = matchingEntry.classification;  // One of 6 classes
            calibration.classificationConfidence = matchingEntry.confidence;  // 0-100
            
            // Map criteria met/failed
            calibration.criteriaMet = matchingEntry.supportingEvidence?.map(e => e.itemId) || [];
            calibration.criteriaFailed = matchingEntry.blockingEvidence?.map(e => e.itemId) || [];
            
            console.log(`  📋 Classification: ${calibration.classification} (${calibration.classificationConfidence}%)`);
        } else {
            // No direct match - run local classification
            const localClass = classifyFindingV21(finding, context);
            calibration.classification = localClass.class;
            calibration.classificationConfidence = localClass.confidence;
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 2: Apply Reachability Analysis
    // ──────────────────────────────────────────────
    if (reachabilityAnalysis && reachabilityAnalysis.paths) {
        const matchingPath = reachabilityAnalysis.paths.find(p => p.findingId === finding.id);
        
        if (matchingPath) {
            calibration.reachability = matchingPath.isReachable ? 'reachable' : 'unreachable';
            calibration.executionPath = matchingPath.callChain;  // Full ExecutionStep[]
            
            // v2.1 NEW: Extract cross-contract prerequisites
            calibration.crossContractPrereqs = (matchingPath.crossContractPrereqs || []).map(ccp => ({
                targetContract: ccp.targetContract,
                requiredState: ccp.requiredState,
                dependencyType: ccp.dependencyType,
                canBeSatisfied: ccp.canBeSatisfied
            }));
            
            // Extract blocking requirement if unreachable
            if (!matchingPath.isReachable && matchingPath.blockingRequirement) {
                calibration.blockingRequirement = {
                    requirement: matchingPath.blockingRequirement.requirement,
                    type: matchingPath.blockingRequirement.type,
                    whyBlocking: matchingPath.blockingRequirement.whyBlocking,
                    potentialBypass: matchingPath.blockingRequirement.potentialBypass
                };
            }
            
            console.log(`  🎯 Reachability: ${calibration.reachability}${calibration.blockingRequirement ? ' (blocked: ' + calibration.blockingRequirement.type + ')' : ''}`);
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 3: Apply Disproof Analysis
    // ──────────────────────────────────────────────
    if (disproofAnalysis && disproofAnalysis.results) {
        const matchingDisproof = disproofAnalysis.results.find(r => r.findingId === finding.id);
        
        if (matchingDisproof) {
            calibration.disproofResult = matchingDisproof.newClassification;  // Reclassified?
            calibration.disproofConfidence = matchingDisproof.confidence;  // Confidence in reclassification
            
            // What strategies were tried?
            calibration.disproofStrategiesAttempted = (disproofAnalysis.disproofAttempts || [])
                .filter(a => a.targetFindingId === finding.id)
                .map(a => a.strategy);
            
            console.log(`  🛡️ Disproof: ${calibration.disproofResult} (${calibration.disproofConfidence}% confidence)`);
            console.log(`     Strategies tried: ${calibration.disproofStrategiesAttempted.join(', ') || 'none'}`);
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 4: Multi-Dimensional Confidence Score
    // ──────────────────────────────────────────────
    if (confidenceAssessments) {
        const matchingAssessment = confidenceAssessments.find(a => a.findingId === finding.id);
        
        if (matchingAssessment) {
            // v2.1 NEW: Full score breakdown from Fix D
            calibration.confidenceBreakdown = {
                overall: matchingAssessment.overallConfidence,
                evidenceStrength: matchingAssessment.evidenceStrength,
                reachabilityConfidence: matchingAssessment.reachabilityConfidence,
                impactConfidence: matchingAssessment.impactConfidence,
                falsePositiveRisk: matchingAssessment.falsePositiveRisk  // Higher = more likely FP
            };
            
            // v2.1 NEW: Track remaining unknowns for investigation
            calibration.remainingUnknowns = (matchingAssessment.remainingUnknowns || []).map(u => ({
                factor: u.factor,
                whyUnknown: u.whyUnknown,
                impactIfWrong: u.impactIfWrong,
                suggestedInvestigation: u.suggestedInvestigation
            }));
            
            console.log(`  📊 Confidence: ${calibration.confidenceBreakdown.overall}%`);
            console.log(`     Evidence: ${calibration.confidenceBreakdown.evidenceStrength}%, Reachability: ${calibration.confidenceBreakdown.reachabilityConfidence}%`);
            console.log(`     Impact: ${calibration.confidenceBreakdown.impactConfidence}%, FP Risk: ${calibration.confidenceBreakdown.falsePositiveRisk}%`);
            if (calibration.remainingUnknowns.length > 0) {
                console.log(`     ⚠️ Unknowns: ${calibration.remainingUnknowns.map(u => u.factor).join(', ')}`);
            }
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 5: Proof Requirements (9-criteria checklist)
    // ──────────────────────────────────────────────
    if (proofRequirementsList) {
        const matchingProofReq = proofRequirementsList.find(r => r.findingId === finding.id);
        
        if (matchingProofReq) {
            calibration.proofRequirements = {
                met: matchingProofReq.metRequirements,
                total: matchingProofReq.totalRequirements,
                status: matchingProofReq.overallStatus,  // proven-reachable | not-proven | disproven | insufficient-evidence
                requirements: (matchingProofReq.requirements || []).map(req => ({
                    id: req.reqId,
                    requirement: req.requirement,
                    category: req.category,
                    status: req.status,
                    hasEvidence: req.evidence !== undefined && req.evidence !== null,
                    explanation: req.explanation
                }))
            };
            
            console.log(`  ✓ Proof Requirements: ${calibration.proofRequirements.met}/${calibration.proofRequirements.total} (${calibration.proofRequirements.status})`);
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 6: Final Verdict & Recommended Action
    // ──────────────────────────────────────────────
    if (finalVerdict && finalVerdict.verdicts) {
        const matchingVerdict = finalVerdict.verdicts.find(v => v.findingId === finding.id);
        
        if (matchingVerdict) {
            calibration.finalVerdict = matchingVerdict.finalVerdict;  // confirmed-vulnerability | potential-vulnerability | false-positive | by-design | cannot-determine | deferred
            calibration.recommendedAction = matchingVerdict.recommendedAction;  // immediate-fix | short-term-investigation | long-term-monitoring | accept-risk | dismiss | escalate-to-auditor | defer
            
            console.log(`  ⚖️ Verdict: ${calibration.finalVerdict}`);
            console.log(`  ➡️ Action: ${calibration.recommendedAction}`);
        }
    }
    
    // If no final verdict from Trackator, derive from available data
    if (!calibration.finalVerdict) {
        calibration.finalVerdict = deriveVerdict(calibration);
        calibration.recommendedAction = deriveRecommendedAction(calibration);
    }
    
    return calibration;
}

// v2.1: Local classification fallback when no Trackator entry matches
function classifyFindingV21(finding, context) {
    // Use 6-class system from Fix D
    const classMapping = {
        'confirmed-vulnerability': { class: 'reachable-bug', minConfidence: 85 },
        'potential-vulnerability': { class: 'potential-bug', minConfidence: 60 },
        'false-positive': { class: 'false-positive', minConfidence: 0 },
        'by-design': { class: 'by-design', minConfidence: 0 },
        'informational': { class: 'proven-property', minConfidence: 30 },
        'cannot-determine': { class: 'insufficient-evidence', minConfidence: 0 }
    };
    
    // Calculate score based on available evidence
    let score = 50;  // Base uncertainty
    
    if (finding.trackatorEvidence?.matrixEntry) score += 15;
    if (finding.prerequisiteChain?.length >= 4) score += 10;
    if (finding.estimatedDifficulty === 'easy') score += 10;
    if (finding.trackatorEvidence?.source === 'criticalFindings[]') score += 15;
    
    // Determine class based on score and disproof result
    if (finding.disproofResult === 'DISPROVED') {
        return { class: 'false-positive', confidence: 10 };
    } else if (score >= 85) {
        return { class: 'reachable-bug', confidence: score };
    } else if (score >= 60) {
        return { class: 'potential-bug', confidence: score };
    } else if (score >= 30) {
        return { class: 'insufficient-evidence', confidence: score };
    } else {
        return { class: 'cannot-determine', confidence: score };
    }
}

// v2.1: Derive verdict when Trackator doesn't provide one
function deriveVerdict(calibration) {
    if (calibration.disproofResult === 'false-positive' || calibration.disproofResult === 'by-design') {
        return calibration.disproofResult;
    }
    
    if (calibration.classification === 'reachable-bug' && calibration.reachability === 'reachable') {
        if (calibration.proofRequirements.met >= 7) return 'confirmed-vulnerability';
        return 'potential-vulnerability';
    }
    
    if (calibration.classification === 'potential-bug' && calibration.confidenceBreakdown.overall >= 70) {
        return 'potential-vulnerability';
    }
    
    if (calibration.remainingUnknowns?.length > 3) {
        return 'cannot-determine';
    }
    
    return 'deferred';
}

// v2.1: Derive recommended action from verdict
function deriveRecommendedAction(calibration) {
    const actionMap = {
        'confirmed-vulnerability': 'immediate-fix',
        'potential-vulnerability': 'short-term-investigation',
        'false-positive': 'dismiss',
        'by-design': 'accept-risk',
        'cannot-determine': 'escalate-to-auditor',
        'deferred': 'defer'
    };
    
    return actionMap[calibration.finalVerdict] || 'defer';
}
```

### Classification Classes Reference

| Class | Description | Action |
|-------|-------------|--------|
| `confirmed-vulnerability` | Reachable, exploitable, high-confidence bug | Report as P0/P1 finding |
| `potential-vulnerability` | Likely exploitable but needs manual verification | Report with caveats as P2 |
| `false-positive` | Theoretically matches pattern but not actually exploitable | Discard with documentation |
| `by-design` | Looks like bug but intentional security trade-off | Note in methodology |
| `informational` | Not a bug but worth noting (code smell, anti-pattern) | Appendix only |
| `cannot-determine` | Insufficient evidence to classify | Queue for manual review |

### Phase 4 Output

```javascript
hypothesis.evidenceCalibration = {
    classification: string,
    classificationConfidence: number,
    reachability: string,
    disproofResult: FinalVerdict | null,
    confidenceBreakdown: { overall: number, evidenceStrength: number, reachabilityConfidence: number, impactConfidence: number, falsePositiveRisk: number },
    proofRequirements: { met: number, total: number, status: string },
    finalVerdict: string,
    recommendedAction: string
};

hypothesis.forkTestResult = {
    smokeTest: { passed: boolean, error: string },
    deepTest: {
        success: boolean,
        totalIterations: number,
        results: [/* iteration results */],
        bestResult: {
            iteration: number,
            txHash: string,
            trackatorAnalysis: {},
            verdict: string
        },
        finalVerdict: 'CONFIRMED' | 'PROBABLE' | 'DEAD' | 'INCONCLUSIVE'
    }
};
```

### 4.1: Fork Testing Infrastructure

```javascript
const FORK_CONFIG = {
    rpcUrl: process.env.MAINNET_RPC_URL || 'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
    blockNumber: process.env.FORK_BLOCK_NUMBER || 'latest',
    maxIterations: MAX_FORK_ITERATIONS || 10,
    timeoutMs: 300000  // 5 minutes max per iteration
};
```

### Step 4.1: Smoke Fork Test

**Purpose**: Verify basic functionality works on forked state.

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

### Step 4.2: Deep Fork Testing (with Iteration)

**THIS IS THE HEART OF PHASE 4.**

The hacker runs exploit attempts on forked mainnet, observes Trackator visualization of results, and ITERATES until success or max iterations.

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
        // Feed fork result into Trackator for analysis
        const trackatorVisualization = await trackatorAnalyzer.analyzeForkResult(forkResult);
        
        const iterationResult = {
            iteration,
            exploitAttempt: exploitAttempt.description,
            txHash: forkResult.txHash,
            success: forkResult.success,
            reverted: forkResult.reverted,
            revertReason: forkResult.revertReason,
            gasUsed: forkResult.gasUsed,
            
            // Trackator Analysis
            trackatorAnalysis: {
                stateDiff: trackatorVisualization.stateDiff,  // What changed
                alertsTriggered: trackatorVisualization.alerts,  // New anomalies
                oracleImpact: trackatorVisualization.oracleAnalysis,  // Price effects
                invariantViolations: trackatorVisualization.violations  // Broken invariants
            },
            
            // Hacker Assessment
            hackerNotes: '',  // Filled below
            modifications: []  // What to change for next attempt
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

### Hacker Visualization Analysis

**How hacker interprets Trackator output**:

```javascript
function analyzeVisualization(visualization, hypothesis) {
    const notes = [];
    
    // 1. State Diff Analysis
    if (visualization.stateDiff) {
        const { before, after } = visualization.stateDiff;
        
        // Did attacker balance increase meaningfully?
        const attackerProfit = calculateProfit(before, after, hypothesis.attackerAddress);
        
        if (attackerProfit > 0) {
            notes.push(`✅ Attacker profit: ${formatEther(attackerProfit)} ETH`);
            
            if (attackerProfit > MINIMUM_VIABLE_PROFIT) {
                notes.push(`🎯 Profit exceeds minimum threshold - EXPLOIT WORKING`);
            } else {
                notes.push(`⚠️ Profit too small (${attackerProfit}) - need larger position`);
            }
        } else {
            notes.push(`❌ No profit - state changes don't benefit attacker`);
        }
        
        // Did protocol lose funds?
        const protocolLoss = calculateProtocolLoss(before, after);
        if (protocolLoss > 0) {
            notes.push(`💸 Protocol loss: ${formatEther(protocolLoss)} ETH`);
        }
    }
    
    // 2. Alert Analysis
    if (visualization.alertsTriggered?.length > 0) {
        notes.push(`\n🚨 Alerts triggered: ${visualization.alertsTriggered.length}`);
        for (const alert of visualization.alertsTriggered) {
            notes.push(`   - ${alert.name} (${alert.severity})`);
            
            // Unexpected alert = new attack vector?
            if (!hypothesis.expectedAlerts?.includes(alert.id)) {
                notes.push(`   ⭐ UNEXPECTED ALERT - potential new attack vector!`);
            }
        }
    }
    
    // 3. Oracle Impact
    if (visualization.oracleImpact) {
        const { deviationPercent, threshold, status } = visualization.oracleImpact;
        
        notes.push(`\n📊 Oracle impact: ${deviationPercent}% deviation (threshold: ${threshold}%)`);
        
        if (status === 'ANOMALY_DETECTED') {
            if (deviationPercent < threshold) {
                notes.push(`   ⚠️ Deviation detected but below threshold - need bigger move`);
            } else {
                notes.push(`   ✅ Deviation exceeds threshold - manipulation working!`);
            }
        }
    }
    
    // 4. Invariant Violations
    if (visualization.invariantViolations?.length > 0) {
        notes.push(`\n💥 Invariant violations: ${visualization.invariantViolations.length}`);
        for (const viol of visualization.invariantViolations) {
            notes.push(`   - ${viol.id}: ${viol.expression}`);
        }
    }
    
    return notes.join('\n');
}
```

### Modification Generation (How Hacker Iterates)

```javascript
function generateModifications(visualization, hypothesis, iteration) {
    const mods = [];
    
    // Based on what went wrong, suggest fixes
    
    // Case 1: Reverted with specific error
    if (visualization.revertReason) {
        mods.push({
            type: 'fix_revert',
            description: `Address revert: "${visualization.revertReason}"`,
            suggestion: getFixForRevert(visualization.revertReason)
        });
    }
    
    // Case 2: Not enough price movement
    if (visualization.oracleImpact?.deviationPercent < 
        visualization.oracleImpact?.threshold) {
        mods.push({
            type: 'increase_manipulation',
            description: 'Increase flash loan size for stronger price impact',
            suggestion: 'Double flash loan amount or add second swap leg'
        });
    }
    
    // Case 3: Profit too small
    if (visualization.profit > 0 && visualization.profit < MINIMUM_VIABLE_PROFIT) {
        mods.push({
            type: 'scale_position',
            description: 'Scale up attack size for meaningful profit',
            suggestion: 'Increase deposit/borrow amount proportionally'
        });
    }
    
    // Case 4: Need preliminary transactions
    if (visualization.missingPreconditions?.length > 0) {
        mods.push({
            type: 'add_precondition',
            description: 'Add missing precondition transactions',
            suggestion: `Execute first: ${visualization.missingPreconditions.join(', ')}`
        });
    }
    
    // Case 5: New unexpected alert = new idea
    const unexpectedAlerts = visualization.alertsTriggered?.filter(a =>
        !hypothesis.expectedAlerts?.includes(a.id)
    ) || [];
    
    if (unexpectedAlerts.length > 0) {
        mods.push({
            type: 'pivot_attack',
            description: 'Pivot to exploit newly discovered alert',
            suggestion: `Focus on ${unexpectedAlerts[0].name} instead`
        });
    }
    
    return mods;
}
```

### Phase 5 Output

```javascript
hypothesis.forkTestResult = {
    smokeTest: { passed: boolean, error: string },
    deepTest: {
        success: boolean,
        totalIterations: number,
        results: [/* iteration results */],
        bestResult: {
            iteration: number,
            txHash: string,
            trackatorAnalysis: {},
            verdict: string
        },
        finalVerdict: 'CONFIRMED' | 'PROBABLE' | 'DEAD' | 'INCONCLUSIVE'
    }
};
```

---

