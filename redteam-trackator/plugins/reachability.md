# Plugin: Reachability Plugin

**Phase**: 2, 3, 4, 5 (Multiple checkpoints)
**Purpose**: Verify if attack hypotheses are actually achievable by external attackers
**Type**: **BLOCK GATE** plugin (saves for PoC, doesn't kill)

---

## Overview

This is the **BLOCK GATE** of Redteam-Trackator. Unlike old KILL gates that deleted findings, this plugin:

- **SAVES** findings that can't be immediately verified
- **GRADES** confidence rather than giving binary pass/fail
- **DEFERS** to fork testing when static analysis is insufficient

## Block Gate Philosophy

```
┌─────────────────────────────────────────────────────────────┐
│                    REACHABILITY BLOCK GATE                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Input: Hypothesis + Evidence                             │
│      ↓                                                     │
│   ┌─────────────────────────────────────────┐               │
│   │ Can we PROVE it's impossible?        │               │
│   │   → YES with certainty? → DEAD       │  (Only this    │
│   │   → NO or MAYBE?     → SAVE FOR POC   │   kills)       │
│   └─────────────────────────────────────────┘               │
│      ↓                                                     │
│   ┌─────────────────────────────────────────┐               │
│   │ Can we PROVE it's reachable?         │               │
│   │   → YES with evidence? → CONFIRMED   │               │
│   │   → PARTIAL evidence?  → PROBABLE    │               │
│   │   → NO evidence?      → LEAD        │               │
│   └─────────────────────────────────────────┘               │
│      ↓                                                     │
│   Output: Verdict + Block Gate Action                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Verdict States (CANONICAL — see SKILL.md Rule 4)

| Verdict | Meaning | Block Gate Action | Next Step |
|---------|---------|-------------------|-----------|
| `CONFIRMED_REACHABLE` | All preconditions satisfied, evidence strong | Save for PoC, prioritize | Phase 3/4/5 |
| `PROBABLE` | Most preconditions met, some unknowns | Save for PoC | Fork test to resolve |
| `LEAD` | Interesting but major gaps | Save for manual review | Appendix in report |
| `DEAD` | Proven impossible after thorough check | Discard silently | Remove from queue |
| `INCOMPLETE` | Need more info from Hacker | Return to Hacker | Request additional analysis |

**⚠️ Note**: `CONFIRMED_REACHABLE` is a sub-state for internal tracking. Final verdicts use canonical states: CONFIRMED, PROBABLE, LEAD, DEAD, INCOMPLETE.

## Checkpoint 1: Pattern Match Reachability (Phase 2)

### Input
- Pattern match result from Pattern Matcher Plugin
- Precondition chain from matched exploit card

### Checks Performed

```javascript
function checkPatternReachability(matchResult, context) {
    const preconditions = matchResult.preconditionChain || [];
    const checks = {
        preconditions: {},
        summary: { satisfied: 0, unsatisfied: 0, unknown: 0 }
    };
    
    for (let i = 0; i < preconditions.length; i++) {
        const pc = preconditions[i];
        const result = checkSinglePrecondition(pc, i, context);
        
        checks.preconditions[i] = result;
        
        if (result.status === 'satisfied') checks.summary.satisfied++;
        else if (result.status === 'unsatisfied') checks.summary.unsatisfied++;
        else checks.summary.unknown++;
    }
    
    // Determine verdict
    if (checks.summary.unsatisfied > 0 && checks.summary.unknown === 0) {
        checks.verdict = 'DEAD';
        checks.blockGateAction = 'discard';
        checks.reason = `${checks.summary.unsatisfied} preconditions proven unsatisfiable`;
    } else if (checks.summary.satisfied === preconditions.length) {
        checks.verdict = 'CONFIRMED_REACHABLE';
        checks.blockGateAction = 'save_prioritize';
        checks.reason = 'All preconditions satisfied';
    } else if (checks.summary.unknown >= checks.summary.satisfied) {
        checks.verdict = 'LEAD';
        checks.blockGateAction = 'save_for_fork';
        checks.reason = `More unknowns (${checks.summary.unknown}) than satisfied (${checks.summary.satisfied})`;
    } else {
        checks.verdict = 'PROBABLE';
        checks.blockGateAction = 'save_for_fork';
        checks.reason = `${checks.summary.satisfied}/${preconditions.length} satisfied, ${checks.summary.unknown} need testing`;
    }
    
    return checks;
}
```

### Precondition Type Handlers

#### External Call Existence

```javascript
function checkExternalCallExists(precondition, context) {
    // Find functions with external calls AND CEI violation
    const vulnerableFunctions = context.contracts
        .flatMap(c => c.functions || [])
        .filter(f => 
            f.body?.hasExternalCall === true && 
            f.body?.ceiPattern === 'violated'
        );
    
    if (vulnerableFunctions.length > 0) {
        return {
            status: 'satisfied',
            evidence: vulnerableFunctions.map(f => `${f.name} in ${f.contractName}`),
            trackatorFields: ['functions[].body.hasExternalCall', 'functions[].body.ceiPattern']
        };
    }
    
    return {
        status: 'unsatisfied',
        evidence: 'No functions with external calls before state updates found',
        trackatorFields: ['functions[].body.hasExternalCall', 'functions[].body.ceiPattern']
    };
}
```

#### No Reentrancy Guard

```javascript
function checkNoReentrancyGuard(precondition, context) {
    // Get functions that have external calls
    const functionsWithExternalCalls = context.contracts
        .flatMap(c => c.functions || [])
        .filter(f => f.body?.hasExternalCall === true);
    
    // Check which ones LACK nonReentrant modifier
    const unguarded = functionsWithExternalCalls.filter(f =>
        !f.modifiers?.some(m => 
            m.toLowerCase().includes('reentrancy') ||
            m.toLowerCase().includes('mutex') ||
            m.toLowerCase().includes('lock')
        )
    );
    
    if (unguarded.length > 0) {
        return {
            status: 'satisfied',
            evidence: unguarded.map(f => `${f.name}() lacks reentrancy guard`),
            trackatorFields: ['functions[].modifiers[]'],
            vulnerableFunctions: unguarded
        };
    }
    
    return {
        status: 'unsatisfied',
        evidence: 'All functions with external calls have guards',
        trackatorFields: ['functions[].modifiers[]']
    };
}
```

#### Attacker-Controlled Target

```javascript
function checkAttackerControlledTarget(precondition, context) {
    // Find functions where external call target could be attacker-controlled
    
    const vulnerableFunctions = [];
    
    for (const contract of context.contracts) {
        for (const func of contract.functions || []) {
            // Check 1: Function takes address parameter that gets called
            const addressParams = func.parameters?.filter(p => 
                p.type === 'address' || p.type === 'contract'
            ) || [];
            
            // Check 2: Function calls msg.sender (which is always attacker-controlled)
            const callsMsgSender = func.calls?.some(c => 
                c === 'msg.sender' || c.includes('.call{value:')
            ) || false;
            
            // Check 3: Function transfers to msg.sender or parameter address
            const transfersToCaller = func.body?.hasTransfer === true;
            
            if (addressParams.length > 0 || callsMsgSender || transfersToCaller) {
                // Verify it's accessible (public or role-based that attacker might have)
                const entryPoint = context.entryPoints?.find(e => 
                    e.name === func.name && e.contract === contract.name
                );
                
                if (entryPoint && entryPoint.access !== 'internal') {
                    vulnerableFunctions.push({
                        function: func.name,
                        contract: contract.name,
                        reason: addressParams.length > 0 
                            ? `Takes address param: ${addressParams.map(p => p.name).join(', ')}`
                            : callsMsgSender 
                                ? 'Calls msg.sender'
                                : 'Transfers to caller',
                        access: entryPoint.access
                    });
                }
            }
        }
    }
    
    if (vulnerableFunctions.length > 0) {
        return {
            status: 'satisfied',
            evidence: vulnerableFunctions,
            trackatorFields: ['functions[].parameters[]', 'entryPoints[].access']
        };
    }
    
    return {
        status: 'unknown',  // Might exist but not obvious from static analysis
        evidence: 'No obviously attacker-controlled targets found, dynamic analysis needed',
        trackatorFields: ['functions[].parameters[]', 'calls[]'],
        recommendation: 'Fork test to verify runtime behavior'
    };
}
```

#### Public Entry Point Exists

```javascript
function checkPublicEntryPointExists(precondition, context) {
    // For the vulnerable function(s), is there a public path?
    
    const publicEntryPoints = context.entryPoints?.filter(e => 
        e.access === 'anyone' && e.criticality !== 'low'
    ) || [];
    
    if (publicEntryPoints.length > 0) {
        return {
            status: 'satisfied',
            evidence: publicEntryPoints.map(e => `${e.name} in ${e.contract}`),
            count: publicEntryPoints.length,
            trackatorFields: ['entryPoints[].access']
        };
    }
    
    // Check if there are role-based entries that attacker might qualify for
    const roleBasedEntries = context.entryPoints?.filter(e => 
        e.access === 'role-based' && e.criticality !== 'low'
    ) || [];
    
    if (roleBasedEntries.length > 0) {
        return {
            status: 'unknown',  // Depends on whether attacker has role
            evidence: `Only role-based access: ${roleBasedEntries.map(e => e.name).join(', ')}`,
            trackatorFields: ['entryPoints[].access'],
            recommendation: 'Check if roles are obtainable (e.g., via token ownership)'
        };
    }
    
    return {
        status: 'unsatisfied',
        evidence: 'No public or plausibly accessible entry points found',
        trackatorFields: ['entryPoints[].access']
    };
}
```

## Checkpoint 2: Execution Trace Validation (Phase 3)

### Input
- Complete execution trace from Hacker agent
- Hypothesis being traced

### Validation Checklist

```javascript
function validateExecutionTrace(trace, hypothesis) {
    const validation = {
        isValid: false,
        completeness: 0,  // 0-100
        issues: [],
        blockGateAction: null
    };
    
    // Check 1: Trace exists and has steps
    if (!trace || !trace.steps || trace.steps.length === 0) {
        validation.issues.push({ code: 'EMPTY_TRACE', severity: 'critical' });
        return validation;
    }
    validation.completeness += 20;
    
    // Check 2: Starts at correct entry point
    const firstStep = trace.steps[0];
    if (firstStep.function === hypothesis.entryFunction || 
        firstStep.function === hypothesis.manipulationPoint) {
        validation.completeness += 10;
    } else {
        validation.issues.push({ 
            code: 'WRONG_START', 
            severity: 'medium',
            expected: hypothesis.entryFunction,
            actual: firstStep.function
        });
    }
    
    // Check 3: Follows call chain completely
    const hasEarlyTermination = trace.steps.some(s => 
        s.type === 'trace_limit_reached' || s.type === 'cycle_detected'
    );
    if (!hasEarlyTermination) {
        validation.completeness += 20;
    } else {
        validation.issues.push({
            code: 'INCOMPLETE_TRACE',
            severity: hasEarlyTermination ? 'critical' : 'low'
        });
    }
    
    // Check 4: External calls documented
    const externalCallSteps = trace.steps.filter(s => s.hasExternalCall);
    const documentedExternalCalls = externalCallSteps.filter(s => 
        s.note && s.note.includes('EXTERNAL')
    );
    
    if (documentedExternalCalls.length === externalCallSteps.length) {
        validation.completeness += 15;
    } else {
        validation.issues.push({
            code: 'UNDOCUMENTED_EXTERNAL_CALLS',
            count: externalCallSteps.length - documentedExternalCalls.length
        });
    }
    
    // Check 5: State changes tracked
    const stepsWithStateChanges = trace.steps.filter(s => 
        (s.stateVariablesRead?.length > 0 || s.stateVariablesWritten?.length > 0)
    );
    if (stepsWithStateChanges.length > 0) {
        validation.completeness += 15;
    }
    
    // Check 6: Guards noted
    const guardedSteps = trace.steps.filter(s => 
        s.modifiers && s.modifiers.some(m => 
            m.includes('nonReentrant') || m.includes('only') || m.includes('require')
        )
    );
    if (guardedSteps.length > 0) {
        validation.completeness += 10;
        // Check if guard effectiveness analyzed
        const guardAnalysis = trace.steps.filter(s => s.guardAnalysis);
        if (guardAnalysis.length >= guardedSteps.length * 0.5) {
            validation.completeness += 10;
        }
    }
    
    // Final verdict
    validation.isValid = validation.completeness >= 70 && 
        !validation.issues.some(i => i.severity === 'critical');
    
    // Block gate action
    if (validation.isValid) {
        validation.blockGateAction = trace.conclusion?.survives 
            ? 'proceed_to_next_phase' 
            : 'save_as_mitigated';
    } else if (validation.completeness >= 50) {
        validation.blockGateAction = 'return_to_hacker';  // Fixable issues
    } else {
        validation.blockGateAction = 'return_to_hacker';  // Major redo needed
    }
    
    return validation;
}
```

## Checkpoint 3: Fuzz Realism Verification (Phase 4)

### Input
- Fuzz campaign results
- Violations found by Echidna/Medusa

### Realism Assessment

```javascript
function assessFuzzRealism(violation, context) {
    const assessment = {
        isRealistic: false,
        score: 0,  // 0-100
        reasons: [],
        keepForReview: true  // Default: save, don't kill
    };
    
    // Check 1: Requires unrealistic state?
    if (requiresUnrealisticState(violation, context)) {
        assessment.reasons.push('Requires state unlikely on mainnet');
        assessment.score -= 30;
    } else {
        assessment.score += 20;
    }
    
    // Check 2: Requires trusted role action?
    if (requiresTrustedRoleAction(violation)) {
        assessment.isRealistic = false;
        assessment.keepForReview = false;  // Operational error
        assessment.reasons.push('Requires trusted role action - operational');
        return assessment;
    } else {
        assessment.score += 20;
    }
    
    // Check 3: Capital requirements feasible?
    const capitalReq = estimateCapitalRequired(violation);
    if (capitalReq > PROTOCOL_TVL * 0.1) {  // More than 10% of TVL
        assessment.reasons.push(`High capital required: $${capitalReq}M`);
        assessment.score -= 10;
    } else {
        assessment.score += 15;
    }
    
    // Check 4: Sequence length feasible?
    if (violation.sequenceLength > MAX_FEASIBLE_SEQUENCE) {
        assessment.reasons.push(`Sequence too long: ${violation.sequenceLength} txs`);
        assessment.score -= 15;
    } else {
        assessment.score += 15;
    }
    
    // Check 5: Time sensitivity feasible?
    if (violation.requiresSameBlock && !hasFlashLoanAccess(context)) {
        assessment.reasons.push('Requires same-block execution without flash loan source');
        assessment.score -= 10;
    } else {
        assessment.score += 10;
    }
    
    // Determine realism
    assessment.isRealistic = assessment.score >= 50;
    
    // Block gate
    if (assessment.isRealistic) {
        assessment.blockGateAction = 'proceed_to_fork';
    } else if (assessment.keepForReview && assessment.score >= 30) {
        assessment.blockGateAction = 'save_for_manual_review';
    } else {
        assessment.blockGateAction = 'discard';
    }
    
    return assessment;
}
```

## Checkpoint 4: Fork Test Evidence Validation (Phase 5)

### Input
- Fork test results from Hacker
- Trackator visualization of fork outcome

### Evidence Strength Scoring

```javascript
function validateForkEvidence(forkResult, hypothesis) {
    const validation = {
        strength: 0,
        isValid: false,
        blockGateAction: null,
        issues: []
    };
    
    // Check 1: Transaction exists (+20)
    if (forkResult.txHash && isValidEthereumTx(forkResult.txHash)) {
        validation.strength += 20;
    } else {
        validation.issues.push('NO_TX_HASH');
    }
    
    // Check 2: Trackator analysis present (+15)
    if (forkResult.trackatorAnalysis) {
        validation.strength += 15;
        const ta = forkResult.trackatorAnalysis;
        
        // Check 3: State diff shows profit (+15)
        if (ta.stateDiff) {
            const profit = calculateProfit(ta.stateDiff, hypothesis.attacker);
            if (profit > 0) {
                validation.strength += 15;
                validation.profit = profit;
            }
        }
        
        // Check 4: Relevant alerts triggered (+10)
        if (ta.alertsTriggered?.length > 0) {
            validation.strength += 10;
            const relevantAlerts = ta.alertsTriggered.filter(a =>
                isRelevantToHypothesis(a, hypothesis)
            );
            if (relevantAlerts.length > 0) {
                validation.strength += 10;
            }
        }
        
        // Check 5: Oracle impact significant (if applicable) (+10)
        if (ta.oracleImpact && hypothesis.involvesOracle) {
            validation.strength += 10;
            if (ta.oracleImpact.deviationPercent >= ta.oracleImpact.threshold) {
                validation.strength += 10;  // Significant manipulation
            }
        }
        
        // Check 6: Invariant violations confirm bug class (+10)
        if (ta.invariantViolations?.length > 0) {
            validation.strength += 10;
        }
    }
    
    // Check 7: Not operational error
    if (isOperationalError(forkResult, hypothesis)) {
        validation.issues.push('OPERATIONAL_ERROR');
        validation.blockGateAction = 'discard';
        return validation;
    }
    
    // Final determination
    validation.isValid = validation.strength >= 60;
    
    if (validation.strength >= 80) {
        validation.blockGateAction = 'report_now';  // Confirmed!
    } else if (validation.strength >= 60) {
        validation.blockGateAction = 'report_with_caveats';  // Probable
    } else if (validation.strength >= 30) {
        validation.blockGateAction = 'appendix_only';  // Lead
    } else {
        validation.blockGateAction = 'save_for_future_review';
    }
    
    return validation;
}
```

## Output Format (All Checkpoints)

```javascript
{
    plugin: 'reachability',
    checkpoint: 1 | 2 | 3 | 4,
    hypothesisId: string,
    
    input: object,  // Whatever was passed in
    
    verdict: 'CONFIRMED_REACHABLE' | 'PROBABLE' | 'LEAD' | 'DEAD' | 'INCOMPLETE',
    // Note: CONFIRMED_REACHABLE is sub-state. Final verdicts use canonical set.
    
    details: {
        // Checkpoint-specific data
    },
    
    blockGateAction: 'proceed_to_next_phase' | 'return_to_hacker' | 'save_for_poc' | 
                   'save_for_fork' | 'save_for_manual_review' | 'discard' | 'report_now' |
                   'report_with_caveats' | 'appendix_only',
    
    confidence: number,  // 0-100
    timestamp: ISODateString
}
```

## Summary Statistics

Track reachability statistics across all hypotheses:

```javascript
{
    totalHypothesesChecked: number,
    verdictDistribution: {
        confirmedReachable: number,
        probable: number,
        lead: number,
        dead: number,
        incomplete: number
    },
    blockGateActionsTaken: {
        proceedToNextPhase: number,
        returnToHacker: number,
        savedForPoC: number,
        discarded: number
    },
    averageConfidence: number,
    checkPointPassRates: {
        checkpoint1: number,  // Pattern match
        checkpoint2: number,  // Trace validation
        checkpoint3: number,  // Fuzz realism
        checkpoint4: number   // Fork evidence
    }
}
```

---

## v2.0 ENHANCED: Evidence Validator Integration

When Trackator's **Evidence Validator** data (`context.evidence`) is available, the Reachability plugin incorporates additional validation layers:

### Checkpoint 2.5: Pre-Classification Weighting (v2.0 NEW)

Before finalizing verdict at any checkpoint, check if Evidence Validator has already classified this finding:

```javascript
function applyPreClassificationWeighting(verdict, hypothesis, context) {
    if (!context.evidence?.classificationRegistry) {
        return verdict;  // No enhanced data - return unchanged
    }
    
    const preClass = findPreClassificationForHypothesis(hypothesis.id, context.evidence.classificationRegistry);
    
    if (!preClass) {
        return verdict;  // No pre-classification for this finding
    }
    
    // Adjust confidence based on pre-classification
    switch (preClass) {
        case 'confirmed-vulnerability':
            // Boost confidence - already validated by Evidence Validator
            verdict.confidence = Math.min((verdict.confidence || 50) + 15, 100);
            verdict.preClassification = 'confirmed-vulnerability';
            verdict.preClassificationBoost = +15;
            break;
            
        case 'potential-vulnerability':
            // Modest boost - likely but needs confirmation
            verdict.confidence = Math.min((verdict.confidence || 50) + 5, 100);
            verdict.preClassification = 'potential-vulnerability';
            verdict.preClassificationBoost = +5;
            break;
            
        case 'false-positive':
            // Significant downgrade - Evidence Validator thinks this is FP
            verdict.confidence = Math.max((verdict.confidence || 50) - 30, 0);
            verdict.preClassification = 'false-positive';
            verdict.preClassificationAdjustment = -30;
            
            // If confidence drops very low, consider discarding
            if (verdict.confidence < 20) {
                verdict.verdict = 'LEAD';  // Downgrade to lead, don't kill (block gate!)
                verdict.reason += ' [ADJUSTED: Evidence Validator indicates false-positive]';
            }
            break;
            
        case 'by-design':
            // Note as design choice, don't necessarily discard
            verdict.preClassification = 'by-design';
            verdict.note = 'Evidence Validator classifies as intentional design choice';
            break;
            
        default:
            // informational or cannot-determine - no adjustment
            verdict.preClassification = preClass;
            break;
    }
    
    return verdict;
}
```

### Checkpoint 2.6: Nine-Criteria Partial Application (v2.0 NEW)

At early checkpoints (1-2), we may not have all criteria yet. Apply what's available:

```javascript
function applyPartialNineCriteria(verdict, hypothesis, context) {
    if (!context.evidence?.reachabilityAnalysis) {
        return verdict;
    }
    
    // Look for existing reachability analysis from Evidence Validator
    const existingAnalysis = context.evidence.reachabilityAnalysis.find(
        r => r.findingId === hypothesis.id
    );
    
    if (!existingAnalysis) {
        return verdict;
    }
    
    // Extract criteria we can verify now vs. what needs later verification
    const criteriaNow = {
        entry_accessible: existingAnalysis.prerequisites?.find(
            p => p.condition === 'entry_accessible'
        ),
        gas_feasible: existingAnalysis.gasCostEstimate ? { satisfied: true } : null
    };
    
    // Apply available criteria to current verdict
    const satisfiedCount = Object.values(criteriaNow).filter(c => c?.satisfied).length;
    
    if (satisfiedCount > 0) {
        verdict.nineCriteriaPartial = {
            totalApplicable: Object.keys(criteriaNow).length,
            satisfied: satisfiedCount,
            criteria: criteriaNow,
            source: 'evidence-validator-reachability-analysis'
        };
        
        // Small confidence boost for each satisfied criterion
        verdict.confidence = Math.min(
            (verdict.confidence || 50) + (satisfiedCount * 3),
            100
        );
    }
    
    return verdict;
}
```

### Disproof Engine Awareness (v2.0 NEW)

If a finding has been through the Disproof Engine before reaching reachability:

```javascript
function applyDisproofAwareness(verdict, hypothesis, context) {
    const disproofResult = context.evidence?.disproofEngine?.disproofEvidence?.find(
        d => d.findingId === hypothesis.id
    );
    
    if (!disproofResult) {
        return verdict;
    }
    
    verdict.disproofStatus = disproofResult.reasonSafe || 'disproof-attempted';
    
    // If disproof found guard code that's effective, reduce confidence
    if (disproofResult.guardCodeFound && disproofResult.isEffective) {
        verdict.confidence = Math.max((verdict.confidence || 50) - 25, 5);
        verdict.disproofImpact = 'guard-code-found-effective';
        verdict.note = 'Disproof engine found effective guard code - vulnerability may be mitigated';
    } else if (disproofResult.guardCodeFound) {
        // Guard found but effectiveness uncertain
        verdict.disproofImpact = 'guard-code-found-effectiveness-uncertain';
        verdict.note = 'Guard code found but effectiveness needs manual review';
    }
    
    return verdict;
}
```

### Enhanced Output with v2.0 Data

When enhanced data is available, reachability output includes:

```javascript
{
    plugin: 'reachability',
    checkpoint: 1 | 2 | 3 | 4,
    hypothesisId: string,
    
    // Standard fields (unchanged)
    verdict: 'CONFIRMED_REACHABLE' | 'PROBABLE' | 'LEAD' | 'DEAD' | 'INCOMPLETE',
    details: object,
    blockGateAction: string,
    confidence: number,
    timestamp: ISODateString,
    
    // v2.0: Enhanced fields when Trackator data available
    v2Enhanced: {
        hasEnhancedData: boolean,
        
        // From Evidence Validator integration
        preClassification: {
            class: string | null,       // 6-class category
            confidenceAdjustment: number,
            appliedAtCheckpoint: number
        },
        
        // Nine-criteria partial results
        nineCriteriaPartial: {
            criteriaChecked: number,
            criteriaSatisfied: number,
            details: object | null
        },
        
        // Disproof engine awareness
        disproofAwareness: {
            wasAttempted: boolean,
            guardCodeFound: boolean,
            impactOnConfidence: number
        },
        
        // Cross-reference to other phases
        storageDataReferenced: string[],   // Storage fields used in checks
        couplingDataReferenced: string[],  // Coupling fields used in checks  
        syncDataReferenced: string[]        // Sync fields used in checks
    }
}
```

### v2.0 Integration Flow

```
Standard Reachability Check
         ↓
    Verdict Determined
         ↓
┌─────────────────────────────┐
│ Is context.evidence available? │
└───────────┬─────────────────┘
            │ YES
            ↓
┌─────────────────────────────┐
│ Apply Pre-Classification     │ ← Checkpoint 2.5
│ (boost/reduce confidence)    │
└───────────┬─────────────────┘
            ↓
┌─────────────────────────────┐
│ Apply Partial Nine-Criteria  │ ← Checkpoint 2.6
│ (use available criteria)     │
└───────────┬─────────────────┘
            ↓
┌─────────────────────────────┐
│ Apply Disproof Awareness     │ ← New check
│ (adjust for guard codes)      │
└───────────┬─────────────────┘
            ↓
    Final Enhanced Verdict
    (with v2Enhanced object)
```
