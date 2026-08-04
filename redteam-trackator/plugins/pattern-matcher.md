# Plugin: Pattern Matcher Plugin

**Phase**: 2 (Pattern Matching)
**Purpose**: Cross-reference Trackator alerts against historical exploit patterns from Exploits-class-library
**Type**: Analysis plugin (finds matches, scores them)

---

## Overview

This plugin matches current protocol anomalies against 56+ historical exploit patterns to:
1. Find known vulnerability classes
2. Assess severity based on historical losses
3. Provide detection heuristics from real exploits
4. Identify precondition chains that must be satisfied

## Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Surviving hypotheses | Phase 1 output | Filtered alerts to match |
| Protocol context | Phase 0 output | Protocol type, components |
| Exploits library | External | `Exploits-class-library/` directory |
| **Storage data** | **Trackator Phase 1** | `context.storage` - value-bearing variables, writers, contended vars |
| **Coupling data** | **Trackator Phase 2** | `context.coupling` - function dependency matrix, hidden couplings |
| **Sync data** | **Trackator Phase 3** | `context.sync` - desync risks, assumption dependency graph |
| **Evidence data** | **Trackator Phase 4** | `context.evidence` - classification registry, confidence scores |

## Library Structure Reference

```
Exploits-class-library/
├── card-index.csv                          # Metadata for all 56 cards
├── protocol-type-to-exploit-patterns.json   # Protocol type → applicable patterns
└── exploit-pattern-cards/
    ├── reentrancy-state-update-after-external-call.md      # $4.75M loss
    ├── flash-loan-spot-price-manipulation-single-tx.md     # $300K loss
    ├── missing-modifier-privileged-function.md             # $4.9M loss
    ├── first-depositor-share-price-inflation.md              # $15.8M loss
    ├── stableswap-virtual-balance-invariant-drift.md        # $129M loss
    └── ... (56 total pattern cards)
```

## Card Structure (What Each Contains)

Each exploit pattern card has:

```markdown
# Exploit Pattern: {slug}

## Source
| Field | Value |
|-------|-------|
| Protocol exploited | {name} |
| Loss | ${USD} |
| Attacker TX | {link} |

## Bug Class
- **Primary**: {primary_class}
- **Secondary**: {secondary_class}

## Protocol Types
`{list of applicable protocol types}`

## Root Cause
{Explanation of vulnerability}

## Precondition Chain
1. {Precondition 1}
2. {Precondition 2}
3. ...
N. {Precondition N}

## Attack Pattern
1. {Step 1}
2. {Step 2}
...

## Detection Heuristic
### Signature (2-4 sentences)
{Human-readable detection pattern}

### Grep patterns
```
{code search patterns}
```

### Detection checklist (5 steps)
1. {Check 1}
...
5. {Check 5}

## Variants
### Variant 1: {name}
{code example}

## Anti-Examples
1. {Safe pattern}
2. {Safe pattern}

## Economic Context
| Metric | Value |
|--------|-------|
| Extracted value | ${amount} |
| Attack cost | ${gas} |
| Capital required | {source} |

## Historical Occurrences
| Protocol | Date | Loss | Source |
|----------|------|------|--------|
| ... | ... | ... | ... |
```

## Matching Algorithm

### Step 1: Load Applicable Patterns

```javascript
function loadApplicablePatterns(protocolType, libraryPath) {
    // Read protocol-type-to-exploit-patterns.json
    const typeMap = readJson(`${libraryPath}/protocol-type-to-exploit-patterns.json`);
    
    // Get patterns for this protocol type
    const applicable = typeMap[protocolType] || [];
    
    // Also get "Any" type patterns
    const anyType = typeMap['Any'] || [];
    
    return [...applicable, ...anyType];
}
```

**Protocol types in library**:

| Type | Example Patterns |
|------|------------------|
| Lending | Self-liquidation via donation, Health factor miscalculation, Oracle dependency |
| Dexes | AMM reserve skim, Flash loan spot price, Callback manipulation |
| Bridge | Message trusted root bypass, Signature replay |
| Staking | Repeated reward claim no reset, Lock then immediate claim |
| Yield Aggregators | Redundant mint entrypoint, Referral bonus error |
| DAOs/Governance | Proposal executed without timelock |
| Any (EOA-restricted) | EOA-only restriction bypassed via EIP-7702 |

### Step 2: Calculate Match Score

```javascript
function calculateMatchScore(alert, pattern) {
    let score = 0;
    const details = {};
    
    // Factor 1: Bug class match (weight: 30%)
    const classMatch = compareBugClass(alert.category, pattern.primary_bug_class);
    score += classMatch * 0.30;
    details.bugClassMatch = classMatch;
    
    // Factor 2: Protocol type compatibility (weight: 25%)
    const typeCompatibility = checkProtocolTypeCompatibility(
        alert.protocolType, 
        pattern.protocol_types
    );
    score += typeCompatibility * 0.25;
    details.typeCompatibility = typeCompatibility;
    
    // Factor 3: Detection heuristic match (weight: 25%)
    const heuristicMatch = matchDetectionHeuristic(alert, pattern.detection_heuristic);
    score += heuristicMatch * 0.25;
    details.heuristicMatch = heuristicMatch;
    
    // Factor 4: Severity alignment (weight: 10%)
    const severityAlignment = alignSeverity(alert.severity, pattern.representative_loss_usd);
    score += severityAlignment * 0.10;
    details.severityAlignment = severityAlignment;
    
    // Factor 5: Precondition feasibility (weight: 10%)
    const precondFeasibility = checkPreconditionFeasibility(alert, pattern.precondition_chain);
    score += precondFeasibility * 0.10;
    details.preconditionFeasibility = precondFeasibility;
    
    return {
        score,
        details,
        exceedsThreshold: score >= MATCH_THRESHOLD  // Default: 0.5
    };
}
```

### Step 3: Bug Class Comparison Map

```javascript
const BUG_CLASS_MAP = {
    'reentrancy': ['reentrancy', 'checks-effects-interactions-violation'],
    'access-control': ['access-control', 'missing-auth', 'privilege-escalation'],
    'oracle-manipulation': ['oracle-manipulation', 'price-manipulation', 'price-oracle'],
    'flash-loan': ['flash-loan', 'flash-loan-vulnerability'],
    'accounting-error': ['accounting-error', 'double-spend', 'rounding-error'],
    'arithmetic-error': ['integer-overflow-underflow', 'arithmetic-error'],
    'business-logic-flaw': ['business-logic-flaw', 'logic-error'],
    'denial-of-service': ['denial-of-service', 'dos'],
    'signature-replay': ['signature-replay', 'signature-forgery'],
    'governance-manipulation': ['governance-manipulation']
};

function compareBugClass(alertCategory, patternPrimaryClass) {
    alertNormalized = alertCategory.toLowerCase().replace(/-/g, ' ');
    patternNormalized = patternPrimaryClass.toLowerCase().replace(/-/g, ' ');
    
    // Direct match
    if (alertNormalized === patternNormalized) return 1.0;
    
    // Check synonym lists
    const alertSynonyms = BUG_CLASS_MAP[alertCategory] || [alertCategory];
    if (alertSynonyms.includes(patternPrimaryClass)) return 0.9;
    
    // Partial match
    if (alertNormalized.includes(patternNormalized.split(' ')[0]) ||
        patternNormalized.includes(alertNormalized.split(' ')[0])) {
        return 0.6;
    }
    
    // No match
    return 0.0;
}
```

### Step 4: Detection Heuristic Matching

```javascript
function matchDetectionHeuristic(alert, heuristic) {
    if (!heuristic) return 0.5;  // Neutral if no heuristic
    
    let matches = 0;
    let totalChecks = 0;
    
    // Check signature keywords against alert name/description
    const signatureKeywords = extractKeywords(heuristic.signature);
    const alertText = `${alert.name} ${alert.description || ''}`.toLowerCase();
    
    for (const keyword of signatureKeywords) {
        totalChecks++;
        if (alertText.includes(keyword.toLowerCase())) {
            matches++;
        }
    }
    
    // Check condition type alignment
    if (heuristic.grepPatterns) {
        const relevantGrep = heuristic.grepPatterns.filter(p => 
            isRelevantToAlert(p, alert)
        );
        totalChecks += relevantGrep.length;
        
        for (const grep of relevantGrep) {
            if (couldGenerateAlert(grep, alert)) {
                matches++;
            }
        }
    }
    
    return totalChecks > 0 ? matches / totalChecks : 0.5;
}
```

### Step 5: v2.0 Enhanced Scoring with Trackator Multi-Phase Data

When Trackator's enhanced analysis phases are available, the match scoring incorporates **storage dependency evidence**, **state coupling signals**, **synchronization risks**, and **evidence validator classifications**:

```javascript
function calculateMatchScore_v2(alert, pattern, context) {
    // Start with base score (Factors 1-5 from v1.0)
    const baseResult = calculateMatchScore(alert, pattern);
    let score = baseResult.score;
    const details = { ...baseResult.details, v2Enhancements: {} };

    // Factor 6: Storage Dependency Alignment (weight: +10% bonus)
    // Does this pattern target value-bearing variables that have permissionless writers?
    if (context.storage?.valueBearingVariables) {
        const storageAlignment = checkStorageAlignment(alert, pattern, context.storage);
        score += storageAlignment * 0.10;
        details.v2Enhancements.storageAlignment = storageAlignment;

        // BONUS: If pattern targets contended variable with permissionless writer
        if (storageAlignment > 0.8 && hasExploitableStorageTarget(alert, context.storage)) {
            score += 0.05;  // Extra bonus for directly exploitable storage
            details.v2Enhancements.exploitableStorageBonus = true;
        }
    }

    // Factor 7: State Coupling Signal (weight: +10% bonus)
    // Does this pattern exploit atomicity violations or hidden couplings?
    if (context.coupling?.functionDependencyMatrix) {
        const couplingSignal = checkCouplingSignal(alert, pattern, context.coupling);
        score += couplingSignal * 0.10;
        details.v2Enhancements.couplingSignal = couplingSignal;

        // BONUS: Strong coupling + accessible functions = high confidence
        if (couplingSignal > 0.7 && hasAccessibleCoupling(alert, context.coupling)) {
            score += 0.05;
            details.v2Enhancements.atomicityViolationBonus = true;
        }
    }

    // Factor 8: Synchronization Risk (weight: +10% bonus)
    // Is this a timing-based attack supported by desync analysis?
    if (context.sync?.criticalDesyncRisks) {
        const syncRisk = checkSyncRisk(alert, pattern, context.sync);
        score += syncRisk * 0.10;
        details.v2Enhancements.syncRisk = syncRisk;

        // BONUS: Critical/high severity desync risk = very exploitable
        if (syncRisk > 0.8) {
            score += 0.05;
            details.v2Enhancements.criticalDesyncBonus = true;
        }
    }

    // Factor 9: Evidence Validator Pre-Classification (weight: adjusts confidence)
    // Has this finding already been partially validated by Evidence Validator?
    if (context.evidence?.classificationRegistry) {
        const preClassification = checkPreClassification(alert, context.evidence);
        details.v2Enhancements.preClassification = preClassification;

        // Adjust based on pre-classification
        if (preClassification.class === 'confirmed-vulnerability') {
            score = Math.min(score + 0.15, 1.0);  // Cap at 1.0
        } else if (preClassification.class === 'false-positive') {
            score *= 0.5;  // Significant downgrade
        } else if (preClassification.class === 'potential-vulnerability') {
            score += 0.05;  // Modest boost
        }
    }

    return {
        score: Math.min(score, 1.0),  // Cap at 1.0
        details,
        exceedsThreshold: score >= MATCH_THRESHOLD,
        v2Enhanced: true
    };
}

// --- v2.0 Helper Functions ---

// Check if pattern aligns with storage dependency findings
function checkStorageAlignment(alert, pattern, storage) {
    let alignment = 0;

    // Does the pattern target a value-bearing variable?
    const targetVar = extractTargetVariable(alert);  // Extract from alert description
    if (targetVar) {
        const isValueBearing = storage.valueBearingVariables?.some(
            vbv => vbv.variable === targetVar
        );
        if (isValueBearing) alignment += 0.4;

        // Does it have permissionless writers?
        const writers = storage.variableWriters?.get(targetVar) || [];
        const hasPermissionless = writers.some(w =>
            w.accessControlLevel === 'none' || w.accessControlLevel === 'permissionless'
        );
        if (hasPermissionless) alignment += 0.4;

        // Is it contended (race condition)?
        const isContended = storage.contentedVariables?.some(
            cv => cv.variable === targetVar && cv.writerCount >= 2
        );
        if (isContended) alignment += 0.2;
    }

    return Math.min(alignment, 1.0);
}

// Check if pattern exploits state coupling
function checkCouplingSignal(alert, pattern, coupling) {
    let signal = 0;

    // Extract functions involved in the attack pattern
    const involvedFunctions = extractInvolvedFunctions(pattern.attackPattern);

    for (let i = 0; i < involvedFunctions.length - 1; i++) {
        const funcA = involvedFunctions[i];
        const funcB = involvedFunctions[i + 1];
        const pairKey = `${funcA}->${funcB}`;

        // Check function dependency matrix
        const couplingData = coupling.functionDependencyMatrix?.[pairKey];
        if (couplingData) {
            if (couplingData.strength === 'STRONG' || couplingData.strength > 0.7) {
                signal = Math.max(signal, 0.8);  // Strong coupling = high signal
            } else if (couplingData.strength > 0.4) {
                signal = Math.max(signal, 0.5);  // Medium coupling
            }
        }
    }

    // Check for hidden couplings that match this pattern type
    const patternType = classifyPatternType(pattern.primary_bug_class);
    const matchingHiddenCouplings = (coupling.hiddenCouplings || []).filter(hc => {
        return hc.couplingType === patternType ||
               (patternType === 'atomicity' && hc.strength === 'STRONG');
    });

    if (matchingHiddenCouplings.length > 0) {
        signal = Math.max(signal, 0.7);
    }

    return Math.min(signal, 1.0);
}

// Check if pattern exploits synchronization issues
function checkSyncRisk(alert, pattern, sync) {
    let risk = 0;

    const patternCategory = pattern.primary_bug_class?.toLowerCase() || '';

    // Timing/oracle/price patterns benefit from sync data
    const timingRelatedPatterns = [
        'oracle-manipulation', 'flash-loan', 'sandwich-attack',
        'front-running', 'mev', 'price-manipulation', 'stale-price'
    ];

    if (timingRelatedPatterns.some(p => patternCategory.includes(p))) {
        // Check for critical desync risks
        const relevantRisks = (sync.criticalDesyncRisks || []).filter(r =>
            r.riskType === 'stale-price' ||
            r.riskType === 'race-window' ||
            r.riskType === 'missing-verifier'
        );

        if (relevantRisks.some(r => r.severity === 'critical')) {
            risk = 0.9;
        } else if (relevantRisks.some(r => r.severity === 'high')) {
            risk = 0.7;
        } else if (relevantRisks.length > 0) {
            risk = 0.5;
        }

        // Check assumption dependency graph for unverified assumptions
        const unverifiedAssumptions = findUnverifiedAssumptions(sync);
        if (unverifiedAssumptions.length > 0) {
            risk = Math.max(risk, 0.6);
        }
    }

    return Math.min(risk, 1.0);
}

// Check pre-classification from Evidence Validator
function checkPreClassification(alert, evidence) {
    const registry = evidence.classificationRegistry;

    // Check each class for this alert
    if (registry.confirmedVulnerability?.some(f => f.findingId === alert.id)) {
        return { class: 'confirmed-vulnerability', criteriaMet: true };
    }
    if (registry.potentialVulnerability?.some(f => f.findingId === alert.id)) {
        return { class: 'potential-vulnerability', criteriaMet: true };
    }
    if (registry.falsePositive?.some(f => f.findingId === alert.id)) {
        return { class: 'false-positive', disproofEvidence: true };
    }
    if (registry.byDesign?.some(f => f.findingId === alert.id)) {
        return { class: 'by-design', designRationale: true };
    }

    return { class: 'unknown', criteriaMet: false };
}

// --- v2.0 Helper Functions (continued) ---

/**
 * hasExploitableStorageTarget - Check if pattern targets an exploitable storage variable
 * @param {object} alert - The alert being checked
 * @param {object} storage - Storage Dependency Analyzer data
 * @returns {boolean} - True if there's a directly exploitable storage target
 */
function hasExploitableStorageTarget(alert, storage) {
    const targetVar = extractTargetVariable(alert);
    if (!targetVar || !storage) return false;
    
    // Check for value-bearing variable with permissionless writer
    const isValueBearing = storage.valueBearingVariables?.some(
        vbv => vbv.variable === targetVar
    );
    
    if (!isValueBearing) return false;
    
    // Check writers for permissionless access
    const writers = storage.variableWriters?.get(targetVar) || [];
    return writers.some(w =>
        w.accessControlLevel === 'none' || w.accessControlLevel === 'permissionless'
    );
}

/**
 * hasAccessibleCoupling - Check if coupling involves attacker-accessible functions
 * @param {object} alert - The alert being checked  
 * @param {object} coupling - State Coupling Detector data
 * @returns {boolean} - True if strong coupling exists between accessible functions
 */
function hasAccessibleCoupling(alert, coupling) {
    if (!coupling?.functionDependencyMatrix) return false;
    
    const involvedFunctions = extractInvolvedFunctionsFromAlert(alert);
    if (involvedFunctions.length < 2) return false;
    
    for (let i = 0; i < involvedFunctions.length - 1; i++) {
        const funcA = involvedFunctions[i];
        const funcB = involvedFunctions[i + 1];
        const pairKey = `${funcA}->${funcB}`;
        
        const couplingData = coupling.functionDependencyMatrix[pairKey];
        if (couplingData && (couplingData.strength === 'STRONG' || couplingData.strength > 0.7)) {
            // Check if at least one function is accessible to attacker
            if (isFunctionAccessibleByAttacker(funcA) || isFunctionAccessibleByAttacker(funcB)) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * findUnverifiedAssumptions - Find assumptions without verifiers from Sync Analyzer
 * @param {object} sync - Sync Analyzer data
 * @returns {Array} - List of unverified assumptions
 */
function findUnverifiedAssumptions(sync) {
    if (!sync?.assumptionDependencyGraph) return [];
    
    const { producers, consumers, verifiers } = sync.assumptionDependencyGraph;
    const verifiedIds = new Set((verifiers || []).map(v => v.assumptionId));
    
    // Find assumptions that have consumers but NO verifiers
    const unverified = (consumers || []).filter(consumer => {
        const hasVerifier = verifiedIds.has(consumer.assumptionId);
        const hasProducer = (producers || []).some(p => p.assumptionId === consumer.assumptionId);
        
        // Return only if it's produced and consumed but never verified
        return hasProducer && !hasVerifier;
    });
    
    return unverified;
}

// Internal helpers used above

/**
 * isFunctionAccessibleByAttacker - Quick check if function can be called by external attacker
 * Note: This is a simplified check - full version would use context.entryPoints
 */
function isFunctionAccessibleByAttacker(funcName) {
    // In production, this would check entryPoints array
    // For now, assume public/external functions are accessible
    // This should be overridden by the actual implementation using Trackator data
    return true;  // Conservative default for scoring bonus
}
```

## Output Format

```javascript
{
    plugin: 'pattern-matcher',
    hypothesisId: string,
    alertId: string,
    v2Enhanced: boolean,  // Whether enhanced scoring was used

    matches: [
        {
            patternSlug: string,
            primaryBugClass: string,
            representativeLoss: number,  // USD
            incidentCount: number,
            matchScore: number,  // 0-1 (may exceed 1.0 with v2 bonuses, capped)

            patternDetails: {
                rootCause: string,
                preconditionChain: string[],
                attackPattern: string[],
                detectionHeuristic: {
                    signature: string,
                    grepPatterns: string[],
                    checklist: string[]
                },
                variants: [{ name: string, codeSketch: string }],
                antiExamples: string[]
            },

            trackatorAlignment: {
                matchingFields: string[],
                satisfiedPreconditions: string[],
                unsatisfiedPreconditions: string[],
                unknownPreconditions: string[]
            },

            // v2.0: Enhanced alignment data from Trackator phases
            v2Alignment: {
                storageEvidence: {
                    targetsValueBearing: boolean,
                    hasPermissionlessWriter: boolean,
                    isContendedVariable: boolean,
                    sharedStateRiskScore: number
                },
                couplingEvidence: {
                    exploitsAtomicityViolation: boolean,
                    couplingStrength: 'STRONG' | 'MEDIUM' | 'WEAK' | 'NONE',
                    hiddenCouplingType: string | null,
                    invariantImpact: string
                },
                syncEvidence: {
                    desyncRiskType: string | null,
                    desyncSeverity: string | null,
                    staleWindowMs: number | null,
                    hasUnverifiedAssumption: boolean
                },
                preClassification: {
                    evidenceClass: string | null,
                    confidenceAdjustment: number  // + or -
                }
            }
        }
    ],

    bestMatch: {
        slug: string,
        score: number,
        confidence: 'high' | 'medium' | 'low',
        v2BonusBreakdown?: {  // Present when v2Enhanced=true
            storageBonus: number,
            couplingBonus: number,
            syncBonus: number,
            preClassificationAdjustment: number
        }
    },

    recommendation: 'proceed_to_reachability' | 'weak_match_save_as_lead'
}
```

## Example: Reentrancy Pattern Match

### Input Alert (from Trackator)

```json
{
    "id": "ALERT_1",
    "name": "CEI Pattern Violation - Potential Reentrancy",
    "category": "reentrancy",
    "condition": {
        "type": "pattern",
        "field": "ceiPattern",
        "operator": "eq",
        "value": "violated"
    },
    "severity": "critical"
}
```

### Matching Card: `reentrancy-state-update-after-external-call.md`

**Card Key Data**:
- Primary bug class: `reentrancy`
- Representative loss: `$4,750,000`
- Incident count: 49+
- Protocol types: `Dexes, Lending, Leveraged Farming, NFT, Staking, Yield Aggregators`

**Detection Heuristic Signature**:
> A function performs `.call{value: x}("")`, `.transfer()`, ERC20 transfer to externally-supplied address, and ONLY AFTER writes to balance/debt/share storage. Function lacks `nonReentrant` modifier.

**Precondition Chain**:
1. State-mutating function performs external call before state update
2. No reentrancy guard (or wrong scope)
3. External call target attacker-controlled
4. Re-entry reads stale state

### Match Result

```javascript
{
    patternSlug: 'reentrancy-state-update-after-external-call',
    primaryBugClass: 'reentrancy',
    representativeLoss: 4750000,
    matchScore: 0.92,  // HIGH match!
    
    trackatorAlignment: {
        matchingFields: ['ceiPattern=violated', 'category=reentrancy', 'severity=critical'],
        satisfiedPreconditions: [
            'External call exists (hasExternalCall=true)',
            'CEI pattern violated confirms state update after external call'
        ],
        unsatisfiedPreconditions: [],
        unknownPreconditions: [
            'Is external call target attacker-controlled? (need manual check)',
            'Can re-entry actually read stale state? (trace required)'
        ]
    },
    
    recommendation: 'proceed_to_reachability'
}
```

## Integration with Reachability Plugin

After pattern matching completes, results flow to **Reachability Plugin** which:

1. Takes precondition chain from matched pattern
2. Checks each precondition against Trackator data
3. Determines if attack is feasible
4. Applies BLOCK GATE (save, don't kill)

See: `plugins/reachability.md`

---

## Top Patterns by Historical Impact

| Rank | Pattern Slug | Total Loss | Incidents | Primary Target |
|------|-------------|-----------|-----------|----------------|
| 1 | bridge-message-trusted-root-bypass | $152M | 1 | Bridges |
| 2 | stableswap-virtual-balance-invariant-drift | $129M | 2 | Dexes/Algo-Stables |
| 3 | self-liquidation-via-collateral-donation | $197M | 2 | Lending |
| 4 | vyper-compiler-reentrancy-lock-failure | $41M | 2 | Algo-Stables/Dexes |
| 5 | repeated-reward-claim-no-state-reset | $20M | 5 | Staking/Yield |
| 6 | hook-callback-settlement-manipulation-via-poolmanager-unlock | $12M | 1 | Derivatives/Dexes |
| 7 | first-depositor-share-price-inflation | $15.8M | 22 | Lending/Staking |
| 8 | missing-modifier-privileged-function | $4.9M | 10 | Multiple |
| 9 | reentrancy-state-update-after-external-call | $4.75M | 49 | Multiple |
| 10 | read-only-reentrancy-oracle-price-during-callback | $3.25M | 6 | Lending/Dexes |

---

## Anti-Patterns (False Positive Prevention)

The library includes **Anti-Examples** for each pattern — safe code patterns that LOOK vulnerable but aren't.

**Use these to avoid false positives:**

```javascript
// When checking reentrancy, verify it's NOT:
const reentrancyAntiPatterns = [
    'Effects-before-interactions ordering',  // State updated BEFORE external call
    'Correctly-scoped nonReentrant guard',     // Guard on right function
    'Pull-payment pattern'                     // Separate withdraw function
];

// If alert matches anti-pattern → downgrade confidence
if (matchesAntiPattern(alert, reentrancyAntiPatterns)) {
    result.matchScore *= 0.5;  // Reduce but don't eliminate
    result.antiPatternFlag = true;
}
```
