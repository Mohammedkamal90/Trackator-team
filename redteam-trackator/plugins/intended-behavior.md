# Plugin: Intended Behavior Plugin

**Phase**: 1 (Intent Filtering)
**Purpose**: Kill false positives early by comparing against intended behavior and design choices
**Type**: Filter plugin (determines keep/discard)

---

## Overview

This plugin determines whether a Trackator alert points at a genuine vulnerability or an intentional design choice / operational pattern.

## Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Hypothesis | Phase 0 output | Alert to evaluate |
| Protocol Context | Phase 0 output | Trackator enrich data |
| Protocol Documentation | External (optional) | Specs, whitepapers, docs |
| **Storage data** | **Trackator Phase 1** | `context.storage` - value-bearing variables, writers |
| **Coupling data** | **Trackator Phase 2** | `context.coupling` - function dependency matrix |
| **Sync data** | **Trackator Phase 3** | `context.sync` - desync risks, assumption graph |
| **Evidence data** | **Trackator Phase 4** | `context.evidence` - classification registry |

## Decision Matrix

### Primary Checks

#### Check 1: Trust Assumption Violation

```javascript
function checkTrustAssumption(alert, trustAssumptions) {
    for (const ta of trustAssumptions) {
        if (alertMatchesAssumption(alert, ta)) {
            return {
                isMatch: true,
                assumption: ta,
                recommendation: ta.confidence === 'low' 
                    ? 'KEEP'  // Low confidence = attack surface
                    : 'DOWNGRADE'  // Known assumption
            };
        }
    }
    return { isMatch: false };
}
```

**Trackator field mapping**: `trustAssumptions[].category` vs `alert.category`

| Alert Category | Matches Trust Assumption | Action |
|---------------|------------------------|---------|
| oracle-manipulation | TA_1 (oracle) | Check confidence |
| access-control | TA_2 (external-contract) | Check confidence |
| governance | TA_3 (governance) | Usually DOWNGRADE |
| price-manipulation | TA_L1 (price-feed) | Check confidence |

#### Check 2: Component Responsibility

```javascript
function checkComponentResponsibility(alert, components) {
    const component = findComponentForField(alert.field, components);
    
    if (!component) return { isMatch: false };
    
    // Does component's responsibility explain this alert?
    if (alert.description.includes(component.responsibility) ||
        alert.field in component.stateOwned) {
        
        // Is the function working as designed?
        const func = findFunctionByField(alert.field, component.interfaces);
        if (func && func.accessControl !== 'None') {
            return {
                isMatch: true,
                type: 'working_as_designed',
                component: component.name,
                recommendation: 'DISCARD'
            };
        }
    }
    
    return { isMatch: false };
}
```

**Trackator field mapping**: 
- `components[].responsibility` — what component does
- `components[].interfaces[].accessControl` — how it's protected
- `components[].stateOwned[]` — what state it owns

#### Check 3: Operational Error Detection

```javascript
function checkOperationalError(alert, context) {
    // Get function associated with alert
    const func = findFunctionForAlert(alert, context.contracts);
    if (!func) return { isOperationalError: false };
    
    // Has role-based access control?
    const hasRoleModifier = func.modifiers?.some(m => 
        m.includes('onlyRole') || 
        m.includes('onlyOwner') || 
        m.includes('require')
    );
    
    if (!hasRoleModifier) {
        // No access control on state-changing function → BUG, not operational
        return { isOperationalError: false };
    }
    
    // Check what the alert is about
    if (alert.aboutParameterChange && hasRoleModifier) {
        // "Admin set bad parameter" → Operational
        return {
            isOperationalError: true,
            type: 'privileged_configuration',
            recommendation: 'DISCARD',
            reason: `Function ${func.name} has ${func.modifiers.join(',')} - trusted role action`
        };
    }
    
    if (alert.aboutMissingGuard && hasRoleModifier) {
        // Missing guard but has auth → might still be bug
        return { isOperationalError: false };  // Let other checks decide
    }
    
    return { isOperationalError: false };
}
```

**Operational error indicators**:
- Alert describes parameter value change by privileged function
- Alert assumes trusted role will act maliciously
- Alert complains about configuration choices
- Alert requires "admin key compromise" or similar

#### Check 4: Exploitable Design Choice

```javascript
function checkExploitableDesignChoice(alert, context) {
    // Even if "intended", can attacker exploit it?
    
    // Check 1: Does it enable downstream attacks?
    const enablesAttacks = enablesAttackChain(alert, context.attackVectors);
    
    // Check 2: Is there a public path to exploit it?
    const publicPath = hasPublicExploitPath(alert, context.entryPoints);
    
    // Check 3: Does Trackator show it's reachable?
    const reachable = isReachableByExternalActor(alert, context);
    
    if (enablesAttacks && (publicPath || reachable)) {
        return {
            isExploitable: true,
            recommendation: 'KEEP_WITH_NOTE',
            note: 'Design choice but exploitable by external actor'
        };
    }
    
    return { isExploitable: false };
}
```

#### Check 5: Storage Invariant Validation (v2.0 NEW)

```javascript
function checkStorageInvariant(alert, context) {
    // v2.0: Use Storage Dependency Analyzer data to validate storage-related alerts

    if (!context.storage?.valueBearingVariables) {
        return { isMatch: false, reason: 'No storage data available' };
    }

    const targetVar = extractTargetVariable(alert);
    if (!targetVar) {
        return { isMatch: false, reason: 'No target variable in alert' };
    }

    // 5a: Is this a value-bearing variable with proper access control?
    const isValueBearing = context.storage.valueBearingVariables.some(
        vbv => vbv.variable === targetVar
    );

    if (isValueBearing) {
        const writers = context.storage.variableWriters.get(targetVar) || [];
        const hasPermissionless = writers.some(w =>
            w.accessControlLevel === 'none' || w.accessControlLevel === 'permissionless'
        );

        if (hasPermissionless) {
            // Value-bearing variable with permissionless writer = KEEP (real vulnerability)
            return {
                isMatch: true,
                type: 'storage_vulnerability',
                recommendation: 'KEEP',
                reason: `${targetVar} holds user funds AND has permissionless writers`,
                severity: 'critical',
                trackatorEvidence: {
                    fieldsUsed: ['storage.valueBearingVariables', 'storage.variableWriters'],
                    writerCount: writers.length,
                    permissionlessCount: writers.filter(w =>
                        w.accessControlLevel === 'none' || w.accessControlLevel === 'permissionless'
                    ).length
                }
            };
        }
    }

    // 5b: Is this a contended variable (potential race condition)?
    const contendedVar = context.storage.contentedVariables?.find(
        cv => cv.variable === targetVar && cv.writerCount >= 2
    );

    if (contendedVar) {
        return {
            isMatch: true,
            type: 'race_condition_candidate',
            recommendation: 'KEEP',
            reason: `${targetVar} has ${contendedVar.writerCount} writers - race condition risk`,
            severity: 'high',
            trackatorEvidence: {
                fieldsUsed: ['storage.contentedVariables'],
                writerCount: contendedVar.writerCount,
                writers: contendedVar.writers
            }
        };
    }

    // 5c: Does this variable appear in shared-state matrix with high risk?
    const sharedStateEntry = context.storage.sharedStateMatrix?.find(
        s => s.sharedVariables.includes(targetVar) && s.riskScore > 0.7
    );

    if (sharedStateEntry) {
        return {
            isMatch: true,
            type: 'shared_state_risk',
            recommendation: 'KEEP_WITH_NOTE',
            reason: `${targetVar} in shared state matrix with risk score ${sharedStateEntry.riskScore}`,
            severity: 'medium',
            trackatorEvidence: {
                fieldsUsed: ['storage.sharedStateMatrix'],
                entryPoint: sharedStateEntry.entryPoint,
                hasValueBearing: sharedStateEntry.hasValueBearing
            }
        };
    }

    return { isMatch: false };
}
```

**Storage validation rules**:
| Alert Target | Has Permissionless Writer | Is Contended | Action |
|--------------|--------------------------|--------------|--------|
| Value-bearing | Yes | - | **KEEP** (critical) |
| Any variable | - | ≥2 writers | **KEEP** (high) |
| In shared-state | - | - | **KEEP_WITH_NOTE** (medium) |
| Other | No | No | Continue to next check |

#### Check 6: Cross-Contract Coupling Safety (v2.0 NEW)

```javascript
function checkCouplingSafety(alert, context) {
    // v2.0: Use State Coupling Detector to identify atomicity violations

    if (!context.coupling?.functionDependencyMatrix) {
        return { isMatch: false, reason: 'No coupling data available' };
    }

    const involvedFunctions = extractInvolvedFunctionsFromAlert(alert);
    if (involvedFunctions.length < 2) {
        return { isMatch: false, reason: 'Alert involves single function' };
    }

    // 6a: Check for strong coupling between attacker-accessible functions
    for (let i = 0; i < involvedFunctions.length - 1; i++) {
        const funcA = involvedFunctions[i];
        const funcB = involvedFunctions[i + 1];
        const pairKey = `${funcA}->${funcB}`;

        const coupling = context.coupling.functionDependencyMatrix[pairKey];

        if (coupling && (coupling.strength === 'STRONG' || coupling.strength > 0.7)) {
            // Both functions accessible to attacker?
            const funcAAccessible = isFunctionAccessible(funcA, context);
            const funcBAccessible = isFunctionAccessible(funcB, context);

            if (funcAAccessible && funcBAccessible) {
                return {
                    isMatch: true,
                    type: 'atomicity_violation',
                    recommendation: 'KEEP',
                    reason: `Strong coupling (${pairKey}) exploitable by external actor`,
                    severity: 'high',
                    trackatorEvidence: {
                        fieldsUsed: ['coupling.functionDependencyMatrix'],
                        couplingStrength: coupling.strength,
                        sharedVariables: coupling.sharedVariables || [],
                        couplingType: coupling.couplingType
                    }
                };
            }
        }
    }

    // 6b: Check for hidden couplings that match this alert pattern
    const matchingHiddenCoupling = (context.coupling.hiddenCouplings || []).find(hc =>
        involvedFunctions.includes(hc.functionA) &&
        involvedFunctions.includes(hc.functionB)
    );

    if (matchingHiddenCoupling) {
        const exploitability =
            matchingHiddenCoupling.couplingType === 'timestamp-dependent' ? 'HIGH - MEV viable' :
            matchingHiddenCoupling.couplingType === 'transient' ? 'MEDIUM - race condition' : 'LOW';

        return {
            isMatch: true,
            type: 'hidden_coupling_exploit',
            recommendation: exploitability.includes('HIGH') ? 'KEEP' : 'KEEP_WITH_NOTE',
            reason: `Hidden ${matchingHiddenCoupling.couplingType} coupling detected`,
            severity: exploitability.includes('HIGH') ? 'high' : 'medium',
            trackatorEvidence: {
                fieldsUsed: ['coupling.hiddenCouplings'],
                couplingType: matchingHiddenCoupling.couplingType,
                strength: matchingHiddenCoupling.strength,
                exploitationPotential: exploitability
            }
        };
    }

    // 6c: Check invariant function map - does this break invariants?
    const impactedInvariants = findImpactedInvariants(involvedFunctions, context.coupling);
    if (impactedInvariants.length > 0) {
        return {
            isMatch: true,
            type: 'invariant_violation_risk',
            recommendation: 'KEEP',
            reason: `May violate invariants: ${impactedInvariants.join(', ')}`,
            severity: 'high',
            trackatorEvidence: {
                fieldsUsed: ['coupling.invariantFunctionMap'],
                impactedInvariants
            }
        };
    }

    return { isMatch: false };
}
```

#### Check 7: Sync State Consistency (v2.0 NEW)

```javascript
function checkSyncConsistency(alert, context) {
    // v2.0: Use Sync Analyzer to detect timing/state desync vulnerabilities

    if (!context.sync?.criticalDesyncRisks) {
        return { isMatch: false, reason: 'No sync data available' };
    }

    const alertCategory = alert.category?.toLowerCase() || '';
    const alertFunction = extractTargetFunction(alert);

    // 7a: Check for critical/high desync risks related to this alert
    const relevantDesyncRisks = context.sync.criticalDesyncRisks.filter(risk => {
        // Match by category or function
        const categoryMatch =
            (risk.riskType === 'stale-price' && alertCategory.includes('oracle')) ||
            (risk.riskType === 'stale-price' && alertCategory.includes('price')) ||
            (risk.riskType === 'stale-approval' && alertCategory.includes('access')) ||
            (risk.riskType === 'state-drift' && alertCategory.includes('state')) ||
            (risk.riskType === 'missing-verifier') ||
            (risk.riskType === 'race-window' && alertCategory.includes('reentrancy'));

        const functionMatch =
            alertFunction && (risk.producerFunction === alertFunction ||
                             risk.consumerFunction === alertFunction);

        return categoryMatch || functionMatch;
    });

    if (relevantDesyncRisks.some(r => r.severity === 'critical')) {
        const criticalRisk = relevantDesyncRisks.find(r => r.severity === 'critical');
        return {
            isMatch: true,
            type: 'critical_desync_vulnerability',
            recommendation: 'KEEP',
            reason: `Critical ${criticalRisk.riskType} risk: ${criticalRisk.attackScenario}`,
            severity: 'critical',
            trackatorEvidence: {
                fieldsUsed: ['sync.criticalDesyncRisks'],
                riskType: criticalRisk.riskType,
                staleWindowMs: criticalRisk.staleWindowMs,
                producerFunction: criticalRisk.producerFunction,
                consumerFunction: criticalRisk.consumerFunction
            }
        };
    }

    if (relevantDesyncRisks.some(r => r.severity === 'high')) {
        const highRisk = relevantDesyncRisks.find(r => r.severity === 'high');
        return {
            isMatch: true,
            type: 'high_desync_risk',
            recommendation: 'KEEP',
            reason: `High severity ${highRisk.riskType} risk detected`,
            severity: 'high',
            trackatorEvidence: {
                fieldsUsed: ['sync.criticalDesyncRisks'],
                riskType: highRisk.riskType,
                attackScenario: highRisk.attackScenario
            }
        };
    }

    // 7b: Check assumption dependency graph for unverified assumptions
    if (context.sync?.assumptionDependencyGraph) {
        const { producers, consumers, verifiers } = context.sync.assumptionDependencyGraph;

        // Find unverified assumptions used by the target function
        const unverifiedForThisFunc = (producers || []).filter(prod => {
            const hasVerifier = (verifiers || []).some(v => v.assumptionId === prod.assumptionId);
            const consumedByTarget = (consumers || []).some(
                c => c.assumptionId === prod.assumptionId && c.function === alertFunction
            );
            return !hasVerifier && consumedByTarget;
        });

        if (unverifiedForThisFunc.length > 0) {
            return {
                isMatch: true,
                type: 'unverified_assumption_usage',
                recommendation: 'KEEP',
                reason: `${unverifiedForThisFunc.length} unverified assumptions used by ${alertFunction}`,
                severity: 'medium',
                trackatorEvidence: {
                    fieldsUsed: ['sync.assumptionDependencyGraph'],
                    unverifiedAssumptions: unverifiedForThisFunc.map(u => u.assumptionId),
                    stalenessWindows: unverifiedForThisFunc.map(u => u.stalenessWindow)
                }
            };
        }
    }

    // 7c: Check Evidence Validator pre-classification
    if (context.evidence?.classificationRegistry) {
        const preClass = findPreClassification(alert.id, context.evidence.classificationRegistry);

        if (preClass === 'confirmed-vulnerability') {
            return {
                isMatch: true,
                type: 'pre_validated_finding',
                recommendation: 'KEEP',
                reason: 'Evidence Validator already classified as confirmed vulnerability',
                severity: alert.severity || 'high',
                trackatorEvidence: {
                    fieldsUsed: ['evidence.classificationRegistry'],
                    preClassification: preClass
                }
            };
        }

        if (preClass === 'false-positive') {
            return {
                isMatch: true,
                type: 'pre_disproven',
                recommendation: 'DISCARD',
                reason: 'Evidence Validator already disproved this finding',
                severity: 'low',
                trackatorEvidence: {
                    fieldsUsed: ['evidence.classificationRegistry'],
                    preClassification: preClass
                }
            };
        }
    }

    return { isMatch: false };
}

// --- Helper Function for Check 7c ---

/**
 * findPreClassification - Look up a finding's pre-classification in Evidence Validator's classification registry
 * @param {string} alertId - The alert/finding ID to look up
 * @param {object} registry - The classificationRegistry from context.evidence
 * @returns {string|null} - The pre-classification class, or null if not found
 */
function findPreClassification(alertId, registry) {
    if (!registry || !alertId) return null;
    
    // Search each class for this finding ID
    const classOrder = [
        'confirmedVulnerability',
        'potentialVulnerability', 
        'falsePositive',
        'byDesign',
        'informational',
        'cannotDetermine'
    ];
    
    for (const className of classOrder) {
        const camelCase = className.charAt(0).toLowerCase() + className.slice(1);
        const classArray = registry[className] || registry[camelCase] || registry[className.toLowerCase()];
        
        if (Array.isArray(classArray)) {
            const found = classArray.find(f => 
                f.findingId === alertId || 
                f.id === alertId || 
                f.alertId === alertId
            );
            if (found) {
                // Return kebab-case version to match expected output format
                return className
                    .replace(/([A-Z])/g, '-$1')
                    .toLowerCase()
                    .replace('^-', '');
            }
        }
    }
    
    return null;  // No pre-classification found
}
```

## Output Format

```javascript
{
    plugin: 'intended-behavior',
    hypothesisId: string,
    alertId: string,
    v2Enhanced: boolean,  // Whether v2.0 checks (5-7) were applied

    verdict: 'keep' | 'downgrade_to_info' | 'discard' | 'keep_with_note',

    reasoning: {
        checksPerformed: [
            { check: 'trust_assumption', result: object },
            { check: 'component_responsibility', result: object },
            { check: 'operational_error', result: object },
            { check: 'exploitable_design', result: object }
            // v2.0: Additional checks when enhanced data available
            // { check: 'storage_invariant', result: object },        // Check 5
            // { check: 'coupling_safety', result: object },          // Check 6
            // { check: 'sync_consistency', result: object }          // Check 7
        ],
        primaryReason: string,
        v2ChecksApplied: string[]  // Which v2.0 checks were run
    },

    trackatorEvidence: {
        fieldsReferenced: string[],
        assumptionsChecked: string[],
        // v2.0: Enhanced evidence from Trackator phases
        storageFieldsUsed: string[],
        couplingFieldsUsed: string[],
        syncFieldsUsed: string[],
        evidenceFieldsUsed: string[]
    },

    timestamp: ISODateString
}
```

## Verdict Actions

| Verdict | Meaning | Pipeline Action |
|---------|---------|-----------------|
| `keep` | Genuine anomaly | Proceed to Phase 2 |
| `downgrade_to_info` | Known assumption/low risk | Move to info notes, not findings |
| `discard` | Operational error / design choice | Remove from hypothesis list |
| `keep_with_note` | Intentional but exploitable | Keep with caveat for report |

## Integration Example

**Input Alert**:
```json
{
    "id": "ALERT_1",
    "name": "CEI Pattern Violation - Potential Reentrancy",
    "category": "reentrancy",
    "field": "ceiPattern",
    "severity": "critical"
}
```

**Associated Function from Trackator**:
```json
{
    "name": "transferInRewards",
    "modifiers": ["whenNotPaused", "onlyRole"],
    "body": { "hasExternalCall": true, "ceiPattern": "violated" }
}
```

**Plugin Processing**:

1. **Trust Assumption**: No match (not oracle/governance related)
2. **Component Responsibility**: Function is in StakingRewardsDistributor, responsibility includes "Asset custody" — CEI violation IS relevant
3. **Operational Error**: Has `onlyRole` modifier BUT reentrancy affects STATE even for authorized caller → NOT purely operational
4. **Exploitable Design**: If external call target can be influenced → exploitable

**Output**:
```javascript
{
    verdict: 'keep',
    reasoning: {
        primaryReason: 'CEI violation in privileged function still poses risk if callback target manipulable'
    }
}
```

---

## Edge Cases

### Case: Admin-only function with no external interaction

```javascript
// Alert: Missing access control on setFee()
// Reality: Only admin CAN call it, and it just sets a variable
// Verdict: DISCARD (operational config)
```

### Case: Public function calls external contract

```javascript
// Alert: External call without reentrancy guard
// Reality: Anyone can call, calls untrusted address
// Verdict: KEEP (real vulnerability surface)
```

### Case: Public function but safe pattern

```javascript
// Alert: External call detected
// Reality: Uses pull-payment pattern, state updated before call
// Verdict: DOWNGRADE_TO_INFO (false positive on pattern match)
```
