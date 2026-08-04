# Plugin: Assumption Breaker Plugin

**Phase**: 3 (Creative Attack)
**Purpose**: Systematically test Trackator trust assumptions to find breakable ones that lead to exploitation
**Type**: Generation plugin (creates hypotheses from assumption analysis)

---

## Overview

This plugin takes trust assumptions from Trackator's threat model and tests which ones can be **broken by external attackers** (not by trusted roles being malicious). It generates attack hypotheses based on broken assumptions.

## Philosophy

> *"The protocol assumes X. What if X isn't true? And crucially — can an EXTERNAL attacker make X not true?"*

### CRITICAL DISTINCTION

| Assumption Type | Can External Attacker Break? | Action |
|-----------------|------------------------------|--------|
| Oracle honesty | ✅ YES - Flash loans, sandwich attacks | **TEST IT** |
| Price feed accuracy | ✅ YES - DEX manipulation, MEV | **TEST IT** |
| External contract behavior | ✅ YES - Upgradeable, buggy | **TEST IT** |
| Market liquidity | ✅ YES - Flash loans exist | **TEST IT** |
| Timing/freshness | ✅ YES - Block timestamp manipulation, MEV | **TEST IT** |
| Storage consistency | ✅ YES - Race conditions, reentrancy (v2.0) | **TEST IT** |
| Coupling safety | ✅ YES - Atomicity violations (v2.0) | **TEST IT** |
| Sync integrity | ✅ YES - Stale data exploitation (v2.0) | **TEST IT** |
| Governance integrity | ❌ NO - Trusted role | **SKIP** |
| Admin key safety | ❌ NO - Operational security | **SKIP** |
| Keeper behavior | ❌ NO - Trusted role | **SKIP** |
| Operational config | ❌ NO - Trusted role decision | **SKIP** |

---

## Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Trust assumptions | `context.trustAssumptions` | From Trackator threat model |
| Alert rules | `context.alertRules` | Related alerts for evidence |
| Assets at risk | `context.assetsAtRisk` | What's at stake if assumption breaks |
| Money flows | `context.moneyFlows` | Which flows depend on each assumption |
| Entry points | `context.entryPoints` | Attack surface for exploitation |
| **Storage data** | **Trackator Phase 1** | `context.storage` - value-bearing variables, writers, contended vars |
| **Coupling data** | **Trackator Phase 2** | `context.coupling` - function dependency matrix, hidden couplings |
| **Sync data** | **Trackator Phase 3** | `context.sync` - critical desync risks, assumption graph |

---

## Algorithm

### Step 1: Categorize Assumptions

```javascript
function categorizeAssumptions(trustAssumptions) {
    return {
        breakable: [],    // External attacker can influence
        trusted: [],      // Requires insider/governance — SKIP
        unknown: []       // Need analysis to determine
    };
    
    for (const ta of trustAssumptions) {
        const category = BREAKABILITY_MAP[ta.category];
        
        if (category === 'TRUSTED') {
            result.trusted.push(ta);
            continue;
        }
        
        if (category === 'BREAKABLE') {
            // Check confidence level
            if (ta.confidence === 'high') {
                result.breakable.push({ ...ta, difficulty: 'hard' });
            } else {
                result.breakable.push({ ...ta, difficulty: ta.confidence === 'medium' ? 'medium' : 'easy' });
            }
        } else {
            result.unknown.push(ta);
        }
    }
}

const BREAKABILITY_MAP = {
    // Original categories
    'oracle': 'BREAKABLE',
    'price-feed': 'BREAKABLE',
    'external-contract': 'BREAKABLE',
    'liquidity': 'BREAKABLE',
    'timing': 'BREAKABLE',

    // v2.0 NEW: Trackator-enhanced categories
    'storage-consistency': 'BREAKABLE',      // Attacker can desync storage state
    'coupling-safety': 'BREAKABLE',           // Attacker can exploit atomicity violations
    'sync-integrity': 'BREAKABLE',            // Attacker can exploit stale data/timing

    // Trusted roles (NEVER break these)
    'governance': 'TRUSTED',
    'admin': 'TRUSTED',
    'keeper': 'TRUSTED',
    'operational': 'TRUSTED',
    'curator': 'TRUSTED',          // v2.0: Added curator
    'factory-owner': 'TRUSTED'     // v2.0: Added factory owner
};
```

### Step 2: Generate Attack Vectors per Breakable Assumption

#### 2A: Oracle Assumption Breaker

```javascript
function breakOracleAssumption(assumption, context) {
    const attacks = [];
    
    // Get oracle-related alerts as evidence
    const oracleAlerts = context.alertRules?.filter(a =>
        a.category === 'oracle-manipulation' ||
        a.category === 'price-manipulation' ||
        a.name?.includes('Oracle')
    ) || [];
    
    // Find functions that read oracle prices
    const priceReadingFunctions = findPriceReadingFunctions(context.contracts);
    
    // Attack 1: Flash Loan Price Manipulation
    attacks.push({
        id: `AB_ORACLE_${assumption.id}`,
        brokenAssumptionId: assumption.id,
        attackType: 'flash_loan_price_manipulation',
        
        description: `Flash loan to swing ${assumption.assumption.toLowerCase()} beyond protocol threshold`,
        
        prerequisiteChain: [
            'Protocol uses single-source or manipulable oracle',
            'Oracle reads spot price (no TWAP/TWAP too short)',
            'Flash loan size sufficient to move price on source DEX',
            'Price move occurs within same transaction as vulnerable operation',
            'No heartbeat/Deviation check OR threshold too high'
        ],
        
        requiredCapital: estimateFlashLoanCapital(context),
        feasibility: assessFeasibility(priceReadingFunctions, context),
        
        trackatorEvidence: {
            relevantAlerts: oracleAlerts.map(a => a.id),
            vulnerableFunctions: priceReadingFunctions.map(f => `${f.contract}.${f.name}`),
            moneyFlowTargets: context.moneyFlows?.filter(f => 
                f.involvesPriceRead() || f.conditions?.some(c => c.includes('price'))
            ).map(f => f.id) || []
        },
        
        estimatedImpact: estimateOracleAttackImpact(assumption, context)
    });
    
    // Attack 2: Multi-Block Manipulation (if no heartbeat)
    if (!hasHeartbeatCheck(context)) {
        attacks.push({
            id: `AB_ORACLE_MULTI_${assumption.id}`,
            brokenAssumptionId: assumption.id,
            attackType: 'multi_block_manipulation',
            
            description: `Sustained price manipulation across multiple blocks when no heartbeat check exists`,
            
            prerequisiteChain: [
                'No heartbeat/timestamp freshness check on oracle reads',
                'Attacker can sustain position across multiple blocks',
                'Price deviation persists long enough for exploit transaction',
                'No circuit breaker or pause mechanism triggers'
            ],
            
            requiredCapital: 'Sustained position (higher than flash loan)',
            feasibility: 'medium',
            
            trackatorEvidence: {
                relevantAlerts: oracleAlerts.filter(a => a.name?.includes('stale')).map(a => a.id),
                note: 'No heartbeat detected in codebase'
            },
            
            estimatedImpact: 'Medium-High (sustained manipulation more powerful)'
        });
    }
    
    // Attack 3: Oracle Sandwich Attack
    if (hasPublicEntryToPriceDependentFunction(context)) {
        attacks.push({
            id: `AB_ORACLE_SANDWICH_${assumption.id}`,
            brokenAssumptionId: assumption.id,
            attackType: 'sandwich_attack',
            
            description: `Sandwich user transaction that depends on stale/manipulated oracle price`,
            
            prerequisiteChain: [
                'Public function reads oracle price mid-transaction',
                'Attacker can front-run with price-moving transaction',
                'Attacker can back-run to capture profit',
                'User transaction cannot detect manipulation in time'
            ],
            
            requiredCapital: 'Position size matching target transaction',
            feasibility: 'high' if hasMEVAccess(context) else 'medium',
            
            trackatorEvidence: {
                relevantAlerts: oracleAlerts.filter(a => a.severity === 'high').map(a => a.id),
                attackVector: 'MEV/sandwich'
            },
            
            estimatedImpact: 'Medium (profit from victim, scales with victim size)'
        });
    }
    
    return attacks;
}
```

#### 2B: External Contract Assumption Breaker

```javascript
function breakExternalContractAssumption(assumption, context) {
    const attacks = [];
    
    // Find external contract calls
    const externalCalls = findExternalContractCalls(context.contracts);
    
    for (const extCall of externalCalls) {
        // Check if external contract could be malicious/upgraded
        
        // Attack 1: Malicious Upgrade/Reinit
        if (extCall.targetMightBeUpgradeable || extCall.targetHasInitFunction) {
            attacks.push({
                id: `AB_EXT_UPGRADE_${extCall.function}`,
                brokenAssumptionId: assumption.id,
                attackType: 'malicious_upgrade',
                
                description: `External contract ${extCall.target} could be upgraded to malicious implementation before call`,
                
                prerequisiteChain: [
                    `${extCall.target} has proxy pattern or reinitialize function`,
                    `Admin of ${extCall.target} is compromised OR acts maliciously`,
                    'Upgrade happens between approval and execution',
                    'New implementation returns malicious values'
                ],
                
                // NOTE: This requires TRUSTED ROLE compromise → might be operational error
                // But worth flagging if upgrade pattern exists without timelock
                feasibility: extCall.hasTimelock ? 'low' : 'medium',
                
                caveat: extCall.hasTimelock 
                    ? 'Timelock present makes this harder but not impossible' 
                    : 'No timelock on upgrades — higher risk',
                
                trackatorEvidence: {
                    functionWithExternalCall: `${extCall.contract}.${extCall.function}`,
                    targetContract: extCall.target,
                    hasTimelock: extCall.hasTimelock || false
                }
            });
        }
        
        // Attack 2: Return Value Manipulation
        attacks.push({
            id: `AB_EXT_RETURN_${extCall.function}`,
            brokenAssumptionId: assumption.id,
            attackType: 'return_value_manipulation',
            
            description: `External ${extCall.target} could return crafted values to manipulate logic`,
            
            prerequisiteChain: [
                `${extCall.function} uses return value from ${extCall.target} in state-changing logic`,
                'Return value not validated against bounds',
                'Attacker can influence ${extCall.target} behavior (e.g., it\'s a DEX pool they control)'
            ],
            
            requiredCapital: 'Control of target contract or its inputs',
            feasibility: assessExternalControl(extCall, context),
            
            trackatorEvidence: {
                callerFunction: extCall.function,
                returnValueUsedIn: extCall.returnValueUsage || 'unknown',
                validationPresent: extCall.hasReturnValueValidation || false
            }
        });
    }
    
    return attacks;
}
```

#### 2C: Liquidity/Timing Assumption Breaker

```javascript
function breakLiquidityAssumption(assumption, context) {
    const attacks = [];
    
    // Check for flash loan availability
    const flashLoanPools = identifyFlashLoanSources(context);
    
    if (flashLoanPools.length > 0) {
        attacks.push({
            id: `AB_LIQ_FLASH_${assumption.id}`,
            brokenAssumptionId: assumption.id,
            attackType: 'flash_loan_attack',
            
            description: `Use flash loan from ${flashLoanPools[0]} to bypass capital requirements assumption`,
            
            prerequisiteChain: [
                'Flash loan pool has sufficient liquidity',
                'Attack can execute within single transaction (atomic)',
                'Profit exceeds flash loan fee + gas costs',
                'No max loan size limit OR limit is high enough'
            ],
            
            availableSources: flashLoanPools.map(p => ({
                name: p.name,
                estimatedLiquidity: p.estimatedLiquidity,
                fee: p.fee
            })),
            
            requiredCapital: '0 (flash loan, just need gas)',
            feasibility: 'high',  // Flash loans are well-established
            
            trackatorEvidence: {
                flashLoanPoolsAvailable: flashLoanPools.length,
                relevantAlerts: context.alertRules?.filter(a =>
                    a.name?.includes('Flash') || a.category === 'flash-loan'
                ).map(a => a.id) || []
            },
            
            estimatedImpact: 'Varies — enables many other attack types'
        });
    }
    
    // Timing/MEV attacks
    const timingVulnerableFunctions = findTimingVulnerableFunctions(context.contracts);
    
    for (const func of timingVulnerableFunctions) {
        attacks.push({
            id: `AB_TIMING_${func.name.replace(/[^a-zA-Z0-9]/g, '_')}`,
            brokenAssumptionId: assumption.id,
            attackType: 'mev_front_run',
            
            description: `Front-run ${func.name}() to exploit timing-dependent calculation`,
            
            prerequisiteChain: [
                `${func.name}() reads state that changes between mempool and execution`,
                'Attacker can observe pending transaction',
                'Profit from front-running exceeds gas priority fee',
                'No commit-reveal scheme or similar protection'
            ],
            
            requiredCapital: 'Gas for priority bid + position size',
            feasibility: hasProtectedMempool(context) ? 'low' : 'medium-high',
            
            trackatorEvidence: {
                vulnerableFunction: `${func.contract}.${func.name}`,
                timingDependency: func.timingDependency
            }
        });
    }
    
    return attacks;
}
```

#### 2D: Storage Desync Assumption Breaker (v2.0 NEW)

```javascript
function breakStorageConsistencyAssumption(assumption, context) {
    // v2.0: Use Storage Dependency Analyzer data to find storage-based attacks
    const attacks = [];

    if (!context.storage?.valueBearingVariables) {
        return attacks;  // No storage data available
    }

    // Attack Pattern D1: Permissionless Writer Exploitation
    for (const vbv of context.storage.valueBearingVariables) {
        const writers = context.storage.variableWriters.get(vbv.variable) || [];
        const permissionlessWriters = writers.filter(w =>
            w.accessControlLevel === 'none' || w.accessControlLevel === 'permissionless'
        );

        if (permissionlessWriters.length > 0) {
            attacks.push({
                id: `AB_STORAGE_${assumption.id}_${vbv.variable}`,
                brokenAssumptionId: assumption.id,
                attackType: 'storage_desync_permissionless_write',

                description: `Directly modify value-bearing variable ${vbv.variable} via permissionless writer`,

                prerequisiteChain: [
                    `${vbv.variable} holds user funds (${vbv.type})`,
                    `Permissionless writer exists: ${permissionlessWriters[0].function}()`,
                    'Attacker can call permissionless writer directly',
                    'No invariant check after write OR check is bypassable',
                    'Funds can be withdrawn/extracted after state modification'
                ],

                requiredCapital: 'Minimal (direct function call)',
                feasibility: 'high',  // Direct exploitation path

                trackatorEvidence: {
                    fieldsUsed: ['storage.valueBearingVariables', 'storage.variableWriters'],
                    targetVariable: vbv.variable,
                    variableType: vbv.type,
                    vulnerableWriters: permissionlessWriters.map(w => w.function),
                    isContended: context.storage.contentedVariables?.some(
                        cv => cv.variable === vbv.variable
                    )
                },

                estimatedImpact: `Critical - Direct fund theft via ${vbv.variable}`,
                v2Category: 'storage-desync'
            });
        }
    }

    // Attack Pattern D2: Race Condition on Contended Variables
    for (const cv of (context.storage.contentedVariables || [])) {
        if (cv.writerCount >= 2 && cv.writers.some(w =>
            w.accessControlLevel === 'none' || w.accessControlLevel === 'permissionless'
        )) {
            attacks.push({
                id: `AB_RACE_${assumption.id}_${cv.variable}`,
                brokenAssumptionId: assumption.id,
                attackType: 'race_condition_storage_desync',

                description: `Exploit race condition on contended variable ${cv.variable} with ${cv.writerCount} writers`,

                prerequisiteChain: [
                    `${cv.variable} has ${cv.writerCount} concurrent writers`,
                    'At least one writer is accessible to attacker',
                    'State read between writes creates inconsistency',
                    'No mutex/lock or reentrancy guard protects the variable',
                    'Double-spend or duplicate extraction possible'
                ],

                requiredCapital: 'Medium (may need transaction ordering)',
                feasibility: cv.writerCount > 3 ? 'high' : 'medium',

                trackatorEvidence: {
                    fieldsUsed: ['storage.contentedVariables'],
                    targetVariable: cv.variable,
                    writerCount: cv.writerCount,
                    writers: cv.writers
                },

                estimatedImpact: 'High-Critical depending on asset type',
                v2Category: 'storage-desync'
            });
        }
    }

    return attacks;
}
```

#### 2E: Coupling Exploitation Assumption Breaker (v2.0 NEW)

```javascript
function breakCouplingSafetyAssumption(assumption, context) {
    // v2.0: Use State Coupling Detector data to find atomicity violations
    const attacks = [];

    if (!context.coupling?.functionDependencyMatrix) {
        return attacks;  // No coupling data available
    }

    // Attack Pattern E1: Atomicity Violation via Split Calls
    for (const [pairKey, coupling] of Object.entries(context.coupling.functionDependencyMatrix)) {
        if (coupling.strength === 'STRONG' || coupling.strength > 0.7) {
            const [funcA, funcB] = pairKey.split('->');

            const funcAAccessible = isFunctionExternallyAccessible(funcA, context);
            const funcBAccessible = isFunctionExternallyAccessible(funcB, context);

            if (funcAAccessible && funcBAccessible) {
                attacks.push({
                    id: `AB_ATOMICITY_${pairKey.replace('->', '_')}`,
                    brokenAssumptionId: assumption.id,
                    attackType: 'atomicity_violation_split_call',

                    description: `Call ${funcA} and ${funcB} separately to exploit intermediate state between strongly-coupled operations`,

                    prerequisiteChain: [
                        `${funcA}() and ${funcB}() are strongly coupled (strength: ${coupling.strength})`,
                        'Protocol assumes both execute atomically (or in protected sequence)',
                        'Attacker can call each function independently',
                        'Intermediate state between calls is inconsistent/vulnerable',
                        'Second call exploits state left by first call'
                    ],

                    requiredCapital: 'Low (two separate transactions)',
                    feasibility: coupling.strength > 0.9 ? 'very-high' : 'high',

                    trackatorEvidence: {
                        fieldsUsed: ['coupling.functionDependencyMatrix'],
                        functionPair: [funcA, funcB],
                        couplingStrength: coupling.strength,
                        sharedVariables: coupling.sharedVariables || [],
                        couplingType: coupling.couplingType || 'unknown'
                    },

                    estimatedImpact: 'Critical - Bypasses atomicity guarantees',
                    v2Category: 'coupling-exploit'
                });
            }
        }
    }

    // Attack Pattern E2: Hidden Coupling Exploitation
    for (const hc of (context.coupling.hiddenCouplings || [])) {
        const accessible = isFunctionExternallyAccessible(hc.functionA, context) &&
                         isFunctionExternallyAccessible(hc.functionB, context);

        if (accessible) {
            attacks.push({
                id: `AB_HIDDEN_${hc.functionA}_${hc.functionB}`,
                brokenAssumptionId: assumption.id,
                attackType: `hidden_coupling_${hc.couplingType}`,

                description: `Exploit hidden ${hc.couplingType} coupling between ${hc.functionA}() and ${hc.functionB}()`,

                prerequisiteChain: [
                    `Hidden ${hc.couplingType} coupling exists between functions`,
                    'Protocol documentation does not disclose this dependency',
                    `Coupling strength: ${hc.strength}`,
                    'Attacker can trigger both sides of the coupling',
                    `Exploit type: ${hc.couplingType === 'timestamp-dependent' ? 'MEV/timing' : 'state manipulation'}`
                ],

                requiredCapital: hc.couplingType === 'timestamp-dependent' ? 'Medium' : 'Low',
                feasibility: hc.strength === 'STRONG' ? 'high' : 'medium',

                trackatorEvidence: {
                    fieldsUsed: ['coupling.hiddenCouplings'],
                    couplingType: hc.couplingType,
                    strength: hc.strength,
                    sharedVariables: hc.sharedVariables || []
                },

                estimatedImpact: 'High - Undocumented attack vector',
                v2Category: 'coupling-exploit'
            });
        }
    }

    return attacks;
}
```

#### 2F: Sync Integrity Assumption Breaker (v2.0 NEW)

```javascript
function breakSyncIntegrityAssumption(assumption, context) {
    // v2.0: Use Sync Analyzer data to find timing/stale-data attacks
    const attacks = [];

    if (!context.sync?.criticalDesyncRisks) {
        return attacks;
    }

    for (const risk of context.sync.criticalDesyncRisks) {
        if (risk.severity === 'critical' || risk.severity === 'high') {
            const consumerAccessible = isFunctionExternallyAccessible(risk.consumerFunction, context);

            if (consumerAccessible) {
                attacks.push({
                    id: `AB_DESYNC_${risk.riskType}_${risk.consumerFunction}`,
                    brokenAssumptionId: assumption.id,
                    attackType: `desync_${risk.riskType}_exploitation`,

                    description: `Exploit ${risk.severity} ${risk.riskType} risk: ${risk.attackScenario}`,

                    prerequisiteChain: [
                        `${risk.riskType} desync risk (${risk.severity})`,
                        `Stale window: ${risk.staleWindowMs}ms`,
                        `Consumer accessible: ${risk.consumerFunction}()`,
                        'Time gap allows state inconsistency',
                        'Consumer operates on stale data'
                    ],

                    requiredCapital: risk.riskType === 'stale-price' ? 'Medium' : 'Low',
                    feasibility: risk.staleWindowMs > 30000 ? 'high' : 'medium',

                    trackatorEvidence: {
                        fieldsUsed: ['sync.criticalDesyncRisks'],
                        riskType: risk.riskType,
                        severity: risk.severity,
                        staleWindowMs: risk.staleWindowMs
                    },

                    estimatedImpact: `${risk.severity === 'critical' ? 'Critical' : 'High'} - ${risk.impact}`,
                    v2Category: 'sync-integrity'
                });
            }
        }
    }

    return attacks;
}
```

### Step 3: Filter and Score Attacks

```javascript
function scoreAndFilterAttacks(attacks, context) {
    return attacks
        .map(attack => ({
            ...attack,
            score: calculateAttackScore(attack, context)
        }))
        .filter(attack => attack.score >= MINIMUM_SCORE_THRESHOLD)
        .sort((a, b) => b.score - a.score);
}

function calculateAttackScore(attack, context) {
    let score = 0;
    
    // Factor 1: Feasibility (0-30)
    const feasibilityScores = { high: 30, 'medium-high': 25, medium: 20, 'medium-low': 15, low: 10, theoretical: 5 };
    score += feasibilityScores[attack.feasibility] || 10;
    
    // Factor 2: Impact estimation (0-25)
    if (attack.estimatedImpact?.includes('Critical') || attack.estimatedImpact?.includes('$')) score += 25;
    else if (attack.estimatedImpact?.includes('High')) score += 20;
    else if (attack.estimatedImpact?.includes('Medium')) score += 15;
    else score += 10;
    
    // Factor 3: Evidence strength from Trackator (0-25)
    const evidenceCount = attack.trackatorEvidence?.relevantAlerts?.length || 0;
    score += Math.min(25, evidenceCount * 8);  // ~3 alerts = full marks
    
    // Factor 4: Prerequisite specificity (0-20)
    // More specific = more believable = higher score
    const prereqDetail = attack.prerequisiteChain?.length || 0;
    if (prereqDetail >= 5) score += 20;
    else if (prereqDetail >= 3) score += 15;
    else score += prereqDetail * 4;
    
    return Math.min(100, score);
}

const MINIMUM_SCORE_THRESHOLD = 35;  // Below this = probably not worth pursuing
```

---

## Output Format

```javascript
{
    plugin: 'assumption-breaker',
    runTimestamp: ISODateString,
    
    summary: {
        totalAssumptionsAnalyzed: number,
        breakableFound: number,
        skippedTrusted: number,
        attacksGenerated: number,
        byType: {
            // Original types
            oracle_manipulation: number,
            external_contract: number,
            flash_loan: number,
            timing_mev: number,
            // v2.0 NEW: Trackator-enhanced attack types
            storage_desync: number,       // Permissionless writer, race conditions
            coupling_exploit: number,     // Atomicity violations, hidden couplings
            sync_integrity: number        // Stale data, unverified assumptions
        },
        byFeasibility: {
            high: number,
            medium: number,
            low: number,
            theoretical: number
        },
        v2Enhanced: boolean  // Whether Trackator enhanced data was used
    },

    skippedAssumptions: [
        {
            id: string,
            category: string,
            assumption: string,
            reason: 'trusted_role' | 'not_breakable_externally'
        }
    ],

    attacks: [
        {
            id: string,
            brokenAssumptionId: string,
            attackType: string,
            description: string,
            prerequisiteChain: string[],
            requiredCapital: string,
            feasibility: 'high' | 'medium' | 'low' | 'theoretical',
            estimatedImpact: string,
            score: number,
            trackatorEvidence: object,
            v2Category: 'storage-desync' | 'coupling-exploit' | 'sync-integrity' | null,  // v2.0
            caveat: string | null
        }
    ]
}
```

---

## Integration Notes

### Relationship with Reverse Engineering Plugin

| Aspect | Reverse Engineering | Assumption Breaker |
|--------|--------------------|--------------------|
| Starting point | Assets/value flows | Trust assumptions |
| Finds | Code-level bugs | Design-level weaknesses |
| Novelty | High (novel patterns) | Medium (known attack classes) |
| Execution trace | Required | Required |
| Best for | Protocol-specific bugs | Category-common attacks (oracle, flash loan) |

### When to Run

- **Always run in Phase 3** alongside Reverse Engineering
- Run AFTER reverse engineering (RE finds code issues first, AB finds design issues)
- Feed results into same execution trace builder

### Output Consumption

1. Each attack becomes a hypothesis
2. Hypothesis MUST get full execution trace (Rule 1)
3. Traced hypotheses go to Verifier via reachability BLOCK GATE
4. High-scoring attacks prioritized for fuzz testing (Phase 4)

---

## Example: Lending Protocol Oracle Attack

### Input Assumption
```javascript
{
    id: "TA_1",
    category: "oracle",
    assumption: "Oracle prices reflect true market values",
    confidence: "medium"
}
```

### Generated Attack
```javascript
{
    id: "AB_ORACLE_TA_1",
    brokenAssumptionId: "TA_1",
    attackType: "flash_loan_price_manipulation",
    
    description: "Flash loan to manipulate collateral price below threshold, enabling undercollateralized borrowing",
    
    prerequisiteChain: [
        "Protocol uses Uniswap V3 TWAP for collateral valuation",
        "TWAP window is short (≤30 minutes)",
        "Flash loan size sufficient to move TWAP temporarily",
        "Borrow function checks collateral ratio using manipulated price",
        "Liquidation hasn't triggered yet (needs time delay)"
    ],
    
    requiredCapital: "Flash loan $50M+ (depends on pool liquidity)",
    feasibility: "medium",
    
    trackatorEvidence: {
        relevantAlerts: ["ALERT_5", "ALERT_12"],
        vulnerableFunctions: ["PriceOracle.getPrice", "Vault.checkCollateral"],
        moneyFlowTargets: ["borrow_flow", "liquidation_flow"]
    },
    
    estimatedImpact: "Critical — can drain all borrowable funds",
    score: 82
}
```

---

## Anti-Patterns (Avoid These)

❌ "Governance could pass malicious proposal" → **TRUSTED ROLE, SKIP**
❌ "Admin key gets compromised" → **OPERATIONAL SECURITY, SKIP**
❌ "Keeper doesn't liquidate in time" → **HUMAN FACTOR, SKIP**
❌ Attacks requiring >24h preparation (unless realistic sustained manipulation)
❌ Theoretical attacks with no concrete entry point

✅ Only external-attacker-breakable assumptions
✅ Concrete prerequisite chains from Trackator data
✅ Realistic capital/feasibility assessments
✅ Clear connection to assets at risk
