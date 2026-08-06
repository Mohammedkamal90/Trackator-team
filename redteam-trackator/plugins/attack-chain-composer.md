# Plugin: Attack Chain Composer

**Phase**: 2 (Pattern Matching → Chain Composition)
**Purpose**: Compose individual exploit pattern matches into coherent multi-step attack chains with full execution path tracing
**Type**: Composition plugin (links patterns, validates chains, gates escalation)
**Version**: 2.0.0 (NEW - Phase 2 Upgrade)

---

## Overview

This plugin transforms isolated pattern matches from the Pattern Matcher into **coherent attack chains** that reflect how real attackers actually exploit protocols. A single vulnerability is rarely exploited in isolation — real attacks chain multiple weaknesses together:

1. **Flash loan** provides capital → **Price manipulation** moves oracle → **Accounting error** allows extraction
2. **Missing access control** exposes function → **Reentrancy** drains funds mid-execution
3. **Signature bypass** authenticates attacker → **Arbitrary call** transfers ownership

This plugin:
- **Links patterns** into valid attack sequences
- **Validates preconditions** across the entire chain (not just individual patterns)
- **Enforces Execution Path Gate** before any hypothesis can escalate to Phase 3
- **Scores chains** by realism, extractable value, and feasibility

---

## Core Philosophy: "Right Path" > "Fast Path"

> *"A fast false positive wastes everyone's time. A slow true positive saves the protocol."*

### The Execution Path Gate (MANDATORY)

Before ANY attack chain can escalate to Phase 3 (Creative Hacker), it MUST pass all 4 gates:

```javascript
function canEscalateHypothesis(attackChain) {
    const gates = [
        {
            name: 'Precondition Trace',
            check: () => attackChain.preconditions.every(p => 
                p.executionPath !== null && 
                p.executionPath.verified === true
            ),
            failureMessage: 'One or more preconditions lack verified execution paths'
        },
        {
            name: 'State Change Verification',
            check: () => attackChain.stateChanges.every(s => 
                s.source === 'tracked' || 
                s.manuallyVerified === true
            ),
            failureMessage: 'State changes not fully tracked or manually verified'
        },
        {
            name: 'Attacker Control',
            check: () => attackChain.attackerControlledInputs.length > 0 && 
                     attackChain.attackerControlledInputs.every(i => 
                         i.traceable === true
                     ),
            failureMessage: 'Attacker-controlled inputs not fully traceable'
        },
        {
            name: 'No Conflicting Assumptions',
            check: () => !hasConflictingAssumptions(attackChain),
            failureMessage: 'Chain contains internally conflicting assumptions'
        }
    ];
    
    const results = gates.map(gate => ({
        name: gate.name,
        passed: gate.check(),
        ...(gate.check() ? {} : { reason: gate.failureMessage })
    }));
    
    const allPassed = results.every(r => r.passed);
    
    return {
        canEscalate: allPassed,
        maxAllowedStatus: allPassed ? 'PROBABLE' : 'LEAD',
        gateResults: results,
        blockedBy: results.filter(r => !r.passed).map(r => r.name)
    };
}
```

---

## Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Pattern matches | Pattern Matcher output | Individual exploit pattern matches with scores |
| Protocol context | Phase 0 output | Protocol type, components, entry points |
| Exploits library | External | `Exploits-class-library/` directory |
| Field map | `exploit-trackator-field-map.json` | Precondition → Trackator JSON path mappings |
| Taxonomy | `attack-type-taxonomy.json` | DeFiHackLabs type mappings |
| **Storage data** | **Trackator Phase 1** | `context.storage` - value-bearing variables, writers |
| **Coupling data** | **Trackator Phase 2** | `context.coupling` - function dependencies, hidden couplings |
| **Sync data** | **Trackator Phase 3** | `context.sync` - desync risks, assumption dependencies |
| **Evidence data** | **Trackator Phase 4** | `context.evidence` - classification registry, confidence |
| **Attacks data** | **Trackator Phase 8** | `context.attacks` - ranked targets, scenarios |

---

## Chain Composition Algorithm

### Step 1: Collect Pattern Matches

Gather all pattern matches from Pattern Matcher that scored above threshold:

```javascript
const PATTERN_MATCH_THRESHOLD = 0.6; // 60% similarity score

function collectViablePatterns(patternMatcherOutput) {
    return patternMatcherOutput.matches
        .filter(m => m.similarityScore >= PATTERN_MATCH_THRESHOLD)
        .sort((a, b) => b.similarityScore - a.similarityScore)
        .map(m => ({
            patternSlug: m.patternSlug,
            bugClass: m.bugClass,
            score: m.similarityScore,
            matchedFeatures: m.matchedFeatures,
            missingPreconditions: m.missingPreconditions,
            location: m.location, // { contract, function, lineRange }
            trackatorEvidence: m.trackatorEvidence
        }));
}
```

### Step 2: Identify Chainable Patterns

Two patterns are **chainable** if:

1. **Output of pattern A enables precondition of pattern B**
2. **Both target same contract or coupled contracts**
3. **Combined execution is feasible in single/multi-tx sequence**

```javascript
function findChainablePairs(patterns, couplingData) {
    const chainablePairs = [];
    
    for (let i = 0; i < patterns.length; i++) {
        for (let j = 0; j < patterns.length; j++) {
            if (i === j) continue;
            
            const patternA = patterns[i]; // First step
            const patternB = patterns[j]; // Second step
            
            // Check if A's state change enables B's precondition
            const linkage = analyzePatternLinkage(patternA, patternB, couplingData);
            
            if (linkage.isChainable) {
                chainablePairs.push({
                    firstStep: patternA,
                    secondStep: patternB,
                    linkageType: linkage.type, // 'state_enablement', 'access_grant', 'timing_window', etc.
                    linkageStrength: linkage.strength, // 0-1
                    sharedState: linkage.sharedState,
                    executionOrder: linkage.executionOrder // 'same_tx', 'sequential_tx', 'conditional'
                });
            }
        }
    }
    
    return chainablePairs.sort((a, b) => b.linkageStrength - a.linkageStrength);
}
```

### Step 3: Analyze Pattern Linkage

Determine HOW two patterns connect:

```javascript
function analyzePatternLinkage(patternA, patternB, couplingData) {
    // Load precondition chains from exploit cards
    const cardA = loadExploitCard(patternA.patternSlug);
    const cardB = loadExploitCard(patternB.patternSlug);
    
    const linkageTypes = [];
    
    // Type 1: State Enablement - A modifies state that B requires
    for (const precondition of cardB.preconditionChain) {
        for (const stateChange of cardA.stateChanges) {
            if (stateChangeEnablesPrecondition(stateChange, precondition)) {
                linkageTypes.push({
                    type: 'state_enablement',
                    fromState: stateChange.variable,
                    toPrecondition: precondition.id,
                    strength: calculateEnablementStrength(stateChange, precondition)
                });
            }
        }
    }
    
    // Type 2: Access Grant - A bypasses control that guards B
    if (patternA.bugClass === 'access-control' || patternA.bugClass === 'signature-replay') {
        const bAccessReq = cardB.preconditionChain.find(p => p.type === 'access');
        if (bAccessReq && patternA.location.contract === patternB.location.contract) {
            linkageTypes.push({
                type: 'access_grant',
                bypassedControl: bAccessReq.description,
                strength: 0.9 // Access grant is usually strong linkage
            });
        }
    }
    
    // Type 3: Timing Window - A creates race condition that B exploits
    if (patternA.bugClass === 'reentrancy' || patternA.bugClass === 'flash-loan-vulnerability') {
        const bTimingReq = cardB.preconditionChain.find(p => p.type === 'timing');
        if (bTimingReq) {
            linkageTypes.push({
                type: 'timing_window',
                windowMs: estimateRaceWindow(patternA),
                strength: 0.7
            });
        }
    }
    
    // Type 4: Economic Feasibility - A provides capital for B
    if (patternA.bugClass === 'flash-loan-vulnerability' || 
        patternA.bugClass === 'accounting-error') {
        const bCapitalReq = cardB.economicContext?.capitalRequired;
        if (bCapitalReq) {
            linkageTypes.push({
                type: 'capital_provision',
                estimatedCapital: bCapitalReq,
                strength: 0.8
            });
        }
    }
    
    // Check coupling data for hidden connections
    const hiddenCoupling = findHiddenCoupling(
        patternA.location.contract + '.' + patternA.location.function,
        patternB.location.contract + '.' + patternB.location.function,
        couplingData
    );
    
    // Return strongest linkage or null if none found
    const bestLinkage = linkageTypes.reduce((best, current) => 
        (current.strength > best.strength) ? current : best, 
        { type: 'none', strength: 0 }
    );
    
    return {
        isChainable: bestLinkage.strength >= 0.5 || hiddenCoupling !== null,
        type: bestLinkage.type,
        strength: Math.max(bestLinkage.strength, hiddenCoupling ? 0.6 : 0),
        sharedState: bestLinkage.fromState || hiddenCoupling?.sharedVariable,
        executionOrder: determineExecutionOrder(bestLinkage.type, hiddenCoupling),
        linkages: linkageTypes,
        hiddenCoupling
    };
}
```

### Step 4: Build Attack Chains

Compose viable pairs into full attack chains:

```javascript
function buildAttackChains(chainablePairs, patterns, context) {
    const chains = [];
    const usedPatterns = new Set();
    
    for (const pair of chainablePairs) {
        if (usedPatterns.has(pair.firstStep.patternSlug) || 
            usedPatterns.has(pair.secondStep.patternSlug)) {
            continue; // Each pattern can only be in one chain (for now)
        }
        
        // Build 2-step chain
        const chain = {
            id: generateChainId(pair),
            steps: [pair.firstStep, pair.secondStep],
            linkage: pair,
            type: classifyChainType(pair),
            preconditions: [],
            stateChanges: [],
            attackerControlledInputs: [],
            assumptions: [],
            executionPath: null,
            feasibility: null,
            extractedValueEstimate: null,
            gateStatus: null
        };
        
        // Merge and validate preconditions
        chain.preconditions = mergePreconditions(
            loadExploitCard(pair.firstStep.patternSlug).preconditionChain,
            loadExploitCard(pair.secondStep.patternSlug).preconditionChain
        );
        
        // Trace state changes through Trackator data
        chain.stateChanges = traceStateChanges(chain, context.storage, context.coupling);
        
        // Identify attacker-controlled inputs
        chain.attackerControlledInputs = identifyAttackerInputs(chain, context.init);
        
        // Extract assumptions from both cards
        chain.assumptions = [
            ...loadExploitCard(pair.firstStep.patternSlug).assumptions || [],
            ...loadExploitCard(pair.secondStep.patternSlug).assumptions || []
        ];
        
        // Estimate extracted value
        chain.extractedValueEstimate = estimateExtractedValue(chain, context.assetsAtRisk);
        
        // Run Execution Path Gate
        chain.gateStatus = canEscalateHypothesis(chain);
        
        if (chain.gateStatus.canEscalate || chain.gateStatus.maxAllowedStatus === 'LEAD') {
            chains.push(chain);
            usedPatterns.add(pair.firstStep.patternSlug);
            usedPatterns.add(pair.secondStep.patternSlug);
        }
    }
    
    // Try to extend 2-step chains into 3-step chains
    return extendChains(chains, patterns, context);
}
```

### Step 5: Trace Full Execution Path

For each chain, trace COMPLETE execution from entry point to final extraction:

```javascript
function traceExecutionPath(chain, context) {
    const executionSteps = [];
    let currentState = { ...context.initialState };
    
    for (let stepIndex = 0; stepIndex < chain.steps.length; stepIndex++) {
        const step = chain.steps[stepIndex];
        const card = loadExploitCard(step.patternSlug);
        
        const stepExecution = {
            stepNumber: stepIndex + 1,
            patternSlug: step.patternSlug,
            action: card.attackPattern[stepIndex] || card.attackPattern[0],
            entryPoint: step.location.function,
            contract: step.location.contract,
            parameters: {},
            externalCalls: [],
            stateDelta: {},
            preconditionsChecked: [],
            postconditions: []
        };
        
        // Map attack pattern steps to executable actions
        for (const attackStep of card.attackPattern) {
            // Find the actual function call
            const functionCall = resolveFunctionCall(attackStep, context.init);
            
            stepExecution.parameters = {
                ...stepExecution.parameters,
                ...extractParameters(attackStep)
            };
            
            if (functionCall.isExternal) {
                stepExecution.externalCalls.push({
                    target: functionCall.target,
                    function: functionCall.name,
                    purpose: attackStep.purpose
                });
            }
            
            // Track state changes using storage.json write graph
            const stateImpact = queryStorageImpact(
                functionCall.contract,
                functionCall.name,
                context.storage
            );
            
            stepExecution.stateDelta = {
                ...stepExecution.stateDelta,
                ...stateImpact
            };
            
            currentState = { ...currentState, ...stateImpact };
        }
        
        // Verify preconditions using field map
        for (const precondition of chain.preconditions) {
            const verification = verifyPreconditionAgainstTrackator(
                precondition,
                context,
                currentState
            );
            
            stepExecution.preconditionsChecked.push({
                preconditionId: precondition.id,
                text: precondition.condition_text,
                verified: verification.verified,
                trackatorSource: verification.source,
                jsonPath: verification.jsonPath,
                currentValue: verification.currentValue
            });
        }
        
        executionSteps.push(stepExecution);
    }
    
    // Final extraction step
    const lastStep = executionSteps[executionSteps.length - 1];
    const extractionStep = {
        stepNumber: executionSteps.length + 1,
        action: 'EXTRACT_VALUE',
        description: 'Drain/extract value enabled by previous steps',
        method: determineExtractionMethod(chain),
        estimatedValue: chain.extractedValueEstimate,
        destination: 'attacker.controlled_address'
    };
    
    return {
        steps: executionSteps,
        extractionStep,
        totalSteps: executionSteps.length + 1,
        requiresSingleTx: chain.type === 'single_tx_flash_loan' || 
                          chain.type === 'reentrancy_chain',
        requiresMultiTx: chain.type === 'multi_tx_manipulation' ||
                         chain.type === 'governance_takeover',
        gasEstimate: estimateGas(executionSteps)
    };
}
```

---

## Known Chain Archetypes

Based on analysis of 904+ DeFiHackLabs incidents, these are the most common attack chain patterns:

### Archetype 1: Flash Loan Price Manipulation Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│ FLASH LOAN → PRICE MANIPULATION → ACCOUNTING DRAIN                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Step 1: Flash Borrow Capital                                        │
│   ├─ Pattern: flash-loan-vulnerability                              │
│   ├─ Action: Borrow $XM from Aave/Balancer/Morpho                   │
│   └─ Enables: Capital for manipulation                              │
│                                                                     │
│ Step 2: Manipulate Price Feed                                       │
│   ├─ Pattern: flash-loan-spot-price-manipulation-single-tx          │
│   │         OR single-oracle-dependency-without-sanity-checks       │
│   ├─ Action: Swap on thin pool to move spot price/tick              │
│   └─ Enables: Skewed collateral valuation                           │
│                                                                     │
│ Step 3: Exploit Accounting Error                                    │
│   ├─ Pattern: accounting-error (share inflation, rounding, etc.)    │
│   ├─ Action: Deposit/ borrow/ mint at manipulated price             │
│   └─ Result: Overvalued position → borrow more → repay flash       │
│                                                                     │
│ Historical examples: Impermax V3 ($300K), Platypus ($2M), LAVA      │
│                                                                     │
│ Detection signature:                                                │
│   - Single TX containing flashLoan + large swap + deposit/borrow    │
│   - Pool reserves/tick moved >50% in one block                      │
│   - Collateral valuation reads slot0/sqrtPriceX96 (no TWAP)        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Prerequisites (ALL must pass Execution Path Gate):**

| # | Precondition | Trackator Verification Path |
|---|--------------|---------------------------|
| 1 | Flash loan callback accessible | `init.json: functions[].body.hasExternalCall == true` AND function name matches `onFlashLoan/executeOperation` |
| 2 | Price source is manipulable | `storage.json: valueBearingVariables[isPriceSource==true].sources.length == 1` |
| 3 | No TWAP/sanity check on price read | `sync.json: criticalRisks[riskType=='stale-price']` exists for consumer function |
| 4 | Accounting uses raw price directly | `coupling.json: hiddenCouplings[]` shows price reader → valuation function without transform |
| 5 | Attacker can withdraw/borrow post-manipulation | `init.json: functions[].access == 'public'` for withdraw/borrow |

### Archetype 2: Reentrancy Drain Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│ REENTRANCY GUARD MISSING → EXTERNAL CALLBACK → STATE DRAIN          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Step 1: Find Vulnerable Function                                   │
│   ├─ Pattern: reentrancy-state-update-after-external-call           │
│   │         OR read-only-reentrancy-oracle-price-during-callback    │
│   ├─ Function has external call BEFORE state update                 │
│   └─ Missing nonReentrant modifier                                  │
│                                                                     │
│ Step 2: Prepare Callback Target                                     │
│   ├─ Pattern: attacker-deployed-token-impersonation                │
│   │         OR unrestricted-system-callback-function               │
│   ├─ Deploy malicious contract with fallback/receive/hooks          │
│   └─ Ensure callback re-enters vulnerable function                  │
│                                                                     │
│ Step 3: Execute Reentrant Call Sequence                             │
│   ├─ Initial call triggers external transfer                        │
│   ├─ Callback re-enters before state update                         │
│   ├─ Balance/allowance not yet decremented                          │
│   └─ Repeat until drained or gas limit                              │
│                                                                     │
│ Historical examples: DAO ($150M), Cream Finance ($18.5M), Rari      │
│                                                                     │
│ Detection signature:                                                │
│   - Same address appears N times in call stack within one TX        │
│   - Same function called recursively (depth > 1)                    │
│   - Balance decreases ONLY after full recursion completes           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Archetype 3: Access Control Takeover Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│ ACCESS CONTROL MISSING → PRIVILEGE ESCALATION → PROTOCOL DRAIN      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Step 1: Bypass Authentication                                      │
│   ├─ Pattern: signature-validation-flaw                            │
│   │         OR zero-signature-accepted-for-delegated-approval       │
│   │         OR caller-controlled-eip1271-signer-bypasses-auth      │
│   ├─ Craft signature that passes flawed validation                  │
│   └─ Gain unauthorized access to privileged function                │
│                                                                     │
│ Step 2: Escalate Privileges                                        │
│   ├─ Pattern: missing-modifier-privileged-function                 │
│   │         OR ownership-takeover-via-covert-transfer              │
│   ├─ Call admin/governance/owner function                           │
│   └─ Transfer ownership, set parameters, enable drain path          │
│                                                                     │
│ Step 3: Drain Protocol                                             │
│   ├─ Pattern: arbitrary-call OR accounting-error                    │
│   ├─ Use escalated privileges to extract value                     │
│   └─ Withdraw, mint, pause, or redirect funds                       │
│                                                                     │
│ Historical examples: Pickle Finance ($20M), MonoX Finance ($31M)    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Archetype 4: Oracle/Governance Manipulation Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│ ORACLE CONTROL → PARAMETER MANIPULATION → VALUE EXTRACTION          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Step 1: Compromise or Manipulate Oracle                             │
│   ├─ Pattern: single-oracle-dependency-without-sanity-checks       │
│   │         OR governance-proposal-executed-without-timelock-delay  │
│   ├─ Propose malicious price update / governance action             │
│   └─ Execute without proper delay/validation                        │
│                                                                     │
│ Step 2: Protocol Acts on Bad Data                                  │
│   ├─ Pattern: price-manipulation OR business-logic-flaw            │
│   ├─ Protocol uses manipulated value for critical calculation       │
│   └─ Health factors, interest rates, or exchange ratios skewed      │
│                                                                     │
│ Step 3: Profit from Skewed State                                   │
│   ├─ Pattern: liquidation-incentive-miscalculation                 │
│   │         OR reward-accounting-error                             │
│   ├─ Cheap liquidations, inflated rewards, or arbitrage             │
│   └── Extract spread between real and protocol-perceived value      │
│                                                                     │
│ Historical examples: Mango Markets ($114M), MND ($1.8M)             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Archetype 5: Cross-Contract Coupling Exploitation

```
┌─────────────────────────────────────────────────────────────────────┐
│ HIDDEN COUPLING → ATOMICITY VIOLATION → STATE DESYNC               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Step 1: Identify Hidden Coupling (from Trackator)                  │
│   ├─ Source: coupling.json → hiddenCouplings[]                     │
│   ├─ Two+ functions share state without coordination               │
│   └─ Both accessible to attacker (or one enables the other)         │
│                                                                     │
│ Step 2: Break Atomicity Assumption                                 │
│   ├─ Pattern: timing-sensitive-operation-no-lock                   │
│   │         OR amm-reserve-skim-sync-manipulation                  │
│   ├─ Call function A to set favorable state                        │
│   └─ Call function B before A's effects propagate/validate         │
│                                                                     │
│ Step 3: Exploit Inconsistent State                                 │
│   ├─ Pattern: stableswap-virtual-balance-invariant-drift           │
│   │         OR reflection-token-rate-desync                        │
│   ├─ Protocol acts on stale/inconsistent data                      │
│   └─ Profit from divergence between perceived and actual state     │
│                                                                     │
│ Detection signature:                                                │
│   - coupling.json shows stronglyCoupledPairs with bothAccessible   │
│   - sync.json shows atRiskGroups with assumptionDependency         │
│   - Two TXs in close temporal proximity touching coupled state     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Output Format

### Attack Chain Object

```javascript
{
    // Metadata
    id: "CHAIN_001",
    archetype: "flash_loan_price_manipulation", // From known archetypes above
    createdAt: "2026-08-06T...",
    composerVersion: "2.0.0",
    
    // Composition
    steps: [
        {
            stepNumber: 1,
            patternSlug: "flash-loan-spot-price-manipulation-single-tx",
            patternName: "Flash Loan Spot Price Manipulation",
            bugClass: "price-manipulation",
            similarityScore: 0.87,
            location: {
                contract: "LendingPool",
                function: "depositCollateral",
                sourceFile: "src/LendingPool.sol",
                lineRange: [142, 189]
            },
            action: "Flash borrow, swap on pool to manipulate price, then deposit",
            preconditions: [
                {
                    id: "pre_1_1",
                    condition_text: "Flash loan callback accessible to attacker",
                    verified: true,
                    executionPath: {
                        traced: true,
                        path: "attacker → executeOperation() → pool.swap() → deposit()",
                        trackatorSource: "trackator-init.json",
                        jsonPath: "contracts[LendingPool].functions[executeOperation]",
                        evidence: "Function is public, hasExternalCall=true"
                    }
                }
                // ... more preconditions
            ],
            stateChanges: [
                {
                    variable: "pool.reserves.tokenA",
                    type: "manipulated",
                    direction: "decreased",
                    magnitude: "~40%",
                    source: "trackator-storage.json"
                }
            ],
            attackerControlledInputs: [
                {
                    parameter: "amount",
                    type: "uint256",
                    controlled: true,
                    traceable: true,
                    source: "attacker.supplied"
                }
            ]
        }
        // ... step 2, step 3
    ],
    
    // Linkage Analysis
    linkage: {
        type: "state_enablement", // How steps connect
        strength: 0.85, // 0-1 confidence in chain validity
        sharedState: ["pool.reserves.tokenA", "collateralValues[msg.sender]"],
        executionOrder: "same_tx", // same_tx | sequential_tx | conditional
        rationale: "Step 1's price manipulation enables Step 3's inflated collateral valuation"
    },
    
    // Aggregated Preconditions (merged from all steps)
    preconditions: [...], // All preconditions merged and deduplicated
    stateChanges: [...], // All state changes in execution order
    attackerControlledInputs: [...], // All attacker-controlled parameters
    assumptions: [...], // All assumptions that must hold
    
    // Execution Trace (COMPLETE - required for gate)
    executionPath: {
        traced: true,
        steps: [...], // Detailed step-by-step execution
        extractionStep: {...}, // Final value extraction
        totalSteps: 4,
        requiresSingleTx: true,
        gasEstimate: "850000-1200000"
    },
    
    // Feasibility Assessment
    feasibility: {
        technicalFeasibility: "high", // high | medium | low | theoretical
        economicFeasibility: "high",
        requiredCapital: "Flash loan $5-10M",
        estimatedProfit: "$300K-2M",
        profitToCostRatio: "30-200x",
        timeWindow: "Single transaction (atomic)",
        complexity: "medium" // easy | medium | hard | expert
    },
    
    // Execution Path Gate Status (MANDATORY)
    gateStatus: {
        canEscalate: true, // If false, CANNOT proceed to Phase 3
        maxAllowedStatus: "PROBABLE", // Status ceiling even if can't escalate
        gateResults: [
            { name: "Precondition Trace", passed: true },
            { name: "State Change Verification", passed: true },
            { name: "Attacker Control", passed: true },
            { name: "No Conflicting Assumptions", passed: true }
        ],
        blockedBy: [], // Empty if all passed
        checkedAt: "2026-08-06T..."
    },
    
    // Historical Context
    historicalMatches: [
        {
            protocol: "Impermax V3",
            date: "2025-04-26",
            loss: "$300K",
            similarity: "92%",
            source: "DeFiHackLabs"
        }
        // ... similar incidents
    ],
    
    // Trackator Evidence Summary
    trackatorEvidence: {
        initJson: ["contracts[].functions[] (entry points, modifiers)"],
        storageJson: ["valueBearingVariables[] (targets)", "contendedVars[] (race conditions)"],
        couplingJson: ["hiddenCouplings[] (chain links)", "stronglyCoupledPairs[]"],
        syncJson: ["atRiskGroups[] (timing)", "criticalRisks[] (desync)"],
        evidenceJson: ["classificationRegistry[] (bug classes)"],
        attacksJson: ["criticalAttackScenarios[] (similar patterns)"]
    }
}
```

---

## Integration with Existing Pipeline

### Where This Plugin Fits

```
PHASE 2 PIPELINE (Enhanced):
                    
    ┌──────────────────┐
    │  Pattern Matcher  │ ← Existing plugin (finds individual matches)
    │  (patterns.md)    │
    └────────┬─────────┘
             │ patternMatches[]
             ▼
    ┌──────────────────┐
    │ Attack Chain     │ ← NEW: This plugin (composes matches into chains)
    │ Composer          │
    │ (this file)       │
    └────────┬─────────┘
             │ attackChains[]
             ▼
    ┌──────────────────┐
    │ Execution Path   │ ← Built into this plugin (mandatory gate)
    │ Gate Validation  │
    └────────┬─────────┘
             │ gatedChains[] (only passing chains)
             ▼
         PHASE 3: Creative Hacker Agent
         (receives validated chains only)
```

### Interaction with Pattern Matcher

The Attack Chain Composer **consumes** Pattern Matcher output:

```javascript
// Pattern Matcher outputs this format:
const patternMatcherOutput = {
    summary: {
        totalPatternsChecked: 65,
        matchesFound: 12,
        highConfidenceMatches: 5 // score >= 0.8
    },
    matches: [
        {
            patternSlug: "flash-loan-spot-price-manipulation-single-tx",
            bugClass: "price-manipulation",
            similarityScore: 0.87,
            matchedFeatures: [
                "reads slot0/sqrtPriceX96",
                "no TWAP validation",
                "in same tx as deposit/borrow"
            ],
            missingPreconditions: [], // Empty = all satisfied
            location: { contract: "LendingPool", function: "deposit" },
            trackatorEvidence: {
                initJson: "functions[deposit].body.hasExternalCall = true",
                storageJson: "valueBearingVariables[collateralValue].sources = [pool.slot0]",
                syncJson: "atRiskGroups[deposit_borrow].riskLevel = HIGH"
            }
        }
        // ... more matches
    ]
};

// Attack Chain Composer transforms it into:
const attackChains = composeAttackChains(patternMatcherOutput, context);
```

### Interaction with Verifier Agent

After composition, chains are sent to Verifier for validation:

```javascript
// What we send to Verifier:
const verifierPayload = {
    phase: 2,
    subPhase: "chain_composition",
    input: {
        patternMatchCount: patternMatcherOutput.matches.length,
        chainCount: attackChains.length,
        passingGateCount: attackChains.filter(c => c.gateStatus.canEscalate).length
    },
    output: {
        attackChains: attackChains.map(c => ({
            id: c.id,
            archetype: c.archetype,
            stepCount: c.steps.length,
            gateStatus: c.gateStatus,
            feasibility: c.feasibility,
            topHistoricalMatch: c.historicalMatches[0]
        }))
    },
    request: "Validate chain compositions for logical consistency and completeness"
};
```

---

## Helper Functions Reference

### Precondition Verification Against Trackator

```javascript
function verifyPreconditionAgainstTrackator(precondition, context, currentState) {
    // Load field mapping from exploit-trackator-field-map.json
    const fieldMap = loadFieldMap();
    const mapping = fieldMap.field_mappings[precondition.mapping_key];
    
    if (!mapping) {
        return {
            verified: false,
            reason: `No Trackator field mapping found for precondition: ${precondition.id}`,
            source: null,
            jsonPath: null
        };
    }
    
    // Query Trackator JSON using mapped path
    const primaryResult = queryTrackatorJson(
        mapping.trackator_verification.primary_source,
        mapping.trackator_verification.json_path,
        context
    );
    
    // Apply verification logic from field map
    const logicResult = applyVerificationLogic(
        mapping.trackator_verification.verification_logic,
        primaryResult,
        currentState
    );
    
    // Check secondary sources if needed
    let secondaryResults = [];
    if (!logicResult.verified && mapping.trackator_verification.secondary_sources) {
        for (const secondary of mapping.trackator_verification.secondary_sources) {
            const [source, path] = secondary.split(': ');
            secondaryResults.push(queryTrackatorJson(source.trim(), path, context));
        }
    }
    
    return {
        verified: logicResult.verified || secondaryResults.some(r => r.verified),
        source: mapping.trackator_verification.primary_source,
        jsonPath: mapping.trackator_verification.json_path,
        currentValue: primaryResult.value,
        expectedValue: precondition.expected_value,
        deviation: logicResult.deviation,
        executionPath: mapping.execution_path_tracing
    };
}
```

### Conflict Detection

```javascript
function hasConflictingAssumptions(attackChain) {
    const assumptions = attackChain.assumptions;
    const conflicts = [];
    
    for (let i = 0; i < assumptions.length; i++) {
        for (let j = i + 1; j < assumptions.length; j++) {
            const conflict = detectPairwiseConflict(assumptions[i], assumptions[j]);
            if (conflict) {
                conflicts.push(conflict);
            }
        }
    }
    
    // Common conflict patterns:
    // 1. "Pool is deep enough to swap" vs "Pool is shallow enough to manipulate"
    // 2. "Function requires auth" vs "Function is permissionless"
    // 3. "State updates atomically" vs "State has race window"
    // 4. "Price feed is trustworthy" vs "Price feed is manipulatable"
    
    return conflicts.length > 0 ? conflicts : null;
}

function detectPairwiseConflict(assumptionA, assumptionB) {
    const conflictPatterns = [
        {
            regex: /deep.*liquidity|high.*volume|slippage.*low/i,
            antiregex: /shallow.*liquidity|thin.*pool|manipulable/i,
            message: "Cannot assume pool is both deep (for swapping) and shallow (for manipulating)"
        },
        {
            regex: /requires.*auth|access.*control|onlyOwner/i,
            antiregex: /permissionless|public.*access|anyone.*can/i,
            message: "Cannot assume function both requires and doesn't require authentication"
        },
        {
            regex: /atomic|mutex|lock|reentrancy.*guard/i,
            antiregex: /race.*window|desync|stale.*state|TOCTOU/i,
            message: "Cannot assume operation is both atomic and has race condition"
        },
        {
            regex: /trustworthy.*oracle|reliable.*price|TWAP|heartbeat/i,
            antiregex: /manipulable|spot.*price|single.*source|no.*sanity/i,
            message: "Cannot assume oracle is both trustworthy and manipulatable"
        }
    ];
    
    for (const pattern of conflictPatterns) {
        const matchesA = pattern.regex.test(assumptionA.text) || pattern.regex.test(assumptionB.text);
        const matchesB = pattern.antiregex.test(assumptionA.text) || pattern.antiregex.test(assumptionB.text);
        
        if (matchesA && matchesB) {
            return {
                assumptionA: assumptionA.id,
                assumptionB: assumptionB.id,
                message: pattern.message,
                severity: "blocking" // Blocks escalation
            };
        }
    }
    
    return null;
}
```

### Value Estimation

```javascript
function estimateExtractedValue(attackChain, assetsAtRisk) {
    // Base estimation on:
    // 1. Historical losses from matched patterns
    // 2. Assets at risk from Trackator
    // 3. Chain type multiplier
    
    const historicalAvgLoss = attackChain.steps.reduce((sum, step) => {
        const card = loadExploitCard(step.patternSlug);
        return sum + (card.source.loss_usd || 0);
    }, 0) / attackChain.steps.length;
    
    const assetExposure = assetsAtRisk.reduce((sum, asset) => {
        return sum + (asset.valueUsd || 0);
    }, 0);
    
    // Chain type affects extractable percentage
    const chainMultipliers = {
        'flash_loan_price_manipulation': 0.01, // 1% of exposure typically
        'reentrancy_drain': 0.5, // Can drain 50%+
        'access_control_takeover': 0.8, // Can take almost everything
        'oracle_governance_manipulation': 0.1, // 10% typical
        'cross_contract_coupling': 0.05 // 5% typical
    };
    
    const multiplier = chainMultipliers[attackChain.type] || 0.01;
    
    return {
        minimum: Math.min(historicalAvgLoss * 0.1, assetExposure * multiplier * 0.1),
        likely: Math.max(historicalAvgLoss, assetExposure * multiplier),
        maximum: Math.min(assetExposure * multiplier * 2, historicalAvgLoss * 10),
        methodology: `Historical avg ($${historicalAvgLoss}) × chain multiplier (${multiplier}) × exposure ($${assetExposure})`,
        confidence: attackChain.linkage.strength // 0-1
    };
}
```

---

## Quality Checks (Self-Validation)

Before outputting chains, this plugin runs internal quality checks:

```javascript
function runQualityChecks(attackChains) {
    const issues = [];
    
    for (const chain of attackChains) {
        // Check 1: Every step must have at least 2 verified preconditions
        for (const step of chain.steps) {
            if ((step.preconditions?.filter(p => p.verified)?.length || 0) < 2) {
                issues.push({
                    severity: 'error',
                    chainId: chain.id,
                    step: step.stepNumber,
                    message: `Step ${step.stepNumber} has fewer than 2 verified preconditions`
                });
            }
        }
        
        // Check 2: Execution path must be complete
        if (!chain.executionPath?.traced) {
            issues.push({
                severity: 'error',
                chainId: chain.id,
                message: 'Chain lacks complete execution trace'
            });
        }
        
        // Check 3: At least one attacker-controlled input per step
        for (const step of chain.steps) {
            if ((step.attackerControlledInputs?.length || 0) === 0) {
                issues.push({
                    severity: 'warning',
                    chainId: chain.id,
                    step: step.stepNumber,
                    message: `Step ${step.stepNumber} has no identified attacker-controlled inputs`
                });
            }
        }
        
        // Check 4: Gate status must be present
        if (!chain.gateStatus) {
            issues.push({
                severity: 'error',
                chainId: chain.id,
                message: 'Chain missing Execution Path Gate status'
            });
        }
        
        // Check 5: Historical match should exist for high-confidence chains
        if (chain.linkage.strength > 0.8 && (!chain.historicalMatches || chain.historicalMatches.length === 0)) {
            issues.push({
                severity: 'info',
                chainId: chain.id,
                message: 'High-confidence chain lacks historical precedent - may be novel attack'
            });
        }
    }
    
    return {
        valid: issues.filter(i => i.severity === 'error').length === 0,
        issues,
        chainsWithErrors: issues.filter(i => i.severity === 'error').map(i => i.chainId),
        chainsWithWarnings: [...new Set(issues.filter(i => i.severity === 'warning').map(i => i.chainId))]
    };
}
```

---

## Usage Example

### Input: Pattern Matcher finds 3 matches

```javascript
const patternMatcherOutput = {
    matches: [
        {
            patternSlug: "flash-loan-spot-price-manipulation-single-tx",
            similarityScore: 0.87,
            location: { contract: "Vault", function: "deposit" }
        },
        {
            patternSlug: "single-oracle-dependency-without-sanity-checks",
            similarityScore: 0.79,
            location: { contract: "Oracle", function: "getPrice" }
        },
        {
            patternSlug: "first-depositor-share-price-inflation",
            similarityScore: 0.72,
            location: { contract: "LPVault", function: "mint" }
        }
    ]
};
```

### Output: Attack Chain Composer produces 1 chain

```javascript
const attackChains = [
    {
        id: "CHAIN_001",
        archetype: "flash_loan_price_manipulation",
        steps: [
            {
                stepNumber: 1,
                patternSlug: "flash-loan-spot-price-manipulation-single-tx",
                action: "Flash borrow, manipulate pool price via swap"
            },
            {
                stepNumber: 2,
                patternSlug: "single-oracle-dependency-without-sanity-checks",
                action: "Oracle reads manipulated price (no sanity check)"
            },
            {
                stepNumber: 3,
                patternSlug: "first-depositor-share-price-inflation",
                action: "Deposit at inflated price, mint shares worth more than deposit"
            }
        ],
        linkage: {
            type: "state_enablement",
            strength: 0.85,
            executionOrder: "same_tx"
        },
        gateStatus: {
            canEscalate: true,
            maxAllowedStatus: "PROBABLE",
            gateResults: [
                { name: "Precondition Trace", passed: true },
                { name: "State Change Verification", passed: true },
                { name: "Attacker Control", passed: true },
                { name: "No Conflicting Assumptions", passed: true }
            ]
        },
        feasibility: {
            technicalFeasibility: "high",
            estimatedProfit: "$500K-2M",
            requiredCapital: "Flash loan $5-10M"
        }
    }
];
```

---

## Files This Plugin Consumes

| File | Purpose |
|------|---------|
| `Exploits-class-library/card-index.csv` | Pattern metadata |
| `Exploits-class-library/protocol-type-to-exploit-patterns.json` | Protocol routing |
| `Exploits-class-library/exploit-pattern-cards/*.md` | Individual pattern details |
| `Exploits-class-library/exploit-trackator-field-map.json` | Precondition → Trackator path mapping |
| `Exploits-class-library/attack-type-taxonomy.json` | Type classification |
| `trackator-init.json` | Contract inventory, functions, modifiers |
| `trackator-storage.json` | Value-bearing variables, writers, contended vars |
| `trackator-coupling.json` | Function dependencies, hidden couplings |
| `trackator-sync.json` | Sync groups, at-risk groups, assumptions |
| `trackator-evidence.json` | Classification registry, confidence scores |
| `trackator-attacks.json` | Ranked targets, attack scenarios |

---

## Files This Plugin Produces

| File | Content |
|------|---------|
| `output/attack-chains.json` | Composed attack chains (this session) |
| `output/chain-composition-report.md` | Human-readable composition report |
| `output/gate-blocked-chains.json` | Chains that failed Execution Path Gate (for review) |

---

## Anti-Patterns (Don't Do These)

❌ **Chain patterns that share no state** — "Access control bug + Reentrancy" in unrelated contracts  
❌ **Skip precondition verification** — Assume pattern match = exploitable (it's NOT)  
❌ **Ignore gate blocks** — Escalate blocked chains to Phase 3 anyway  
❌ **Create chains longer than 5 steps** — Real attacks rarely exceed 3-4 steps  
❌ **Assume historical loss = current extractable value** — Context differs  
❌ **Mix operational errors with code bugs** — "Admin sets bad oracle + Flash loan"  

✅ **Every chain step enables the next** — Clear state/access/timing linkage  
✅ **All preconditions traced to Trackator fields** — No hand-waving  
✅ **Respect gate verdict** — Blocked means BLOCKED (save for later analysis)  
✅ **Keep chains under 5 steps** — Simpler = more realistic  
✅ **Note novel chains explicitly** — No historical match ≠ invalid  

---

## Return Format

After completing composition, return:

```
DONE: {N} attack chains composed from {M} pattern matches.
{K} chains PASSED Execution Path Gate (can escalate to Phase 3).
{J} chains BLOCKED by gate (saved for analysis, not escalating).
Top chain: {CHAIN_ID} ({archetype}), {step_count} steps, ~${estimated_profit} extractable.
Quality check: {valid/warnings_count warnings}.
Key findings: {brief summary of top 3 chains}
```
