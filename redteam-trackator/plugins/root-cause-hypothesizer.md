# Plugin: Root Cause Hypothesizer

**Phase**: 3 (Creative Attack Enhancement)
**Purpose**: Perform multi-layer causal analysis on attack chains to identify WHY vulnerabilities exist at code, design, and fundamental levels
**Type**: Analysis plugin (deepens hypotheses with root cause classification)
**Version**: 2.0.0 (NEW - Phase 3 Upgrade)

---

## Overview

The Root Cause Hypothesizer transforms attack chains from Phase 2 into **causally-complete vulnerability assessments**. While the Attack Chain Composer answers **"HOW"** an exploit works, this plugin answers **"WHY"** the vulnerability exists at multiple depth layers:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ROOT CAUSE ANALYSIS LAYERS                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  LAYER 1: SURFACE (What)                                            │
│  ├─ Exploit pattern matched                                         │
│  ├─ Attack chain composed                                           │
│  └─ "Attacker does X, then Y, then Z"                               │
│                                                                     │
│  LAYER 2: CODE (Where Exactly)                                      │
│  ├─ Specific function/line with flaw                                │
│  ├─ Missing check, wrong order, incorrect logic                     │
│  └─ "Function F at line L missing guard G"                          │
│                                                                     │
│  LAYER 3: DESIGN (Why Code Was Written This Way)                    │
│  ├─ Assumption violated (oracle honest, tx atomic, caller trusted)   │
│  ├─ Invariant not enforced or wrong invariant assumed               │
│  └─ "Developer assumed P, but P doesn't hold under condition C"     │
│                                                                     │
│  LAYER 4: FUNDAMENTAL (Why Design Allowed This)                     │
│  ├─ Complexity hazard (inheritance, proxy, upgrade pattern)          │
│  ├─ Integration hazard (cross-contract, composability assumption)    │
│  └─ Economic misalignment (incentive structure enables exploitation) │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Insight**: Most audits find Layer 1 (the bug). Good audits find Layer 2 (the code flaw). **Elite audits find Layers 3-4** (why the bug was possible to introduce).

This plugin ensures every hypothesis escalated from Phase 3 includes root cause analysis that:
1. **Explains WHY** the vulnerability exists, not just WHAT it is
2. **Identifies what the audit missed** using historical "What Audit Missed" data
3. **Suggests fundamental fixes** that address root cause, not just symptoms
4. **Classifies the failure mode** for pattern recognition across protocols

---

## Core Philosophy: "Why > What"

> *"Finding the bug tells you what's broken. Finding the root cause tells you why it can break again."*

### The Root Cause Question Chain

For every attack chain from Phase 2, this plugin asks:

```javascript
function performRootCauseAnalysis(attackChain, context) {
    return {
        // Layer 1: Already known from Phase 2
        surface: {
            exploitPattern: attackChain.archetype,
            attackSteps: attackChain.steps,
            extractedValue: attackChain.feasibility.estimatedProfit
        },
        
        // Layer 2: NEW - Pinpoint exact code location
        code: analyzeCodeLayer(attackChain, context),
        
        // Layer 3: NEW - Identify design-level failure
        design: analyzeDesignLayer(attackChain, context),
        
        // Layer 4: NEW - Find fundamental enabling factor
        fundamental: analyzeFundamentalLayer(attackChain, context),
        
        // Cross-cutting: What would a typical audit miss?
        auditBlindSpots: identifyAuditBlindSpots(attackChain, context),
        
        // Remediation guidance
        remediation: generateRemediationGuidance(attackChain)
    };
}
```

---

## Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Attack chains | Phase 2 output | Composed chains passing Execution Path Gate |
| Exploit cards | `Exploits-class-library/exploit-pattern-cards/*.md` | Root Cause + "What Audit Missed" sections |
| Root cause catalog | `root-cause-catalog.json` | Causal pattern templates |
| Trackator context | All phases | init, storage, coupling, sync, evidence JSONs |

---

## Layer 2: Code-Level Analysis

### Objective
Identify the **exact code location and mechanism** of the flaw.

### Algorithm

```javascript
function analyzeCodeLayer(attackChain, context) {
    const codeAnalysis = {
        primaryFlaw: null,
        secondaryFlaws: [],
        flawType: null,  // From classification taxonomy
        exactLocation: {
            contract: null,
            function: null,
            lineRange: null,
            codeSnippet: null
        },
        mechanism: null,  // HOW the flaw enables exploitation
        missingMitigation: null  // What should be there but isn't
    };
    
    for (const step of attackChain.steps) {
        const card = loadExploitCard(step.patternSlug);
        
        // Extract root cause from card's "Root Cause" section
        const cardRootCause = parseRootCauseSection(card);
        
        // Map to Trackator's exact location data
        const trackatorLocation = locateFlawInTrackator(
            step.location,
            cardRootCause.mechanism,
            context.init
        );
        
        if (step.stepNumber === 1) {
            codeAnalysis.primaryFlaw = {
                patternSlug: step.patternSlug,
                description: cardRootCause.description,
                mechanism: cardRootCause.mechanism,
                location: trackatorLocation
            };
            codeAnalysis.flawType = classifyCodeFlaw(cardRootCause);
            codeAnalysis.exactLocation = trackatorLocation;
            codeAnalysis.mechanism = cardRootCause.mechanism;
        } else {
            codeAnalysis.secondaryFlaws.push({
                stepNumber: step.stepNumber,
                patternSlug: step.patternSlug,
                description: cardRootCause.description,
                location: trackatorLocation
            });
        }
        
        // Identify missing mitigation
        const mitigation = identifyMissingMitigation(step, card, context);
        if (mitigation) {
            codeAnalysis.missingMitigation = mitigation;
        }
    }
    
    return codeAnalysis;
}
```

### Code Flaw Classification Taxonomy

```javascript
const CODE_FLAW_TYPES = {
    // ORDERING FLAWS (most common in DeFi)
    CHECK_EFFECTS_INTERACTION_VIOLATION: {
        name: "Checks-Effects-Interactions Violation",
        description: "External call or state-changing operation occurs before critical state update",
        typicalPatterns: ["reentrancy-state-update-after-external-call", "flash-accounting-callback-pulls-from-unrelated-approved-address"],
        detection: "External call found before storage write in function body order"
    },
    MISSING_ACCESS_CONTROL: {
        name: "Missing Access Control",
        description: "Sensitive function lacks proper authorization check",
        typicalPatterns: ["missing-modifier-privileged-function", "ownership-takeover-via-covert-transfer"],
        detection: "Public function performs sensitive operation without onlyOwner/role check"
    },
    MISSING_INPUT_VALIDATION: {
        name: "Missing Input Validation",
        description: "Function accepts attacker-controlled input without bounds/sanity checks",
        typicalPatterns: ["unverified-caller-supplied-amount-exceeds-deposit", "unvalidated-swap-data-arbitrary-call"],
        detection: "Parameter used directly in calculation without validation"
    },
    
    // LOGIC ERRORS
    INCORRECT_CALCULATION: {
        name: "Incorrect Calculation",
        description: "Mathematical error in security-critical computation",
        typicalPatterns: ["health-factor-precision-miscalculation", "share-mint-truncation-after-supply-crushed-to-near-zero"],
        detection: "Division before multiplication, precision loss, overflow/underflow path"
    },
    STATE_CONSISTENCY_ERROR: {
        name: "State Consistency Error",
        description: "Multiple state variables updated non-atomically creating inconsistency window",
        typicalPatterns: ["stableswap-virtual-balance-invariant-drift-via-batched-operations", "amm-reserve-skim-sync-manipulation"],
        detection: "Related state variables written in different functions without lock"
    },
    RACE_CONDITION: {
        name: "Race Condition",
        description: "Shared state accessible by multiple callers without synchronization",
        typicalPatterns: ["sequential-legitimate-ops-trigger-underflow-dos", "token-transfer-hook-self-triggered-sync"],
        detection: "Contended variable with multiple writers and no mutex/reentrancy guard"
    },
    
    // ASSUMPTION VIOLATIONS
    ORACLE_TRUST_ASSUMPTION: {
        name: "Oracle Trust Assumption Violation",
        description: "Code assumes oracle value is trustworthy without validation",
        typicalPatterns: ["single-oracle-dependency-without-sanity-checks", "flash-loan-spot-price-manipulation-single-tx"],
        detection: "Price/oracle read used directly without TWAP/bounds/timestamp check"
    },
    CALLER_TRUST_ASSUMPTION: {
        name: "Caller Trust Assumption Violation",
        description: "Code assumes caller behaves honestly/cooperatively",
        typicalPatterns: ["callback-caller-check-bypassed-via-create2-prediction", "attacker-deployed-token-impersonation"],
        detection: "Caller-supplied address used as trusted counterparty"
    },
    ATOMICITY_ASSUMPTION: {
        name: "Atomicity Assumption Violation",
        description: "Code assumes multi-step operations are atomic when they're not",
        typicalPatterns: ["lock-then-immediate-claim-no-enforced-delay", "concentrated-liquidity-jit-range-walk-fee-extraction"],
        detection: "Multi-step operation without completion check or delay enforcement"
    }
};
```

---

## Layer 3: Design-Level Analysis

### Objective
Identify **design decisions or assumption violations** that enabled the code flaw.

### Algorithm

```javascript
function analyzeDesignLayer(attackChain, context) {
    return {
        violatedAssumptions: identifyViolatedAssumptions(attackChain, context),
        missingInvariants: identifyMissingInvariants(attackChain, context),
        designGap: classifyDesignGap(attackChain),
        complexityFactor: assessComplexityContribution(attackChain, context)
    };
}

function identifyViolatedAssumptions(attackChain, context) {
    const violations = [];
    
    // Check against Sync Analyzer's assumption dependency graph
    if (context.sync?.assumptionDependencyGraph) {
        const { producers, consumers, verifiers } = context.sync.assumptionDependencyGraph;
        
        for (const step of attackChain.steps) {
            const card = loadExploitCard(step.patternSlug);
            
            // Each precondition represents an assumption the protocol makes
            for (const precondition of card.preconditionChain) {
                const assumptionType = classifyAssumptionType(precondition);
                
                // Is there a verifier for this assumption?
                const hasVerifier = verifiers.some(v => 
                    v.assumptionId === precondition.id || 
                    v.coversAssumption(precondition)
                );
                
                if (!hasVerifier) {
                    violations.push({
                        assumptionId: precondition.id,
                        assumptionText: precondition.condition_text,
                        type: assumptionType,
                        violatedBy: step.patternSlug,
                        whyUnverified: explainWhyNoVerifier(precondition, context),
                        severity: assessAssumptionViolationSeverity(assumptionType)
                    });
                }
            }
        }
    }
    
    return violations;
}
```

### Assumption Type Classification

```javascript
const ASSUMPTION_TYPES = {
    ORACLE_HONESTY: {
        name: "Oracle Honesty",
        description: "Oracle returns accurate, manipulation-resistant prices",
        violationImpact: "Price-dependent calculations can be skewed",
        typicalMitigation: "TWAP, multi-source aggregation, heartbeat checks",
        detectableVia: "sync.json: assumptionDependencies[?(@.type=='oracle_trust')]"
    },
    TX_ATOMICITY: {
        name: "Transaction Atomicity",
        description: "Protocol state is consistent within a transaction",
        violationImpact: "Intermediate states can be exploited",
        typicalMitigation: "Reentrancy guards, mutexes, completion flags",
        detectableVia: "coupling.json: hiddenCouplings[?(@.atomicityRisk==true)]"
    },
    CALLER_BENIGNANCE: {
        name: "Caller Benignance",
        description: "Caller acts in good faith, not adversarially",
        violationImpact: "Attacker-controlled parameters exploited",
        typicalMitigation: "Input validation, trust minimization, permissioned callbacks",
        detectableVia: "init.json: functions[?(@.parameters[].callerSupplied==true)]"
    },
    LIQUIDITY_DEPTH: {
        name: "Liquidity Depth",
        description: "Pools have sufficient depth to resist manipulation",
        violationImpact: "Spot prices can be moved significantly",
        typicalMitigation: "Depth requirements, circuit breakers, slippage limits",
        detectableVia: "storage.json: valueBearingVariables[?(@.manipulable==true)]"
    },
    PRICE_STABILITY: {
        name: "Price Stability (Short-term)",
        description: "Prices don't move materially within one block/TX",
        violationImpact: "Flash loan manipulation viable",
        typicalMitigation: "TWAP, delayed pricing, moving averages",
        detectableVia: "sync.json: criticalRisks[?(@.riskType=='stale-price')]"
    },
    CONTRACT_IMMUTABILITY: {
        name: "Contract Immutability (Behavioral)",
        description: "External contracts behave as expected/documented",
        violationImpact: "Malicious callback/implementation change",
        typicalMitigation: "Allowlisting, interface checks, behavior validation",
        detectableVia: "init.json: functions[?(@.body.hasExternalCall==true && @.body.externalTarget=='parameter')]"
    },
    GOVERNANCE_INTEGRITY: {
        name: "Governance Process Integrity",
        description: "Governance follows documented rules/timelines",
        violationImpact: "Rushed proposals, missing delays, parameter manipulation",
        typicalMitigation: "Timelocks, execution delays, proposal quotas",
        detectableVia: "enrich.json: invariants[?(@.type=='governance')]"
    }
};
```

### Design Gap Classification

```javascript
function classifyDesignGap(attackChain) {
    const gaps = {
        SINGLE_POINT_OF_FAILURE: {
            name: "Single Point of Failure",
            description: "Critical functionality depends on one unverified source/contract/path",
            indicator: "Single oracle, single price feed, single entry point with no fallback",
            rootCause: "Insufficient redundancy in critical path"
        },
        MISSING_DEFENSE_IN_DEPTH: {
            name: "Missing Defense in Depth",
            description: "Only one layer of protection between attacker and value",
            indicator: "One check, one modifier, one assumption standing between attack and loss",
            rootCause: "Security model assumes first line of defense never fails"
        },
        TRUST_BOUNDARY_VIOLATION: {
            name: "Trust Boundary Violation",
            description: "Trust extends beyond verified/controlled boundary",
            indicator: "External input trusted after crossing trust boundary",
            rootCause: "Trust model doesn't account for adversarial environment"
        },
        STATE_MODEL_INCORRECTNESS: {
            name: "State Model Incorrectness",
            description: "Protocol's internal state machine has reachable invalid states",
            indicator: "State transitions allow inconsistent/invalid combinations",
            rootCause: "Formal state model missing or incomplete"
        },
        ECONOMIC_MISALIGNMENT: {
            name: "Economic Misalignment",
            description: "Incentive structure rewards exploitation or punishes honesty",
            indicator: "Profitable attack costs less than potential gain",
            rootCause: "Game-theoretic analysis missing or incomplete"
        },
        COMPLEXITY_HAZARD: {
            name: "Complexity Hazard",
            description: "System too complex to fully verify/audit",
            indicator: "Deep inheritance, proxy patterns, many integration points",
            rootCause: "Over-engineering or premature optimization"
        }
    };
    
    // Match attack chain characteristics to gap types
    // ... implementation matches archetype features to gap indicators
    
    return gaps;
}
```

---

## Layer 4: Fundamental Analysis

### Objective
Identify **systemic/enabling factors** that made this class of vulnerability possible.

### Algorithm

```javascript
function analyzeFundamentalLayer(attackChain, context) {
    return {
        enablingFactor: identifyEnablingFactor(attackChain, context),
        systemicIssue: classifySystemicIssue(attackChain),
        recurrenceProbability: estimateRecurrence(attackChain, context),
        protocolClassIndicator: mapToProtocolClass(attackChain)
    };
}

const ENABLING_FACTORS = {
    INHERITANCE_COMPOSITION: {
        name: "Inheritance/Composition Complexity",
        description: "Vulnerability enabled by deep contract inheritance or complex composition",
        example: "Proxy → Implementation → Library → Interface chain obscures reentrancy target",
        detection: "Contract inheritance depth > 3 OR composition chain > 5 contracts",
        mitigation: "Flatten inheritance, explicit visibility, composition audit"
    },
    PROXY_UPGRADE_PATTERN: {
        name: "Proxy/Upgrade Pattern Hazard",
        description: "Upgradeable proxy pattern creates verification gaps",
        example: "Implementation contract changed, old audit no longer valid",
        detection: "Proxy pattern detected with upgrade capability",
        mitigation: "Re-audit on upgrade, immutable core, upgrade timelocks"
    },
    CROSS_PROTOCOL_INTEGRATION: {
        name: "Cross-Protocol Integration Risk",
        description: "Vulnerability arises at integration boundary between protocols",
        example: "Protocol A assumes Protocol B's behavior, B changes or differs",
        detection: "External protocol calls with assumption about behavior",
        mitigation: "Interface contracts, behavior validation, defense at boundary"
    },
    NOVEL_PRIMITIVE_USAGE: {
        name: "Novel Primitive Usage",
        description: "Using new/untested ERC/token standard or DeFi primitive",
        example: "New hook mechanism in ERC-4337 has unexpected reentrancy surface",
        detection: "Usage of token/standard < 6 months old OR custom modification",
        mitigation: "Extended testing period, formal verification, security review"
    },
    TIME_PRESSURE_DEPLOYMENT: {
        name: "Time Pressure / Deployment Rush",
        indication: "Vulnerability consistent with rushed development",
        example: "Copy-paste from similar protocol without full adaptation",
        detection: "Code similarity to other protocols with modifications, incomplete adaptation",
        mitigation: "Development timeline security gates, adaptation checklist"
    }
};
```

---

## "What the Audit Missed" Integration

### Objective
Leverage historical post-mortem insights to predict what auditors might miss THIS time.

### Data Source
Each exploit card contains a **"What the Audit Missed"** section with specific blind spots:

```javascript
function identifyAuditBlindSpots(attackChain, context) {
    const blindSpots = [];
    
    for (const step of attackChain.steps) {
        const card = loadExploitCard(step.patternSlug);
        const auditMissed = parseAuditMissedSection(card);
        
        blindSpots.push({
            patternSlug: step.patternSlug,
            blindSpots: auditMissed,
            relevanceToCurrent: assessBlindSpotRelevance(auditMissed, context),
            specificCheckRecommendation: generateSpecificCheck(auditMissed, step.location)
        });
    }
    
    // Also check anti-pattern library
    const antiPatterns = loadAntiPatternLibrary();
    blindSpots.push(...mapAntiPatternsToBlindSpots(antiPatterns, attackChain));
    
    return blindSpots;
}
```

### Common Audit Blind Spot Categories

From analysis of 65+ exploit cards:

| Blind Spot Category | Frequency | Example |
|---------------------|-----------|---------|
| **Parameter Trust** | 28% | Assuming attacker-supplied address is "trusted pair/pool/callback" |
| **Modifier Scope** | 22% | Assuming `nonReentrant` on entrypoint covers all reentry paths |
| **Oracle Assumptions** | 18% | Assuming spot price = fair price without TWAP check |
| **Integration Gaps** | 15% | Missing behavior at protocol integration boundaries |
| **Edge Case Math** | 10% | Precision loss, overflow, division order in edge cases |
| **State Consistency** | 7% | Assuming related state updates atomically when they don't |

---

## Remediation Guidance

### Objective
Generate **root cause-aligned remediation**, not just symptom patches.

### Algorithm

```javascript
function generateRemediationGuidance(attackChain) {
    return {
        immediateFixes: generateImmediateFixes(attackChain),      // Stop the bleeding
        codeLevelFixes: generateCodeLevelFixes(attackChain),     // Fix the specific flaw
        designLevelFixes: generateDesignLevelFixes(attackChain),  // Fix the design gap
        fundamentalChanges: generateFundamentalChanges(attackChain), // Prevent class of bugs
        
        fixValidation: [
            "Verify fix doesn't break existing functionality",
            "Test fix against original attack vector",
            "Check for introduced side effects",
            "Confirm fix addresses root cause, not just symptom"
        ]
    };
}

// Example: For reentrancy chain
function generateRemediationForReentrancy(analysis) {
    return {
        immediate: "Add nonReentrant modifier to vulnerable function AND all functions in call chain",
        code: "Move state update BEFORE external call (checks-effects-interactions pattern)",
        design: "Establish coding standard: ALL functions performing external calls MUST have reentrancy guard",
        fundamental: "Review entire codebase for CEI violations; consider automated lint rule"
    };
}
```

---

## Output Format

### Root Cause Analysis Object

```javascript
{
    id: "RCA_CHAIN_001",
    chainId: "CHAIN_001",  // From Phase 2
    analyzedAt: "2026-08-06T...",
    
    // Layer 1: Surface (from Phase 2, preserved)
    surface: {
        archetype: "flash_loan_price_manipulation",
        steps: [...],
        feasibility: {...}
    },
    
    // Layer 2: Code (NEW)
    code: {
        primaryFlaw: {
            type: "ORACLE_TRUST_ASSUMPTION_VIOLATION",
            name: "Oracle Trust Assumption Violation",
            description: "Protocol reads spot price from single AMM pool without TWAP validation",
            location: {
                contract: "Oracle.sol",
                function: "getPrice()",
                lineRange: [45, 52],
                codeSnippet: "return pool.slot0().sqrtPriceX96;"
            },
            mechanism: "Spot price manipulable via flash loan-funded swap; no historical average or sanity check"
        },
        secondaryFlaws: [...],
        missingMitigation: {
            type: "TWAP_ORACLE",
            recommendation: "Replace spot price read with Uniswap V3 TWAP (observe()) or Chainlink feed",
            urgency: "critical"
        }
    },
    
    // Layer 3: Design (NEW)
    design: {
        violatedAssumptions: [
            {
                type: "ORACLE_HONESTY",
                text: "Pool spot price reflects fair market value",
                violatedBy: "flash-loan-spot-price-manipulation-single-tx",
                severity: "critical",
                whyUnverified: "No TWAP, no multi-source, no bounds check on price output"
            },
            {
                type: "PRICE_STABILITY",
                text: "Price cannot move >10% in one block",
                violatedBy: "same",
                severity: "high",
                whyUnverified: "No circuit breaker or max deviation check"
            }
        ],
        missingInvariants: [
            {
                invariant: "Collateral value >= actual market value",
                status: "violatable",
                how: "Manipulate price reading to inflate collateral valuation"
            }
        ],
        designGap: {
            type: "SINGLE_POINT_OF_FAILURE",
            name: "Single Point of Failure",
            description: "Entire collateral valuation depends on one unvalidated price read"
        }
    },
    
    // Layer 4: Fundamental (NEW)
    fundamental: {
        enablingFactor: {
            type: "NOVEL_PRIMITIVE_USAGE",
            name: "Novel Primitive Usage",
            description: "Protocol uses concentrated liquidity (Uniswap V3) position as collateral - new primitive with different risk profile than V2 LP tokens"
        },
        systemicIssue: {
            class: "LENDING_AGAINST_EXOTIC_COLLATERAL",
            description: "Lending protocols accepting exotic collateral types often have pricing/oracle gaps"
        },
        recurrenceProbability: "high",  // Same issue likely in other protocols using similar patterns
        protocolClassIndicator: "lending-with-cl-position-collateral"
    },
    
    // Audit Blind Spots (NEW)
    auditBlindSpots: [
        {
            category: "ORACLE_ASSUMPTIONS",
            description: "Auditors assume AMM pool price is 'market price' without verifying manipulation resistance",
            specificCheck: "For every price read, trace: source → freshness → manipulation cost → validation",
            relevance: "critical"
        },
        {
            category: "INTEGRATION_GAPS",
            description: "Auditor may review Oracle.sol in isolation without tracing into pool's liquidity profile",
            specificCheck: "When auditing oracle/price feeds, ALWAYS check liquidity depth of source pools",
            relevance: "high"
        }
    ],
    
    // Remediation (NEW)
    remediation: {
        immediate: [
            "Add TWAP validation (minimum 30-minute observation window)",
            "Add price deviation circuit breaker (max 5% per block)",
            "Add minimum liquidity requirement for eligible price sources"
        ],
        code: [
            "Refactor getPrice() to use pool.observe() instead of pool.slot0()",
            "Add sanity check: require(price >= lowerBound && price <= upperBound)"
        ],
        design: [
            "Establish multi-source oracle strategy (primary + backup + circuit breaker)",
            "Define collateral eligibility criteria including oracle quality requirements"
        ],
        fundamental: [
            "Review all exotic collateral types for pricing adequacy",
            "Consider refusing concentrated LP positions as collateral or applying higher haircuts"
        ]
    },
    
    // Summary Metrics
    summary: {
        totalLayersAnalyzed: 4,
        rootCauseConfidence: "high",  // Based on evidence strength
        fixComplexity: "medium",  // How hard to properly fix
        regressionRisk: "low",  // Risk that fix breaks other things
        priorityScore: 0.92  // Composite severity/importance
    }
}
```

---

## Integration with Existing Pipeline

### Where This Plugin Fits

```
PHASE 3 PIPELINE (Enhanced):
                    
    ┌──────────────────┐
    │ Attack Chains     │  ← From Phase 2 (gate-passing only)
    │ (Phase 2 Output)  │
    └────────┬─────────┘
             │
             ▼
    ┌──────────────────┐     ┌──────────────────────┐
    │ Reverse Engineering│     │ Assumption Breaker   │  ← Existing plugins
    │ (finds NEW bugs)  │     │ (breaks assumptions) │
    └────────┬─────────┘     └────────┬─────────────┘
             │                         │
             └──────────┬──────────────┘
                        ▼
             ┌──────────────────────┐
             │ Root Cause           │  ← NEW: This plugin
             │ Hypothesizer         │
             │ (analyzes WHY)       │
             └────────┬─────────────┘
                      │
                      ▼
             ┌──────────────────────┐
             │ Full Execution Trace │  ← MANDATORY (existing)
             │ (A→B→C→end)         │
             └────────┬─────────────┘
                      │
              RCA-enhanced hypotheses ▼
                   Phase 4: Fork Testing
```

### Interaction with Hacker Agent

The Root Cause Hypothesizer **enhances** the Hacker Agent's output:

```javascript
// BEFORE Phase 3 Enhancement (hacker agent output):
{
    id: "CREATIVE_01",
    type: "reverse_engineering",
    targetAsset: "_balances",
    attackIdea: "Manipulate rewardPerTokenStored...",
    status: "HYPOTHESIS"
}

// AFTER Phase 3 Enhancement (with RCA):
{
    id: "CREATIVE_01",
    type: "reverse_engineering",
    targetAsset: "_balances",
    attackIdea: "Manipulate rewardPerTokenStored...",
    status: "HYPOTHESIS",
    
    // NEW: Root Cause Analysis attached
    rootCauseAnalysis: {
        code: { primaryFlaw: { type: "MISSING_ACCESS_CONTROL", location: {...} } },
        design: { violatedAssumptions: [...], designGap: {...} },
        fundamental: { enablingFactor: {...} },
        auditBlindSpots: [...],
        remediation: {...}
    }
}
```

---

## Quality Checks (Self-Validation)

```javascript
function runRootCauseQualityChecks(analysis) {
    const issues = [];
    
    // Check 1: All 4 layers must be present
    if (!analysis.code || !analysis.design || !analysis.fundamental) {
        issues.push({
            severity: 'error',
            message: 'Missing one or more analysis layers (code/design/fundamental)'
        });
    }
    
    // Check 2: Code flaw must have exact location
    if (!analysis.code?.exactLocation?.contract || 
        !analysis.code?.exactLocation?.function) {
        issues.push({
            severity: 'error',
            message: 'Code-level analysis lacks exact location (contract/function)'
        });
    }
    
    // Check 3: At least one violated assumption identified
    if (!analysis.design?.violatedAssumptions?.length) {
        issues.push({
            severity: 'warning',
            message: 'No design-level assumptions identified'
        });
    }
    
    // Check 4: At least one audit blind spot noted
    if (!analysis.auditBlindSpots?.length) {
        issues.push({
            severity: 'warning',
            message: 'No audit blind spots identified'
        });
    }
    
    // Check 5: Remediation must include immediate + design level
    if (!analysis.remediation?.immediate?.length || 
        !analysis.remediation?.design?.length) {
        issues.push({
            severity: 'warning',
            message: 'Remediation guidance incomplete (need immediate + design fixes)'
        });
    }
    
    // Check 6: Fundamental analysis must classify enabling factor
    if (!analysis.fundamental?.enablingFactor?.type) {
        issues.push({
            severity: 'info',
            message: 'Fundamental analysis lacks enabling factor classification'
        });
    }
    
    return {
        valid: issues.filter(i => i.severity === 'error').length === 0,
        issues
    };
}
```

---

## Usage Example

### Input: Flash Loan Price Manipulation Chain from Phase 2

```javascript
const attackChain = {
    id: "CHAIN_001",
    archetype: "flash_loan_price_manipulation",
    steps: [
        { stepNumber: 1, patternSlug: "flash-loan-spot-price-manipulation-single-tx", ... },
        { stepNumber: 2, patternSlug: "single-oracle-dependency-without-sanity-checks", ... },
        { stepNumber: 3, patternSlug: "first-depositor-share-price-inflation", ... }
    ],
    gateStatus: { canEscalate: true, ... }
};
```

### Output: Root Cause Enhanced Analysis

```javascript
const rcaResult = {
    id: "RCA_CHAIN_001",
    
    code: {
        primaryFlaw: {
            type: "ORACLE_TRUST_ASSUMPTION_VIOLATION",
            location: { contract: "VaultOracle.sol", function: "getAssetPrice()", lineRange: [23, 29] },
            mechanism: "Reads slot0() directly without TWAP or sanity check"
        }
    },
    
    design: {
        violatedAssumptions: [
            { type: "ORACLE_HONESTY", text: "AMM spot price = fair market value" },
            { type: "PRICE_STABILITY", text: "Price stable within one TX" }
        ],
        designGap: { type: "SINGLE_POINT_OF_FAILURE", name: "Single Price Source" }
    },
    
    fundamental: {
        enablingFactor: { type: "CROSS_PROTOCOL_INTEGRATION", name: "Using DEX LP as lending collateral" },
        systemicIssue: { class: "LENDING_WITH_EXOTIC_COLLATERAL" }
    },
    
    auditBlindSpots: [
        { category: "ORACLE_ASSUMPTIONS", description: "Auditor assumed pool price = market price" },
        { category: "INTEGRATION_GAPS", description: "Missed liquidity depth analysis of price source" }
    ],
    
    remediation: {
        immediate: ["Add TWAP oracle", "Add circuit breaker"],
        design: ["Multi-source oracle strategy", "Collateral eligibility criteria"]
    }
};
```

---

## Files This Plugin Consumes

| File | Purpose |
|------|---------|
| `Exploits-class-library/exploit-pattern-cards/*.md` | Root Cause + "What Audit Missed" sections |
| `Exploits-class-library/root-cause-catalog.json` | Causal pattern templates |
| `Exploits-class-library/anti-pattern-library/*.md` | Auditor blind spot catalog |
| Trackator JSON files (all 8) | Location, dependency, sync data |

---

## Files This Plugin Produces

| File | Content |
|------|---------|
| `output/root-cause-analyses.json` | RCA objects for each chain |
| `output/root-cause-report.md` | Human-readable RCA report |
| `output/blind-spot-analysis.md` | Aggregated audit blind spot analysis |

---

## Anti-Patterns (Don't Do These)

❌ **Stop at Layer 1** — Report the exploit pattern without asking WHY it exists  
❌ **Blame the developer** — "Developer mistake" is not a root cause  
❌ **Generic remediation** — "Add validation" without specifying WHAT validation  
❌ **Ignore fundamental factors** — Fix code without addressing design gap  
❌ **Skip audit blind spots** — Don't learn from historical misses  

✅ **Always drill down to Layer 3-4** — Design/Fundamental analysis required  
✅ **Specific locations** — Contract:Function:Line for every finding  
✅ **Historical grounding** — Map to "What Audit Missed" from real incidents  
✅ **Actionable remediation** — Specific enough to implement directly  

---

## Return Format

After completing root cause analysis, return:

```
DONE: Root Cause Analysis complete for {N} attack chains.
{M} analyses passed quality checks ({K} warnings).
Average root cause confidence: {confidence}%.
Top root causes found: {brief summary of top 3}.
Key audit blind spots to watch: {brief summary}.
Remediation priorities: {ordered list by severity}.
```
