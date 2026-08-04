---
name: redteam-trackator
description: Offensive security assessment for Solidity/DeFi protocols using Trackator output as input. Two-agent architecture (Creative Hacker + Verifier) with block-gate paradigm. Trigger on "redteam", "security audit", "offensive testing", "vulnerability assessment", "find exploits", "hack smart contract", "redteam-trackator".
---

# Redteam-Trackator

A two-agent offensive security assessment system that consumes **Trackator** static/runtime analysis output to find **true positive** smart contract vulnerabilities in Solidity/DeFi protocols.

## Core Philosophy

| Old Redteam-Swarm | Redteam-Trackator |
|-------------------|-------------------|
| 50+ agents, 20 kill gates | **2 agents (Hacker + Verifier), Block gates** |
| Kills everything including TPs | **Saves findings for PoC validation** |
| "Everyone is malicious" (kills governance bugs) | **"Roles trusted, setup audited"** |
| Partial execution traces | **Full A→B→C→end trace REQUIRED** |
| Binary bug/no-bug output | **Graded: confirmed/probable/lead/dead** |
| TP survival rate: ~0% | **TP survival rate: estimated 60-80%** |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    REDTEAM-TRACKATOR PIPELINE v2.0                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PHASE 0: INGESTION ──────────┐                                    │
│  ├── Read Trackator output     │                                    │
│  ├── Extract Enhanced Fields  │  ← NEW: Storage/Coupling/Sync/Evid │
│  └── Build hypothesis list     │                                    │
│              ↓                 │                                    │
│  PHASE 1: INTENT FILTERING     │  ← Kill FPs EARLY                  │
│  ├── Intended Behavior Plugin  │                                    │
│  └── {keep | downgrade | discard}                                   │
│              ↓                 │                                    │
│  PHASE 2: PATTERN MATCHING     │  ← Historical exploit cards        │
│  ├── Pattern Matcher Plugin    │                                    │
│  ├── Evidence Validation       │  ← NEW: 6-class classification   │
│  ├── Reachability Check        │  ← BLOCK GATE (save, don't kill)   │
│  └── {confirmed | probable | lead | dead}                           │
│              ↓                 │                                    │
│  PHASE 3: CREATIVE ATTACK      │  ← Where Hacker LIVES             │
│  ├── Reverse Engineering       │  ← ENHANCED: Storage Dep. data    │
│  ├── Assumption Breaker        │  ← ENHANCED: Sync Analyzer data  │
│  ├── State Coupling Analysis   │  ← NEW: Coupling-based attacks   │
│  ├── Full Execution Trace ★    │  ← MANDATORY                      │
│  └── Reachability Check        │  ← BLOCK GATE                     │
│              ↓                 │                                    │
│  PHASE 4: FUZZING             │  ← Echidna/Medusa via Fizz         │
│  ├── Generate from Invariants  │                                    │
│  ├── Run Fuzz Campaign         │                                    │
│  ├── Disproof Engine           │  ← NEW: False positive elimination│
│  └── Realism Check             │  ← BLOCK GATE                     │
│              ↓                 │                                    │
│  PHASE 5: FORK TESTING        │  ← Mainnet reality check           │
│  ├── Smoke Fork               │                                    │
│  ├── Deep Fork + Iteration ★★ │  ← Hacker lives HERE              │
│  ├── Trackator Visualization   │                                    │
│  └── Evidence Validation       │  ← NEW: 9-criteria proof          │
│              ↓                 │                                    │
│  PHASE 6: REPORTING           │                                    │
│  └── redteam-trackator-report.md  ← ENHANCED: Evidence tables      │
│                                                                     │
│  ═══ TRACKATOR ENHANCED DATA LAYERS (v2.0) ═══                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Phase 1: Storage Dependency Analyzer                        │   │
│  │ ├─ variableWriters[]     → Who writes what                  │   │
│  │ ├─ contentedVariables[]  → Race condition targets           │   │
│  │ ├─ valueBearingVariables[] → Where's the money               │   │
│  │ └─ sharedStateMatrix[]   → Permissionless × Shared state   │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │ Phase 2: State Coupling Detector                            │   │
│  │ ├─ functionDependencyMatrix[N×N] → Func pair couplings      │   │
│  │ ├─ hiddenCouplings[]      → Transient/conditional coupling │   │
│  │ ├─ invariantFunctionMap[] → Which funcs break/depend invs  │   │
│  │ └─ topIntersections[]     → Highest-value attack surfaces  │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │ Phase 3: Sync Analyzer (State Synchronization)              │   │
│  │ ├─ assumptionDependencyGraph → Producer/consumer/verifier  │   │
│  │ ├─ desynchronizationAnalysis → Stale data, drift, races    │   │
│  │ ├─ criticalDesyncRisks[]  → TOCTOU, stale oracle, etc.     │   │
│  │ └─ syncRelationships[]    → Top 20 ranked by exploitability │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │ Phase 4: Evidence Validator                                │   │
│  │ ├─ classificationRegistry → 6-class finding classification │   │
│  │ ├─ reachabilityAnalysis[] → Complete execution paths       │   │
│  │ ├─ disproofEngine         → Attempts to DISPROVE findings   │   │
│  │ └─ confidenceAssessments[] → Multi-dimensional 0-100% score  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘

★ = Full execution trace A→B→C→end MANDATORY before escalation
★★ = Hacker iterates on fork until success or max iterations reached
🆕 = New v2.0 capability from Trackator Enhanced Output
```

## Parameters

### Required
- `TRACKATOR_OUTPUT_DIR`: Path containing Trackator JSON files (`trackator-init.json`, `trackator-enrich.json`, optionally `trackator-analyze.json`)
- `TARGET_PROTOCOL`: Name/description of protocol under audit

### Optional (but recommended)
- `EXPLOITS_LIBRARY_PATH`: Path to Exploits-class-library (default: `./Exploits-class-library/`)
- `FIZZ_SKILL_PATH`: Path to Fizz skill for fuzzing integration (optional but recommended)
- `MAX_FORK_ITERATIONS`: Maximum fork test iterations (default: 10)
- `FORK_BLOCK_NUMBER`: Mainnet block number to fork (default: latest)
- `OUTPUT_DIR`: Report output directory (default: `./redteam-output/`)

### v2.0: Enhanced Trackator Output (NEW)
When Trackator produces enhanced output (v2.0+), the following additional files/data are available:

- `trackator-storage.json` — Storage Dependency Analyzer output (variableWriters, shared-state matrix)
- `trackator-coupling.json` — State Coupling Detector output (functionDependencyMatrix, hiddenCouplings)
- `trackator-sync.json` — Sync Analyzer output (assumptionDependencyGraph, desyncAnalysis)
- `trackator-evidence.json` — Evidence Validator output (classificationRegistry, reachabilityAnalysis)

**Backward Compatibility**: If enhanced files are missing, Redteam-Trackator operates in v1.0 mode using only basic Trackator output.

## Workflow Rules

1. **Follow phases in order** — each phase produces artifacts consumed by next phase
2. **Never skip execution trace** — partial traces produce false positives
3. **Block gates save, never kill** — unvalidated findings go to PoC queue, not trash
4. **Trust roles are trusted** — admin/keeper/governance are NOT malicious unless code allows privilege escalation TO that role
5. **Operational errors ≠ bugs** — bad config by trusted role is operational, not vulnerability
6. **Trackator is ground truth** — all analysis builds on Trackator observations, not speculation

---

## STRICT RULES (Non-Negotiable)

### Rule 1: Full Execution Trace Requirement

> *"Before escalating ANY hypothesis to Verifier, Hacker MUST complete full execution trace A → B → C → end of execution."*

**What this means:**
- If hypothesis says "calling A causes manipulation", you MUST trace what happens AFTER A completes
- Trace through ALL downstream function calls until execution returns to caller
- If a later step B/C/D patches the issue → hypothesis dies BEFORE reaching Verifier
- No exceptions. No shortcuts. No "sign of bug" without complete proof.

**Trackator fields used:**
```json
{
  "functions": [{
    "name": "transferInRewards",
    "calls": ["approve", "address", "transferInRewards"],
    "body": { "hasExternalCall": true, "ceiPattern": "violated" }
  }]
}
```

Use `calls[]` array to build complete call graph. Use `callGraph` edges from init.json.

### Rule 2: Trust Role Protection

> *"Trusted roles (admin, keeper, governance, oracle operator) are TRUSTED — not compromised, not malicious, not key-stolen."*

**Trusted actions (NOT bugs):**
- Admin calls privileged function correctly → Operational
- Governance passes proposal following rules → By design
- Keeper triggers liquidation when conditions met → Working as intended
- Oracle returns price within documented bounds → Expected behavior

**BUT these ARE bugs:**
- Code allows privilege escalation TO trusted role without proper process
- Access control check has logic error (wrong variable, bypassable condition)
- Trusted role function has arithmetic overflow on ANY valid input
- Missing access control where spec requires it

**Trackator field mapping:**
```javascript
// Trust assumptions from enrich.json
trustAssumptions: [
  { id: "TA_1", category: "oracle", assumption: "Oracle prices reflect true market values" },
  { id: "TA_3", category: "governance", assumption: "Governance processes are not captured" }
]

// Functions with role-based access
functions: [{ name: "mint", modifiers: ["onlyRole"] }]
```

### Rule 3: Operational Error Exclusion

> *"Operational errors are NOT smart contract bugs."*

| Scenario | Verdict | Reason |
|----------|---------|--------|
| Admin sets feeRate = 99% | NOT BUG | Trusted role making config choice |
| Admin sets oracle = dead address | NOT BUG | Operational failure |
| Keeper doesn't call liquidate() | NOT BUG | Human oversight |
| Governance passes proposal to drain funds | NOT BUG | Governance working as designed |
| Admin pauses forever | NOT BUG | Privileged function doing its job |

**Exception**: If the CODE has a flaw even for valid inputs:
```solidity
// NOT a bug: admin can set high fee
function setFee(uint256 _fee) external onlyOwner { fee = _fee; }

// IS a bug: fee calculation overflows on any valid input
function calculateFee(uint256 amount) public view returns (uint256) {
    return amount * fee / 1e4; // Overflow if amount * fee > MAX_UINT256
}
```

### Rule 4: Block Gate Paradigm

> *"Block gates SAVE findings for PoC validation. Kill gates DELETE findings."*

```
OLD KILL GATE:
Finding → "Can't prove reachability" → DELETE FOREVER ❌

NEW BLOCK GATE:
Finding → "Can't prove reachability yet" → SAVE to PoC queue ✅
→ Later: Fork test proves it works → CONFIRMED ✅
→ Later: Fork test fails → DEAD (but we tried)
```

**Canonical Verdict States (ALL files MUST use these exactly):**

| State | Meaning | Action |
|-------|---------|--------|
| `CONFIRMED` | Proven on forked mainnet with TX hash | Include in report as confirmed finding |
| `PROBABLE` | Strong evidence, partial replication or minor gaps | Include with caveats in report |
| `LEAD` | Interesting pattern worth expert manual review | Appendix only |
| `INCOMPLETE` | Missing information or trace — return to Hacker | Block gate: send back for completion |
| `DEAD` | Proven impossible after thorough investigation | Discard silently |
| `OPERATIONAL_ERROR` | Trusted role using authorized function correctly | Discard with note (not a vulnerability) |
| `DESIGN_CHOICE` | Intentional architecture decision | Note in methodology, don't report as vuln |

**Sub-states (for internal tracking, not final verdict):**
- `CONFIRMED_REACHABLE` → All preconditions met at reachability gate (becomes CONFIRMED/PROBABLE after testing)
- `PENDING` → Initial state, awaiting analysis
- `FILTERED` → Passed Phase 1 intent filtering
- `MATCHED` → Has pattern match from Phase 2
- `TESTED` → Has execution trace from Phase 3

**⚠️ CRITICAL RULE**: All agent and plugin files MUST use these exact verdict values. No lowercase variants, no synonyms.

---

## Phase 0: INGESTION

### Objective
Read and parse all Trackator output files to build initial hypothesis list.

### Inputs Required
- `trackator-init.json` — Contract structure, functions, state variables, call graph
- `trackator-enrich.json` — Threat model, invariants, attack vectors, alert rules, money flows
- `trackator-analyze.json` (optional) — Runtime alerts if Foundry traces available

### Steps

#### Step 0.1: Validate Trackator Output

```javascript
function validateTrackatorOutput(outputDir) {
    const requiredFiles = ['trackator-init.json', 'trackator-enrich.json'];
    
    for (const file of requiredFiles) {
        if (!existsSync(`${outputDir}/${file}`)) {
            throw new Error(`Missing required file: ${file}`);
        }
    }
    
    const initData = readJson(`${outputDir}/trackator-init.json`);
    const enrichData = readJson(`${outputDir}/trackator-enrich.json`);
    
    // Validate structure
    if (!initData.contracts || !initData.contracts.length) {
        throw new Error('No contracts found in init data');
    }
    if (!enrichData.xray || !enrichData.xray.protocolType) {
        throw new Error('Missing protocol type in enrich data');
    }
    
    return { initData, enrichData };
}
```

#### Step 0.2: Build Priority-Ranked Hypothesis List

Extract all alerts from Trackator and rank by priority:

```javascript
function buildHypothesisList(enrichData) {
    const hypotheses = [];
    
    for (const alert of enrichData.alertRules || []) {
        const score = calculatePriorityScore(alert);
        
        hypotheses.push({
            id: `HYP_${alert.id}`,
            sourceAlert: alert,
            priorityScore: score,
            status: 'PENDING',  // PENDING → FILTERED → MATCHED → TESTED → CONFIRMED/DEAD
            phase: 0,  // Which phase created/last-touched this
            evidence: [],
            executionTrace: null,
            forkResult: null,
            createdAt: Date.now()
        });
    }
    
    // Sort by priority score descending
    return hypotheses.sort((a, b) => b.priorityScore - a.priorityScore);
}

function calculatePriorityScore(alert) {
    let score = 0;
    
    // Severity weighting
    if (alert.severity === 'critical') score += 30;
    else if (alert.severity === 'high') score += 20;
    else if (alert.severity === 'medium') score += 10;
    
    // Condition type weighting (pattern = strong signal)
    if (alert.condition?.type === 'pattern') score += 20;
    else if (alert.condition?.type === 'presence') score += 15;
    else if (alert.condition?.type === 'absence') score += 15;
    else if (alert.condition?.type === 'threshold') score += 10;
    
    // Source weighting (runtime/static > inferred)
    if (alert.source === 'runtime') score += 15;
    else if (alert.tier === 'tier1') score += 10;
    
    return score;
}
```

#### Step 0.3: Extract Protocol Context

Build context object for downstream phases:

```javascript
function extractProtocolContext(initData, enrichData) {
    const baseContext = {
        protocolType: enrichData.xray.protocolType,  // lending, dex, vault, etc.
        contracts: initData.contracts,
        assetsAtRisk: enrichData.xray.threatModel?.assetsAtRisk || [],
        entryPoints: enrichData.xray.threatModel?.entryPoints || [],
        invariants: enrichData.invariants || [],
        trustAssumptions: enrichData.xray.threatModel?.trustAssumptions || [],
        attackVectors: enrichData.xray.threatModel?.attackVectors || [],
        adversaryProfiles: enrichData.xray.threatModel?.adversaryProfiles || [],
        alertRules: enrichData.alertRules || [],
        components: enrichData.breakdown?.components || [],
        moneyFlows: enrichData.moneyFlows || []
    };
    
    // v2.0: Try to load enhanced Trackator output
    return { ...baseContext, ...extractEnhancedContext() };
}
```

#### Step 0.4: Extract Enhanced Trackator Data (v2.0 NEW)

```javascript
function extractEnhancedContext(outputDir) {
    const enhanced = {
        hasEnhancedData: false,
        storage: null,
        coupling: null,
        sync: null,
        evidence: null
    };
    
    try {
        // Phase 1: Storage Dependency Analyzer
        if (existsSync(`${outputDir}/trackator-storage.json`)) {
            enhanced.storage = readJson(`${outputDir}/trackator-storage.json`);
            enhanced.hasEnhancedData = true;
            console.log('✅ Loaded Storage Dependency Analyzer data');
            console.log(`   - ${enhanced.storage.variableWriters?.size || 0} variable writers mapped`);
            console.log(`   - ${enhanced.storage.contentedVariables?.length || 0} contended variables`);
            console.log(`   - ${enhanced.storage.valueBearingVariables?.length || 0} value-bearing variables`);
        }
        
        // Phase 2: State Coupling Detector
        if (existsSync(`${outputDir}/trackator-coupling.json`)) {
            enhanced.coupling = readJson(`${outputDir}/trackator-coupling.json`);
            enhanced.hasEnhancedData = true;
            console.log('✅ Loaded State Coupling Detector data');
            console.log(`   - ${Object.keys(enhanced.coupling.functionDependencyMatrix || {}).length}×${Object.keys(enhanced.coupling.functionDependencyMatrix || {}).length} function dependency matrix`);
            console.log(`   - ${enhanced.coupling.hiddenCouplings?.length || 0} hidden couplings found`);
        }
        
        // Phase 3: Sync Analyzer
        if (existsSync(`${outputDir}/trackator-sync.json`)) {
            enhanced.sync = readJson(`${outputDir}/trackator-sync.json`);
            enhanced.hasEnhancedData = true;
            console.log('✅ Loaded Sync Analyzer data');
            console.log(`   - ${enhanced.sync.criticalDesyncRisks?.length || 0} critical desync risks`);
            console.log(`   - ${enhanced.sync.syncRelationships?.length || 0} sync relationships mapped`);
        }
        
        // Phase 4: Evidence Validator
        if (existsSync(`${outputDir}/trackator-evidence.json`)) {
            enhanced.evidence = readJson(`${outputDir}/trackator-evidence.json`);
            enhanced.hasEnhancedData = true;
            console.log('✅ Loaded Evidence Validator data');
            console.log(`   - Classification registry with ${Object.keys(enhanced.evidence.classificationRegistry || {}).length} classes`);
        }
        
    } catch (error) {
        console.warn('⚠️ Error loading enhanced Trackator data:', error.message);
        console.warn('   Continuing in v1.0 compatibility mode');
    }
    
    return enhanced;
}
```

### Enhanced Context Structure (v2.0)

When enhanced data is available, the context object includes:

```javascript
{
    // ... base fields from Step 0.3 ...
    
    // Storage Dependency Analyzer (Trackator Phase 1)
    storage: {
        variableWriters: Map<string, Array<{          // varName → [writers]
            function: string,
            contract: string,
            writeReasonCategory: string,  // 'direct-user-action', 'protocol-admin', ...
            accessControlLevel: string,     // 'none', 'role-based', 'permissionless'
            ceiPatternMatch: boolean
        }>>,
        multiVariableWriters: Array<{        // Functions touching multiple vars
            function: string,
            variablesWritten: string[],
            isComplexStateChange: boolean
        }>,
        contentedVariables: Array<{         // Race condition candidates
            variable: string,
            writerCount: number,
            writers: Array<{ function, accessControlLevel }>
        }>,
        valueBearingVariables: Array<{       // Holds user funds!
            variable: string,
            type: string,                     // 'erc20-balance', 'lp-shares', 'collateral', ...
            location: string,
            estimatedValue?: string
        }>,
        sharedStateMatrix: Array<{          // permissionless × shared storage
            entryPoint: string,
            sharedVariables: string[],
            hasValueBearing: boolean,
            riskScore: number
        }>
    },
    
    // State Coupling Detector (Trackator Phase 2)
    coupling: {
        functionDependencyMatrix: object,     // N×N matrix: funcA → funcB coupling
        hiddenCouplings: Array({
            functionA: string,
            functionB: string,
            couplingType: 'transient' | 'conditional' | 'timestamp-dependent',
            sharedVariables: string[],
            strength: 'STRONG' | 'MEDIUM' | 'WEAK'
        }),
        invariantFunctionMap: {
            establishes: Map<string, string[]>,   // invariantId → [functions that establish]
            dependsOn: Map<string, string[]>,    // invariantId → [functions that depend]
            canViolate: Map<string, string[]>    // invariantId → [functions that can break]
        },
        storageVariableClassification: Map<string, {
            class: 'core' | 'derived' | 'control-flow' | 'metadata',
            reason: string
        }>,
        topIntersections: Array({             // Highest-value attack surfaces
            functionPair: [string, string],
            intersectionValue: number,
            sharedCriticalVars: string[],
            exploitationPotential: string
        })
    },
    
    // Sync Analyzer (Trackator Phase 3)
    sync: {
        assumptionDependencyGraph: {
            producers: Array<{ assumptionId, function, stalenessWindow }>,
            consumers: Array<{ assumptionId, function, validationGap }>,
            verifiers: Array<{ assumptionId, function, verificationType }>
        },
        desynchronizationAnalysis: {
            staleDataDetections: Array({ variable, validWindow, expiryCondition }),
            driftAnalysis: Array({ variable, expectedValue, actualValueRange }),
            missingVerifiers: Array({ assumptionId, consumerFunctions }),
            raceWindows: Array({ windowMs, exploitPrerequisite })
        },
        criticalDesyncRisks: Array({
            riskType: 'stale-price' | 'stale-approval' | 'state-drift' | 'missing-verifier' | 'race-window',
            severity: 'critical' | 'high' | 'medium',
            impact: string,
            attackScenario: string,
            producerFunction: string,
            consumerFunction: string,
            staleWindowMs: number,
            mitigationSuggestion: string
        }),
        syncRelationships: Array({
            id: string,
            producer: string,
            consumer: string,
            verifier: string | null,
            stalenessWindow: number,
            exploitability: number,  // 0-100
            attackComplexity: 'easy' | 'medium' | 'hard'
        })
    },
    
    // Evidence Validator (Trackator Phase 4)
    evidence: {
        classificationRegistry: {
            confirmedVulnerability: Array<{ findingId, criteriaMet }>,
            potentialVulnerability: Array<{ findingId, criteriaMet }>,
            falsePositive: Array<{ findingId, disproofEvidence }>,
            byDesign: Array<{ findingId, designRationale }>,
            informational: Array<{ findingId, note }>,
            cannotDetermine: Array<{ findingId, reason }>
        },
        reachabilityAnalysis: Array({
            findingId: string,
            executionPath: string[],
            prerequisites: Array({ condition, achievable, evidence }),
            blockers: Array({ type, description, bypassable }),
            gasCostEstimate: number,
            feasibleInSingleTx: boolean
        }),
        disproofEngine: {
            attemptedDisproofs: number,
            successfulDisproofs: number,  // False positives caught
            disproofEvidence: Array({ findingId, guardCodeFound, reasonSafe })
        },
        confidenceAssessments: Array({
            findingId: string,
            score: number,  // 0-100
            components: {
                patternMatchStrength: number,
                codeCoverage: number,
                historicalAccuracy: number,
                expertAdjustment: number
            }
        })
    }
}
```

### Phase 0 Output Artifacts

| Artifact | Format | Description |
|----------|--------|-------------|
| `hypotheses-initial.json` | JSON | Priority-ranked hypothesis list from Trackator alerts |
| `protocol-context.json` | JSON | Extracted protocol context for downstream use |
| `enhanced-context.json` | JSON | v2.0: Enhanced Trackator data (storage/coupling/sync/evidence) |

---

## Phase 1: INTENT FILTERING

### Objective
Kill false positives EARLY by comparing against intended behavior, design choices, and operational patterns.

### Plugin: Intended Behavior Plugin

**Purpose**: Determine if an alert points at intentional design rather than bug.

**Inputs**:
- Hypothesis list from Phase 0
- Trackator protocol context
- Protocol documentation (if available)

**Logic**:

```javascript
function intentFilter(hypothesis, context) {
    const alert = hypothesis.sourceAlert;
    
    // CHECK 1: Is this a known trust assumption?
    if (isTrustAssumptionViolation(alert, context.trustAssumptions)) {
        const assumption = findMatchingAssumption(alert, context.trustAssumptions);
        
        // If low confidence assumption AND enables attack chain → keep
        if (assumption.confidence === 'low' && enablesAttackChain(alert, context)) {
            return { verdict: 'keep', reason: 'Low-confidence assumption, attack-enabling' };
        }
        
        // Otherwise downgrade to info
        return { verdict: 'downgrade_to_info', reason: 'Known trust assumption' };
    }
    
    // CHECK 2: Does component responsibility explain this?
    const component = findComponentForField(alert, context.components);
    if (component && isWorkingAsDesigned(alert, component)) {
        return { verdict: 'discard', reason: 'Working as designed per component responsibility' };
    }
    
    // CHECK 3: Is this about trusted role using authorized function?
    if (isOperationalError(alert, context)) {
        return { verdict: 'discard', reason: 'Operational error: trusted role action' };
    }
    
    // CHECK 4: CRITICAL - Even if "intended", is it exploitable?
    if (isExploitableDesignChoice(alert, context)) {
        return { verdict: 'keep_with_note', reason: 'Design choice but exploitable' };
    }
    
    return { verdict: 'keep', reason: 'Genuine anomaly' };
}
```

**Trackator Field Mappings for Intent Filter**:

| Check | Trackator Fields Used |
|-------|----------------------|
| Trust assumption | `trustAssumptions[].category`, `trustAssumptions[].confidence` |
| Component responsibility | `components[].responsibility`, `components[].interfaces[].accessControl` |
| Operational error | `functions[].modifiers[]` (contains onlyRole/onlyOwner) |
| Exploitable design | `attackVectors[].prerequisite[]`, `entryPoints[].access` |

### Intent Filter Decision Matrix

| Alert Type | Has Access Control? | In Trust Assumptions? | Enables Attack Chain? | Verdict |
|------------|---------------------|------------------------|----------------------|---------|
| CEI violation | Yes (onlyRole) | No | No | `downgrade_to_info` |
| CEI violation | No | No | Yes | `keep` |
| Missing auth | N/A | N/A | Yes | `keep` (critical!) |
| Anomalous value change | Yes (admin) | Yes | No | `discard` (operational) |
| Oracle deviation | N/A | Yes (low conf) | Yes | `keep` |

### Phase 1 Output

Update hypotheses with filter results:

```javascript
hypothesis.status = 'FILTERED';  // or DISCARDED
hypothesis.intentFilterResult = {
    verdict: 'keep' | 'downgrade_to_info' | 'discard' | 'keep_with_note',
    reason: string,
    checkedAt: timestamp
};
```

Surviving hypotheses → Phase 2 input.

---

## Phase 2: PATTERN MATCHING

### Objective
Cross-reference surviving hypotheses against historical exploit pattern cards to find matches and assess reachability.

### Plugin: Pattern Matcher Plugin

**Purpose**: Match current alerts against known exploit patterns from Exploits-class-library.

**Input**: Exploits-class-library directory structure

**Library Structure**:
```
Exploits-class-library/
├── card-index.csv                    # All cards with metadata
├── protocol-type-to-exploit-patterns.json  # Protocol type → applicable patterns
└── exploit-pattern-cards/
    ├── reentrancy-state-update-after-external-call.md
    ├── flash-loan-spot-price-manipulation-single-tx.md
    ├── missing-modifier-privileged-function.md
    └── ... (56 total pattern cards)
```

**Pattern Matching Algorithm**:

```javascript
async function patternMatch(hypothesis, context, exploitsLibPath) {
    const protocolType = context.protocolType;
    const alert = hypothesis.sourceAlert;
    
    // Step 1: Get applicable patterns for this protocol type
    const applicablePatterns = loadPatternsForProtocolType(protocolType, exploitsLibPath);
    
    const matches = [];
    
    for (const pattern of applicablePatterns) {
        const matchScore = calculatePatternMatch(alert, pattern);
        
        if (matchScore > THRESHOLD) {
            matches.push({
                patternSlug: pattern.slug,
                primaryBugClass: pattern.primary_bug_class,
                matchScore: matchScore,
                representativeLoss: pattern.representative_loss_usd,
                detectionHeuristic: pattern.detection_heuristic,
                preconditionChain: pattern.precondition_chain
            });
        }
    }
    
    return matches.length > 0 ? matches : null;
}
```

**Match Scoring Factors**:

| Factor | Weight | Trackator Mapping |
|--------|--------|-------------------|
| Bug class match (reentrancy ↔ CEI violation) | 30% | `alert.category` ↔ `pattern.primary_bug_class` |
| Protocol type match | 25% | `context.protocolType` ↔ `pattern.protocol_types` |
| Detection heuristic match | 25% | `alert.condition` ↔ `pattern.detection_checklist` |
| Severity alignment | 10% | `alert.severity` ↔ historical loss |
| Prerequisite satisfaction | 10% | `context.entryPoints` ↔ `pattern.prerequisites` |

### v2.0 ENHANCED: Additional Scoring Factors (Factors 6-9)

When Trackator's enhanced analysis phases are available, the Pattern Matcher applies **4 additional scoring factors** via `calculateMatchScore_v2()` (see `plugins/pattern-matcher.md`):

| Factor | Weight | Source Data | Description |
|--------|--------|-------------|-------------|
| **Factor 6: Storage Dependency Alignment** | +10% bonus | `context.storage` | Does pattern target value-bearing variables with permissionless writers? |
| **Factor 7: State Coupling Signal** | +10% bonus | `context.coupling` | Does pattern exploit strong couplings between accessible functions? |
| **Factor 8: Synchronization Risk** | +10% bonus | `context.sync` | Is this a timing-based attack supported by desync analysis? |
| **Factor 9: Evidence Validator Pre-Classification** | adjusts confidence | `context.evidence` | Has this finding been pre-validated as confirmed/FP? |

**Maximum possible score with v2.0 bonuses**: 1.0 (base) + 0.35 (bonuses) = **1.35 (capped at 1.0)**

**Key v2.0 scoring functions**:
- `checkStorageAlignment(alert, pattern, storage)` → Returns 0-1 storage alignment score
- `checkCouplingSignal(alert, pattern, coupling)` → Returns 0-1 coupling signal score  
- `checkSyncRisk(alert, pattern, sync)` → Returns 0-1 sync risk score
- `checkPreClassification(alert, evidence)` → Returns {class, criteriaMet} for adjustment

### Example: Reentrancy Pattern Match

**Trackator Alert**:
```json
{
  "id": "ALERT_1",
  "name": "CEI Pattern Violation - Potential Reentrancy",
  "category": "reentrancy",
  "condition": { "type": "pattern", "field": "ceiPattern", "operator": "eq", "value": "violated" },
  "severity": "critical"
}
```

**Matching Exploit Card**: `reentrancy-state-update-after-external-call.md`

**Detection Heuristic from Card**:
> A function performs `.call{value: x}("")`, `.transfer()`, ERC20 transfer to externally-supplied address, and ONLY AFTER writes to balance/debt/share storage. Function lacks `nonReentrant` modifier.

**Match Result**:
```javascript
{
    patternSlug: 'reentrancy-state-update-after-external-call',
    primaryBugClass: 'reentrancy',
    matchScore: 0.92,  // High match!
    representativeLoss: 4750000,  // $4.75M from DeltaPrime
    detectionHeuristic: { signature: "...", grepPatterns: [...], checklist: [...] },
    preconditionChain: [
        "External call before state update",
        "No reentrancy guard OR wrong scope",
        "Attacker-controlled callback target",
        "Re-entry reads stale state"
    ]
}
```

### Plugin: Reachability Check (BLOCK GATE #1)

**Purpose**: Verify if matched pattern is actually reachable by attacker.

**IMPORTANT**: This is a **BLOCK GATE**, not kill gate!

```javascript
function reachabilityCheck(hypothesis, patternMatch, context) {
    const preconditions = patternMatch.preconditionChain;
    const satisfied = [];
    const unsatisfied = [];
    const unknown = [];
    
    for (const precondition of preconditions) {
        const result = checkPrecondition(precondition, context);
        
        if (result.satisfied) {
            satisfied.push(precondition);
        } else if (result.unsatisfied === false) {
            unsatisfied.push(precondition);  // Proven unreachable
        } else {
            unknown.push(precondition);  // Needs further testing
        }
    }
    
    // BLOCK GATE LOGIC: Don't kill, just grade
    if (unsatisfied.length > 0 && unknown.length === 0) {
        return {
            verdict: 'dead',
            reason: `Unsatisfied preconditions: ${unsatisfied.join(', ')}`,
            satisfiedPreconditions: satisfied,
            unsatisfiedPreconditions: unsatisfied
        };
    }
    
    if (satisfied.length === preconditions.length) {
        return {
            verdict: 'confirmed_pattern',
            reason: 'All preconditions satisfied',
            satisfiedPreconditions: satisfied,
            confidence: 'high'
        };
    }
    
    // Some unknowns → save for PoC
    return {
        verdict: unknown.length > satisfied.length ? 'lead' : 'probable',
        reason: `${satisfied.length}/${preconditions.length} satisfied, ${unknown.length} need testing`,
        satisfiedPreconditions: satisfied,
        unknownPreconditions: unknown,
        saveForPoC: true  // BLOCK GATE: Save, don't kill!
    };
}
```

**Reachability Checks Using Trackator Data**:

| Precondition Type | Trackator Fields to Check |
|-------------------|----------------------------|
| External call exists | `functions[].body.hasExternalCall === true` |
| No reentrancy guard | `functions[].modifiers[]` does NOT include `nonReentrant` |
| Attacker-controlled target | `functions[].parameters[]` includes address type, OR calls `msg.sender` |
| Public entry point | `entryPoints[].access === 'anyone'` |
| Value at risk | `assetsAtRisk[]` includes target asset |

### Phase 2 Output

```javascript
hypothesis.status = 'MATCHED';  // or DEAD if proven unreachable
hypothesis.patternMatches = [/* array of matches */];
hypothesis.reachabilityResult = {
    verdict: 'confirmed_pattern' | 'probable' | 'lead' | 'dead',
    preconditions: {/* satisfied/unsatisfied/unknown */},
    saveForPoC: boolean
};
```

---

## Phase 3: CREATIVE ATTACK

### Objective
**Where the Hacker agent lives.** Think like an attacker. Break assumptions. Follow value flows backwards. Find NEW vulnerabilities that pattern matching missed.

**v2.0 ENHANCED**: With Trackator's Storage Dependency Analyzer, State Coupling Detector, and Sync Analyzer data, the Hacker now has **weaponized intelligence** for:
- **Value-bearing variable topology** (Storage Dep.)
- **Function coupling graphs** (State Coupling)
- **Assumption dependency chains** (Sync Analyzer)

### Agent: Creative Hacker Agent

**Role**: Offensive mindset. Think like an attacker trying to steal value, brick protocol, or extract profit.

**Mindset Rules**:
1. "How would I steal from this protocol?"
2. "How would I brick it so users can't withdraw?"
3. "What edge states break core assumptions?"
4. "If I manipulate THIS input, what breaks downstream?"
5. **v2.0 NEW**: "Where's the money? Follow value-bearing variables to their writers"
6. **v2.0 NEW**: "What's coupled? Split atomic operations across transactions"
7. **v2.0 NEW**: "What's stale? Exploit assumption gaps between producer and consumer"

### Plugin: Reverse Engineering Plugin

**Purpose**: Follow Trackator value flows BACKWARDS to find manipulation points.

**Algorithm**:

```javascript
function reverseEngineer(context) {
    const creativeHypotheses = [];
    
    // Start from assets at risk
    for (const asset of context.assetsAtRisk) {
        console.log(`\n🎯 Targeting asset: ${asset.name} (${asset.type})`);
        
        // Find money flows involving this asset
        const relevantFlows = context.moneyFlows.filter(flow => 
            flow.involvesAsset(asset.name)
        );
        
        for (const flow of relevantFlows) {
            // Trace flow backwards
            const manipulationPoints = traceFlowBackwards(flow, context);
            
            for (const point of manipulationPoints) {
                creativeHypotheses.push({
                    id: `CREATIVE_${creativeHypotheses.length + 1}`,
                    type: 'reverse_engineering',
                    targetAsset: asset.name,
                    moneyFlow: flow.name,
                    manipulationPoint: point.function,
                    manipulationType: point.type,  // 'input', 'state', 'timing'
                    attackIdea: point.description,
                    sourcePhase: 3,
                    status: 'HYPOTHESIS',
                    createdAt: Date.now()
                });
            }
        }
    }
    
    return creativeHypotheses;
}

function traceFlowBackwards(moneyFlow, context) {
    const points = [];
    
    // For each step in the flow
    for (let i = moneyFlow.steps.length - 1; i >= 0; i--) {
        const step = moneyFlow.steps[i];
        
        // Can attacker influence this step's input?
        if (step.hasExternalInput) {
            points.push({
                function: step.function,
                type: 'input',
                description: `Manipulate ${step.inputName} before ${step.function}`
            });
        }
        
        // Does this step depend on manipulable state?
        if (step.dependsOnState) {
            const stateVar = step.stateDependency;
            
            // Check if state can be manipulated
            if (isStateManipulable(stateVar, context)) {
                points.push({
                    function: step.function,
                    type: 'state',
                    description: `Manipulate ${stateVar} to affect ${step.function} outcome`
                });
            }
        }
        
        // Timing attack possible?
        if (step.hasTimingDependency) {
            points.push({
                function: step.function,
                type: 'timing',
                description: `Front-run or sandwich ${step.function}`
            });
        }
    }
    
    return points;
}
```

**Example Reverse Engineering Attack Idea**:

From your Trackator data:
```
Asset: _balances (StakingRewards)
Flow: stake() → _balances[user] += amount

Manipulation Point:
- What if rewardPerTokenStored is manipulated BEFORE stake()?
- The earned() calculation uses rewardPerTokenStored
- If we manipulate it, we might get inflated rewards

Attack Idea: 
1. Call notifyRewardAmount() with huge amount (if accessible)
2. Immediately call stake()
3. rewardPerTokenStored spikes → our share of rewards inflates
4. Call getReward() → profit from inflated calculation
```

### Plugin: Assumption Breaker Plugin

**Purpose**: Systematically test each Trackator trust assumption to see if breaking it leads to exploitation.

**CRITICAL RULE**: Only test assumptions that can be broken by EXTERNAL attackers, not by trusted roles being malicious.

**v2.0 ENHANCED**: Now leverages Sync Analyzer's `assumptionDependencyGraph` and `criticalDesyncRisks` for precision targeting.

```javascript
function assumptionBreaker(context) {
    const attacks = [];
    
    // v2.0: Prioritize using Sync Analyzer's critical desync risks
    if (context.sync?.criticalDesyncRisks) {
        attacks.push(...breakCriticalDesyncRisks(context));
    }
    
    // Original: Test each trust assumption
    for (const assumption of context.trustAssumptions) {
        // Skip governance assumptions (trusted role)
        if (assumption.category === 'governance') continue;
        
        switch (assumption.category) {
            case 'oracle':
                attacks.push(...breakOracleAssumption(assumption, context));
                break;
                
            case 'external-contract':
                attacks.push(...breakExternalContractAssumption(assumption, context));
                break;
                
            case 'price-feed':
                attacks.push(...breakPriceFeedAssumption(assumption, context));
                break;
        }
    }
    
    return attacks;
}

// v2.0 NEW: Break critical desynchronization risks from Sync Analyzer
function breakCriticalDesyncRisks(context) {
    const attacks = [];
    
    for (const risk of context.sync.criticalDesyncRisks) {
        switch (risk.riskType) {
            case 'stale-price':
                attacks.push({
                    id: `DESYNC_STALE_${risk.producerFunction}`,
                    type: 'stale_price_exploitation',
                    description: `Exploit stale ${risk.producerFunction} price in ${risk.consumerFunction} (${risk.staleWindowMs}ms window)`,
                    attackScenario: risk.attackScenario,
                    prerequisiteChain: [
                        `${risk.producerFunction} sets price with staleness window of ${risk.staleWindowMs}ms`,
                        `${risk.consumerFunction} reads price without freshness check`,
                        'Attacker can manipulate price between producer write and consumer read',
                        'No heartbeat/timestamp validation on consumer side'
                    ],
                    trackatorEvidence: {
                        syncAnalyzerRiskId: risk.id,
                        staleWindowMs: risk.staleWindowMs,
                        severity: risk.severity
                    },
                    estimatedImpact: risk.impact,
                    feasibility: risk.attackComplexity.toLowerCase()
                });
                break;
                
            case 'missing-verifier':
                attacks.push({
                    id: `DESYNC_NOVERIFY_${risk.assumptionId}`,
                    type: 'unverified_assumption_exploitation',
                    description: `Exploit unverified assumption in ${risk.consumerFunction} - no verifier exists`,
                    prerequisiteChain: [
                        'Assumption established by producer function',
                        'Consumer function uses assumption without verification',
                        'Attacker can invalidate assumption between establish and use',
                        'No verification function exists in codebase'
                    ],
                    trackatorEvidence: {
                        syncAnalyzerRiskId: risk.id,
                        missingVerifier: true
                    },
                    estimatedImpact: 'High - assumption violations undetected',
                    feasibility: 'medium'
                });
                break;
                
            case 'race-window':
                attacks.push({
                    id: `DESYNC_RACE_${risk.producerFunction}`,
                    type: 'race_condition_exploitation',
                    description: `Exploit race window in ${risk.consumerFunction} dependent on ${risk.producerFunction}`,
                    prerequisiteChain: [
                        `Race window exists: ${risk.staleWindowMs}ms`,
                        'Attacker can execute transactions within window',
                        'State change during window enables exploitation',
                        'No mutex/lock protecting the critical section'
                    ],
                    trackatorEvidence: {
                        syncAnalyzerRiskId: risk.id,
                        raceWindowMs: risk.staleWindowMs
                    },
                    estimatedImpact: risk.impact,
                    feasibility: risk.attackComplexity.toLowerCase()
                });
                break;
        }
    }
    
    return attacks;
}
```

function breakOracleAssumption(assumption, context) {
    const attacks = [];
    
    // Attack 1: Flash loan price manipulation
    attacks.push({
        id: `AB_ORACLE_1`,
        assumptionId: assumption.id,
        type: 'flash_loan_price_manipulation',
        description: `Flash loan to swing oracle price beyond threshold (${assumption.mitigation})`,
        prerequisiteChain: [
            'Protocol uses single-source oracle',
            'Oracle reads spot price (no TWAP)',
            'Flash loan size sufficient to move price',
            'Price move occurs within same transaction as vulnerable operation'
        ],
        trackatorEvidence: {
            relevantAlerts: findAlertsByCategory(context.alertRules, 'oracle-manipulation'),
            assetsTargeted: context.assetsAtRisk.filter(a => a.type === 'erc20'),
            moneyFlows: context.moneyFlows.filter(f => f.involvesPriceRead())
        }
    });
    
    // Attack 2: Multi-block manipulation (if no heartbeat)
    attacks.push({
        id: `AB_ORACLE_2`,
        assumptionId: assumption.id,
        type: 'multi_block_manipulation',
        description: `Sustained price manipulation across multiple blocks if no heartbeat check`,
        // ... similar structure
    });
    
    return attacks;
}
```

**Allowed vs Disallowed Assumption Breaks**:

| Category | Allowed to Test? | Reason |
|----------|------------------|--------|
| Oracle prices | ✅ YES | External market force |
| External contract behavior | ✅ YES | May have bugs, may be upgradeable |
| Price feed timeliness | ✅ YES | MEV/front-runnable |
| Governance capture | ❌ NO | Trusted role |
| Admin key compromise | ❌ NO | Operational security |
| Keeper misbehavior | ❌ NO | Trusted role |

### ★ MANDATORY: Full Execution Trace

**BEFORE escalating ANY creative hypothesis to Verifier, Hacker MUST complete full execution trace.**

```javascript
function buildExecutionTrace(hypothesis, context) {
    const trace = {
        hypothesisId: hypothesis.id,
        steps: [],
        finalState: null,
        conclusion: null,
        completed: false
    };
    
    // Get starting function
    let currentFunction = hypothesis.entryFunction || hypothesis.manipulationPoint;
    let callStack = [currentFunction];
    let visited = new Set();
    
    // Trace until we return to caller
    while (callStack.length > 0) {
        const func = callStack[callStack.length - 1];
        
        if (visited.has(func)) {
            // Cycle detected - note it
            trace.steps.push({
                function: func,
                type: 'cycle_detected',
                note: 'Already visited this function in current trace'
            });
            callStack.pop();
            continue;
        }
        
        visited.add(func);
        
        const funcData = findFunctionByName(func, context.contracts);
        
        if (!funcData) {
            trace.steps.push({ function: func, type: 'external_or_unknown' });
            callStack.pop();
            continue;
        }
        
        // Record this step
        trace.steps.push({
            function: func,
            contract: funcData.contractName,
            modifiers: funcData.modifiers,
            hasExternalCall: funcData.body?.hasExternalCall,
            ceiPattern: funcData.body?.ceiPattern,
            stateVariablesRead: funcData.stateVariablesRead,
            stateVariablesWritten: funcData.stateVariablesWritten,
            calls: funcData.calls
        });
        
        // Follow external calls (potential reentrancy)
        if (funcData.body?.hasExternalCall) {
            trace.steps[trace.steps.length - 1].note = 
                '⚠️ EXTERNAL CALL HERE - potential reentrancy point';
        }
        
        // Follow internal calls (continue tracing)
        for (const calledFunc of funcData.calls) {
            if (isInternalFunction(calledFunc, context)) {
                callStack.push(calledFunc);
            }
        }
        
        // If no more internal calls to follow, pop stack
        if (!funcData.calls.some(c => isInternalFunction(c, context))) {
            callStack.pop();
        }
        
        // Safety: prevent infinite traces
        if (trace.steps.length > 100) {
            trace.steps.push({ type: 'trace_limit_reached', note: 'Trace exceeded 100 steps' });
            break;
        }
    }
    
    // Analyze trace for issues
    trace.finalState = analyzeFinalState(trace);
    trace.conclusion = drawConclusion(trace, hypothesis);
    trace.completed = true;
    
    return trace;
}

function drawConclusion(trace, hypothesis) {
    // Check if hypothesis survives full trace
    
    // Example: If hypothesis was "reentrancy in A"
    // But trace shows B (called after A) has nonReentrant guard
    // Then hypothesis might be mitigated
    
    const externalCalls = trace.steps.filter(s => s.hasExternalCall);
    const stateUpdatesAfterCalls = trace.steps.filter(s => 
        s.stateVariablesWritten?.length > 0 && 
        occurredAfter(externalCalls, s)
    );
    
    if (externalCalls.length > 0 && stateUpdatesAfterCalls.length > 0) {
        return {
            survives: true,
            reason: 'External calls occur before some state updates - reentrancy possible',
            severity: 'high'
        };
    }
    
    // Check for guards
    const guardsFound = trace.steps.some(s => 
        s.modifiers?.includes('nonReentrant')
    );
    
    if (guardsFound && externalCalls.length > 0) {
        return {
            survives: false,
            reason: 'nonReentrant guard present along call path',
            severity: 'mitigated'
        };
    }
    
    return { survives: true, reason: 'No obvious mitigation found in trace', severity: 'medium' };
}
```

### Plugin: State Coupling Analysis (v2.0 NEW → v2.1 ENHANCED)

**Purpose**: Use Trackator's State Coupling Detector data to find **coupling-based attack vectors** that don't appear in individual function analysis.

**v2.1 ENHANCEMENT (Fix A Integration)**: Now consumes ALL output fields from enhanced `state-coupling-detector.ts`:
- ✅ `functionDependencyMatrix` with `couplingClusters[]`, `statistics`
- ✅ `hiddenCouplings[]` with 13 coupling types (not just transient)
- ✅ `invariantFunctionMap` with `violationPaths[]`, `protectionGaps[]`
- ✅ `variableClassification[]` for targeted variable attacks
- ✅ `topStateIntersections[]` with full participant analysis
- ✅ `hiddenAssumptions[]` with exploitability-based prioritization
- ✅ `criticalFindings[]` as priority queue (quick access array)

**Philosophy**: > *"Two functions that share state are safer than they look—until you realize an attacker can call both in one transaction. And clusters of coupled functions? Those are attack surfaces waiting to happen."*

**When Enhanced Data Available** (`context.coupling` exists):

```javascript
function stateCouplingAnalysis(context) {
    if (!context.coupling) {
        console.log('⚠️ No coupling data available - skipping coupling analysis');
        return [];
    }
    
    const attacks = [];
    const { 
        functionDependencyMatrix, 
        hiddenCouplings, 
        invariantFunctionMap, 
        topStateIntersections,  // Renamed from topIntersections for precision
        variableClassification,
        hiddenAssumptions,
        criticalFindings  // v2.1 NEW: Quick-access priority array
    } = context.coupling;
    
    // ═══════════════════════════════════════════════════════════════
    // v2.1 NEW: PRIORITY 0 - Critical Findings Queue (Quick Access)
    // ═══════════════════════════════════════════════════════════════
    // Trackator pre-computes critical findings - consume them first!
    if (criticalFindings && criticalFindings.length > 0) {
        for (const finding of criticalFindings.filter(f => f.severity === 'critical' || f.severity === 'high')) {
            attacks.push({
                id: `CRITICAL_${finding.id}`,
                type: `critical_${finding.type}`,  // coupling | violation-path | protection-gap | assumption | classification
                title: finding.title,
                description: finding.description,
                location: finding.location,
                impact: finding.impact,
                remediation: finding.remediation,
                evidence: finding.evidence,
                priority: finding.priority === 'immediate' ? 100 : finding.priority === 'short-term' ? 80 : 60,
                trackatorEvidence: {
                    source: 'criticalFindings[]',
                    originalFinding: finding
                },
                estimatedDifficulty: mapSeverityToDifficulty(finding.severity),
                status: 'HYPOTHESIS',
                sourcePhase: 'coupling-critical-findings'  // v2.1 NEW
            });
        }
        console.log(`✅ v2.1: Loaded ${criticalFindings.length} critical findings from coupling analysis`);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ATTACK PATTERN 1: Strong Coupling + Permissionless Entry
    // ═══════════════════════════════════════════════════════════════
    // v2.1 ENHANCED: Now uses matrix.dependencies Map structure correctly
    const matrix = functionDependencyMatrix;
    
    // 1a: Check coupling clusters first (v2.1 NEW)
    if (matrix.couplingClusters && matrix.couplingClusters.length > 0) {
        for (const cluster of matrix.couplingClusters.filter(c => c.riskLevel === 'critical' || c.riskLevel === 'high')) {
            // Cluster attacks: multiple functions sharing state
            const permFunctionsInCluster = cluster.functions.filter(f => 
                matrix.functions.find(mf => mf.id === f)?.isPermissionless
            );
            
            if (permFunctionsInCluster.length >= 1) {
                attacks.push({
                    id: `CLUSTER_${cluster.clusterId}`,
                    type: 'coupling_cluster_exploitation',  // v2.1 NEW TYPE
                    description: `Exploit COUPLING CLUSTER: ${cluster.functions.length} functions tightly coupled through ${cluster.sharedVariables.length} shared variables (cohesion: ${cluster.cohesionScore})`,
                    attackIdea: `Cluster has ${permFunctionsInCluster.length} permissionless entry points. Manipulate shared state via one function, affect computations in others.`,
                    prerequisiteChain: [
                        `Cluster ${cluster.clusterId}: ${cluster.functions.join(', ')}`,
                        `Shared variables: ${cluster.sharedVariables.slice(0, 5).join(', ')}${cluster.sharedVariables.length > 5 ? ' +' + (cluster.sharedVariables.length - 5) + ' more' : ''}`,
                        `Cohesion score: ${cluster.cohesionScore} (${cluster.riskLevel} risk)`,
                        `${permFunctionsInCluster.length} permissionless functions in cluster`,
                        'No cluster-level atomicity or mutex protection'
                    ],
                    trackatorEvidence: {
                        clusterId: cluster.clusterId,
                        functions: cluster.functions,
                        sharedVariables: cluster.sharedVariables,
                        cohesionScore: cluster.cohesionScore,
                        riskLevel: cluster.riskLevel,
                        permissionlessEntries: permFunctionsInCluster
                    },
                    estimatedDifficulty: permFunctionsInCluster.length > 1 ? 'easy' : 'medium',
                    status: 'HYPOTHESIS',
                    priorityBoost: cluster.riskLevel === 'critical' ? 30 : 15  // v2.1: Higher boost for clusters
                });
            }
        }
        console.log(`✅ v2.1: Analyzed ${matrix.couplingClusters.length} coupling clusters`);
    }
    
    // 1b: Original strong coupling detection (enhanced with proper matrix structure)
    if (matrix.dependencies) {
        for (const [depKey, depRelation] of matrix.dependencies.entries()) {
            // v2.1: Use DependencyRelation structure properly
            if (depRelation.couplingStrength >= 70) {  // Numeric threshold from Fix A
                const { sourceFunction, targetFunction } = depRelation;
                
                const srcFuncInfo = matrix.functions.find(f => f.id === sourceFunction);
                const tgtFuncInfo = matrix.functions.find(f => f.id === targetFunction);
                
                const aAccessible = srcFuncInfo?.isPermissionless;
                const bAccessible = tgtFuncInfo?.isPermissionless;
                
                if (aAccessible || bAccessible) {
                    // v2.1: Use variableClassification for value-bearing check
                    const hasValueBearing = depRelation.sharedVariables.some(v => {
                        const varClass = variableClassification?.classifications?.find(vc => vc.variableName === v);
                        return varClass?.primaryCategory === 'accounting' || 
                               varClass?.primaryCategory === 'liquidity' ||
                               varClass?.primaryCategory === 'solvency';
                    }) || depRelation.sharedVariables.some(v => 
                        /balance|supply|debt|collateral|reserve/i.test(v)
                    );
                    
                    if (hasValueBearing || depRelation.sharedVariables.length >= 3) {
                        attacks.push({
                            id: `COUPLING_STRONG_${sourceFunction.replace('.', '_')}_${targetFunction.replace('.', '_')}`,
                            type: 'strong_coupling_exploitation',
                            description: `Exploit STRONG coupling (${depRelation.couplingStrength}/100) between ${sourceFunction} → ${targetFunction} [${depRelation.dependencyType}] - shared: ${depRelation.sharedVariables.join(', ')}`,
                            attackIdea: `Call ${aAccessible ? sourceFunction : targetFunction} to manipulate shared state, then immediately call the other function which assumes state is unchanged`,
                            prerequisiteChain: [
                                `${sourceFunction} and ${targetFunction} share ${depRelation.sharedVariables.length} variables via ${depRelation.dependencyType}`,
                                `At least one function is permissionless: ${aAccessible ? sourceFunction : targetFunction}`,
                                `Risk factors: ${depRelation.riskFactors.join(', ')}`,
                                depRelation.isCrossContract ? '⚠️ Cross-contract dependency increases exploit complexity' : 'Same-contract attack',
                                'No atomicity guard between calls'
                            ],
                            trackatorEvidence: {
                                couplingStrength: depRelation.couplingStrength,
                                dependencyType: depRelation.dependencyType,
                                sharedVariables: depRelation.sharedVariables,
                                valueBearingInvolved: hasValueBearing,
                                riskFactors: depRelation.riskFactors,
                                isCrossContract: depRelation.isCrossContract,
                                matrixEntry: depRelation
                            },
                            estimatedDifficulty: (aAccessible && bAccessible) ? 'easy' : (depRelation.isCrossContract ? 'hard' : 'medium'),
                            status: 'HYPOTHESIS'
                        });
                    }
                }
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ATTACK PATTERN 2: Hidden Couplings (ALL 13 types, not just transient)
    // ═══════════════════════════════════════════════════════════════
    // v2.1 ENHANCED: Now handles ALL HiddenCouplingType values from Fix A
    const EXPLOITABLE_COUPLING_TYPES = [
        'proxy-storage-conflict',        // High severity: storage collision
        'delegatecall-context-leak',     // High severity: full context exposure
        'callback-state-dependence',     // Medium-high: reentrancy vector
        'storage-slot-collision',        // High: manual slot conflicts
        'cross-contract-assumed-state',  // Medium: external state assumption
        'struct-layout-assumption',      // Medium: upgrade vulnerability
        'transient',                     // Original: timing-dependent
        'timestamp-dependent',           // MEV/front-run capable
        'inheritance-storage-overlap',   // Proxy pattern issues
        'library-storage-sharing',       // Library context manipulation
        'multi-contract-consistency',   // Desync across contracts
        'protocol-dependent',           // Cross-protocol assumptions
        'immutable-pattern-violation'   // Should-be-immutable vars
    ];
    
    if (hiddenCouplings && hiddenCouplings.couplings) {
        for (const hidden of hiddenCouplings.couplings) {
            // v2.1: Filter by exploitable types AND severity
            if (EXPLOITABLE_COUPLING_TYPES.includes(hidden.type) && 
                (hidden.severity === 'critical' || hidden.severity === 'high')) {
                
                // v2.1: Use detectionConfidence and exploitationScenario from Fix A
                if (hidden.detectionConfidence !== 'speculative') {
                    attacks.push({
                        id: `COUPLING_HIDDEN_${hidden.type}_${hidden.source.contract}_${(hidden.source.function || 'unknown')}`,
                        type: `hidden_coupling_${hidden.type}`,  // v2.1: Specific type in ID
                        description: `[${hidden.severity.toUpperCase()}] ${hidden.type.replace(/-/g, ' ')}: ${hidden.description}`,
                        attackIdea: hidden.exploitationScenario || `Exploit ${hidden.type} coupling between ${hidden.source.function || '*'} → ${hidden.target.function || '*'}. Mechanism: ${hidden.mechanism}`,
                        prerequisiteChain: [
                            `Hidden coupling type: ${hidden.type}`,
                            `Source: ${hidden.source.contract}.${hidden.source.function || '(contract level)'}`,
                            `Target: ${hidden.target.contract}.${hidden.target.function || '(contract level)'}`,
                            `Shared state: ${hidden.stateState?.join(', ') || 'implicit via mechanism'}`,
                            `Detection confidence: ${hidden.detectionConfidence}`,
                            hidden.recommendation ? `Mitigation hint: ${hidden.recommendation}` : 'No known mitigation'
                        ],
                        trackatorEvidence: {
                            couplingType: hidden.type,
                            severity: hidden.severity,
                            source: hidden.source,
                            target: hidden.target,
                            mechanism: hidden.mechanism,
                            detectionConfidence: hidden.detectionConfidence,
                            exploitationScenario: hidden.exploitationScenario
                        },
                        estimatedDifficulty: hidden.severity === 'critical' ? 'medium' : 'hard',
                        status: 'HYPOTHESIS',
                        priorityBoost: hidden.severity === 'critical' ? 25 : 10
                    });
                }
            }
        }
        console.log(`✅ v2.1: Analyzed ${hiddenCouplings.couplings.length} hidden couplings, found ${hiddenCouplings.summary.criticalCount} critical`);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ATTACK PATTERN 3: Invariant Violation Paths (v2.1: Pre-computed paths)
    // ═══════════════════════════════════════════════════════════════
    // v2.1 NEW: Consume violationPaths[] from invariantFunctionMap (Fix A output)
    if (invariantFunctionMap && invariantFunctionMap.violationPaths) {
        for (const vPath of invariantFunctionMap.violationPaths) {
            // Only include paths that are feasible (not impossible)
            if (vPath.feasibility !== 'impossible') {
                attacks.push({
                    id: `VIOL_PATH_${vPath.pathId}`,
                    type: 'invariant_violation_path',  // v2.1 NEW TYPE
                    description: `[${vPath.feasibility.toUpperCase()}] Violation path for invariant ${vPath.invariantId}: ${vPath.impactIfViolated}`,
                    attackIdea: `Execute violation path: ${vPath.executionSteps.map(s => s.action + '→' + (s.variable || s.function)).join(' → ')}`,
                    prerequisiteChain: [
                        `Invariant: ${vPath.invariantId}`,
                        `Entry function: ${vPath.entryFunction}`,
                        `Feasibility: ${vPath.feasibility}`,
                        `Impact if violated: ${vPath.impactIfViolated}`,
                        ...vPath.prerequisiteState.map(ps => `- Prerequisite: ${ps}`),
                        `Execution steps: ${vPath.executionSteps.length} steps defined`
                    ],
                    trackatorEvidence: {
                        pathId: vPath.pathId,
                        invariantId: vPath.invariantId,
                        entryFunction: vPath.entryFunction,
                        feasibility: vPath.feasibility,
                        impactIfViolated: vPath.impactIfViolated,
                        executionSteps: vPath.executionSteps,
                        prerequisiteState: vPath.prerequisiteState
                    },
                    estimatedDifficulty: vPath.feasibility === 'trivial' ? 'easy' : 
                                         vPath.feasibility === 'easy' ? 'easy' :
                                         vPath.feasibility === 'moderate' ? 'medium' : 'hard',
                    status: 'HYPOTHESIS',
                    priorityBoost: vPath.feasibility === 'trivial' || vPath.feasibility === 'easy' ? 20 : 5
                });
            }
        }
        console.log(`✅ v2.1: Loaded ${invariantFunctionMap.violationPaths.length} invariant violation paths`);
    }
    
    // Also keep original invariant chain logic (complementary)
    if (invariantFunctionMap) {
        // v2.1: Use mappings array structure from Fix A
        const canViolateMap = {};
        const dependsOnMap = {};
        
        // Build lookup maps from mappings array (Fix A structure)
        if (invariantFunctionMap.mappings) {
            for (const mapping of invariantFunctionMap.mappings) {
                // Index violators by invariant
                for (const violator of mapping.potentialViolators) {
                    if (!canViolateMap[mapping.invariantId]) {
                        canViolateMap[mapping.invariantId] = [];
                    }
                    canViolateMap[mapping.invariantId].push(violator.functionId);
                }
                
                // Index dependers by invariant
                for (const depender of mapping.dependers) {
                    if (!dependsOnMap[mapping.invariantId]) {
                        dependsOnMap[mapping.invariantId] = [];
                    }
                    dependsOnMap[mapping.invariantId].push(depender.functionId);
                }
            }
        }
        
        for (const [invId, violators] of Object.entries(canViolateMap)) {
            if (violators.length > 1) {
                const dependers = dependsOnMap[invId] || [];
                for (let i = 0; i < violators.length; i++) {
                    for (let j = 0; j < violators.length; j++) {
                        if (i !== j && dependers.includes(violators[j])) {
                            attacks.push({
                                id: `INV_CHAIN_${invId}_${violators[i].replace('.', '_')}_${violators[j].replace('.', '_')}`,
                                type: 'invariant_violation_chain',
                                description: `Chain: ${violators[i]} breaks invariant ${invId}, then ${violators[j]} which depends on it produces wrong result`,
                                attackIdea: `Call ${violators[i]} to invalidate ${invId}, then immediately call ${violators[j]} before invariant is re-established`,
                                prerequisiteChain: [
                                    `${violators[i]} can violate invariant ${invId}`,
                                    `${violators[j]} depends on invariant ${invId} being valid`,
                                    'No re-validation of invariant between calls',
                                    'Both functions accessible to attacker (or one sets up state for other)'
                                ],
                                trackatorEvidence: {
                                    invariantId: invId,
                                    violator: violators[i],
                                    dependent: violators[j],
                                    invariantSeverity: 'critical'
                                },
                                estimatedDifficulty: 'medium',
                                status: 'HYPOTHESIS'
                            });
                        }
                    }
                }
            }
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ATTACK PATTERN 3.5: Protection Gap Exploitation (v2.1 NEW)
    // ═══════════════════════════════════════════════════════════════
    // v2.1 NEW: Consume protectionGaps[] - find invariants without protection
    if (invariantFunctionMap && invariantFunctionMap.protectionGaps) {
        for (const gap of invariantFunctionMap.protectionGaps.filter(g => g.severity === 'critical' || g.severity === 'high')) {
            attacks.push({
                id: `PROTECT_GAP_${gap.gapId}`,
                type: 'protection_gap_exploitation',  // v2.1 NEW TYPE
                description: `[${gap.severity.toUpperCase()}] Protection Gap: ${gap.missingProtection} for invariant ${gap.invariantId}`,
                attackIdea: `Exploit missing protection: ${gap.missingProtection}. Affected functions: ${gap.affectedFunctions.join(', ')}. Recommended fix: ${gap.recommendedFix}`,
                prerequisiteChain: [
                    `Invariant ${gap.invariantId} has protection gap`,
                    `Missing protection: ${gap.missingProtection}`,
                    `Affected functions: ${gap.affectedFunctions.join(', ')}`,
                    gap.recommendedFix ? `Known fix not yet applied: ${gap.recommendedFix}` : 'No fix documented'
                ],
                trackatorEvidence: {
                    gapId: gap.gapId,
                    invariantId: gap.invariantId,
                    missingProtection: gap.missingProtection,
                    affectedFunctions: gap.affectedFunctions,
                    recommendedFix: gap.recommendedFix,
                    severity: gap.severity
                },
                estimatedDifficulty: gap.severity === 'critical' ? 'easy' : 'medium',
                status: 'HYPOTHESIS',
                priorityBoost: gap.severity === 'critical' ? 30 : 15
            });
        }
        console.log(`✅ v2.1: Found ${invariantFunctionMap.protectionGaps.length} protection gaps`);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ATTACK PATTERN 4: Top State Intersections (Enhanced with participants)
    // ═══════════════════════════════════════════════════════════════
    // v2.1 ENHANCED: Now uses full IntersectionParticipant data
    for (const intersection of (topStateIntersections?.intersections || []).slice(0, 5)) {
        // v2.1: Analyze participant access patterns
        const permParticipants = intersection.functions.filter(p => p.isPermissionless);
        const writerParticipants = intersection.functions.filter(p => p.role === 'writer' || p.role === 'both');
        
        attacks.push({
            id: `COUPLING_TOP_${intersection.rank}`,
            type: 'high_value_intersection',
            description: `Top-${intersection.rank} value intersection (${intersection.intersectionType}): ${intersection.functions.map(f => f.functionId).join(' ↔ ')} (risk: ${intersection.riskScore}/100, value at risk: ${intersection.valueAtRisk})`,
            attackIdea: intersection.exploitationPotential || intersection.specificFindings?.[0] || 'Exploit high-value state intersection',
            prerequisiteChain: [
                `Intersection type: ${intersection.intersectionType}`,
                `Variables involved: ${intersection.variables.join(', ')}`,
                `Contracts: ${intersection.contracts.join(', ')}`,
                `Risk score: ${intersection.riskScore}/100`,
                `Value at risk: ${intersection.valueAtRisk}`,
                `Exploitation complexity: ${intersection.exploitationComplexity}`,
                `Permissionless participants: ${permParticipants.length}/${intersection.functions.length}`,
                `Writer participants: ${writerParticipants.map(p => p.functionId).join(', ')}`
            ],
            trackatorEvidence: {
                rank: intersection.rank,
                intersectionType: intersection.intersectionType,
                variables: intersection.variables,
                contracts: intersection.contracts,
                riskScore: intersection.riskScore,
                valueAtRisk: intersection.valueAtRisk,
                exploitationComplexity: intersection.exploitationComplexity,
                participants: intersection.functions,  // v2.1: Full participant data
                specificFindings: intersection.specificFindings,
                recommendations: intersection.recommendations
            },
            estimatedDifficulty: intersection.exploitationComplexity,
            status: 'HYPOTHESIS',
            priorityBoost: 20 + (permParticipants.length > 0 ? 10 : 0)  // v2.1: Extra boost if permissionless access
        });
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ATTACK PATTERN 5: Hidden Assumption Exploitation (v2.1 NEW)
    // ═══════════════════════════════════════════════════════════════
    // v2.1 NEW: Leverage hiddenAssumptions[] with exploitability ratings
    if (hiddenAssumptions && hiddenAssumptions.assumptions) {
        // Sort by exploitability (trivial > easy > moderate > difficult)
        const sortedAssumptions = [...hiddenAssumptions.assumptions].sort((a, b) => {
            const order = { 'trivial': 4, 'easy': 3, 'moderate': 2, 'difficult': 1 };
            return (order[b.exploitability] || 0) - (order[a.exploitability] || 0);
        });
        
        for (const assumption of sortedAssumptions.slice(0, 10)) {  // Top 10 most exploitable
            if (assumption.exploitability === 'trivial' || assumption.exploitability === 'easy') {
                attacks.push({
                    id: `ASSUMP_${assumption.id}`,
                    type: 'hidden_assumption_exploitation',  // v2.1 NEW TYPE
                    description: `[${assumption.severity.toUpperCase()}] Hidden assumption: "${assumption.assumption}" - if wrong: ${assumption.ifWrong}`,
                    attackIdea: `Exploit assumption violation. Detectability: ${assumption.detectability}. Exploitability: ${assumption.exploitability}. Location: ${assumption.location.contract}.${assumption.location.function || '*'}`,
                    prerequisiteChain: [
                        `Assumption: ${assumption.assumption}`,
                        `Category: ${assumption.category}`,
                        `Held by: ${assumption.heldBy.join(', ')}`,
                        `Validated by: ${assumption.validatedBy.length > 0 ? assumption.validatedBy.join(', ') : '❌ NOT VALIDATED'}`,
                        `If wrong: ${assumption.ifWrong}`,
                        `Detectability: ${assumption.detectability}`,
                        `Exploitability: ${assumption.exploitability}`
                    ],
                    trackatorEvidence: {
                        assumptionId: assumption.id,
                        category: assumption.category,
                        detectability: assumption.detectability,
                        exploitability: assumption.exploitability,
                        validatedBy: assumption.validatedBy,
                        recommendation: assumption.recommendation
                    },
                    estimatedDifficulty: assumption.exploitability,
                    status: 'HYPOTHESIS',
                    priorityBoost: assumption.exploitability === 'trivial' ? 25 :
                                 assumption.exploitability === 'easy' ? 15 : 5
                });
            }
        }
        console.log(`✅ v2.1: Analyzed ${hiddenAssumptions.assumptions.length} hidden assumptions, highly exploitable count: ${sortedAssumptions.filter(a => a.exploitability === 'trivial' || a.exploitability === 'easy').length}`);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ATTACK PATTERN 6: Variable Classification Targeting (v2.1 NEW)
    // ═══════════════════════════════════════════════════════════════
    // v2.1 NEW: Target sensitive variables based on classification
    if (variableClassification && variableClassification.classifications) {
        const sensitiveVars = variableClassification.classifications.filter(v => 
            v.securitySensitivity === 'critical' || v.securitySensitivity === 'high'
        );
        
        for (const sensVar of sensitiveVars.slice(0, 8)) {  // Top 8 most sensitive
            // Find permissionless writers for this variable
            const permWriters = sensVar.writerFunctions.filter(wf => {
                const funcInfo = matrix.functions.find(f => f.id === wf);
                return funcInfo?.isPermissionless;
            });
            
            if (permWriters.length > 0) {
                attacks.push({
                    id: `VAR_TARGET_${sensVar.variableName}_${sensVar.contract}`,
                    type: 'sensitive_variable_targeting',  // v2.1 NEW TYPE
                    description: `[${sensVar.securitySensitivity.toUpperCase()}] Target classified variable: ${sensVar.variableName} (${sensVar.primaryCategory}) in ${sensVar.contract}`,
                    attackIdea: `Variable classified as ${sensVar.primaryCategory}/${sensVar.secondaryCategories.join('/')}. Has ${permWriters.length} permissionless writers: ${permWriters.join(', ')}. Integrity requirement: ${sensVar.integrityRequirement}.`,
                    prerequisiteChain: [
                        `Variable: ${sensVar.variableName} (${sensVar.type})`,
                        `Classification: ${sensVar.primaryCategory} - ${sensVar.classificationRationale}`,
                        `Security sensitivity: ${sensVar.securitySensitivity}`,
                        `Integrity requirement: ${sensVar.integrityRequirement}`,
                        `Permissionless writers: ${permWriters.join(', ')}`,
                        `Reader functions: ${sensVar.readerFunctions.length} readers may trust this value`,
                        sensVar.crossContractImpact.length > 0 ? `Cross-contract impact: ${sensVar.crossContractImpact.map(i => i.targetContract).join(', ')}` : 'Single contract scope'
                    ],
                    trackatorEvidence: {
                        variableName: sensVar.variableName,
                        contract: sensVar.contract,
                        primaryCategory: sensVar.primaryCategory,
                        securitySensitivity: sensVar.securitySensitivity,
                        integrityRequirement: sensVar.integrityRequirement,
                        writerFunctions: sensVar.writerFunctions,
                        readerFunctions: sensVar.readerFunctions,
                        crossContractImpact: sensVar.crossContractImpact,
                        relatedInvariants: sensVar.relatedInvariants
                    },
                    estimatedDifficulty: permWriters.length > 1 ? 'easy' : 'medium',
                    status: 'HYPOTHESIS',
                    priorityBoost: sensVar.securitySensitivity === 'critical' ? 20 : 10
                });
            }
        }
        console.log(`✅ v2.1: Found ${sensitiveVars.length} sensitive variables, with permissionless writers: ${sensitiveVars.filter(v => v.writerFunctions.some(w => matrix.functions.find(f => f.id === w)?.isPermissionless)).length}`);
    }
    
    console.log(`\n📊 State Coupling Analysis Complete: ${attacks.length} attack hypotheses generated`);
    return attacks;
}

// Helper function for v2.1
function mapSeverityToDifficulty(severity) {
    switch (severity) {
        case 'critical': return 'easy';      // Critical = usually straightforward exploit
        case 'high': return 'easy';
        case 'medium': return 'medium';
        case 'low': return 'hard';
        default: return 'medium';
    }
}
```

### Plugin: Intelligent Plugin Router (v2.1 NEW)

**Purpose**: Route hypotheses to the most effective analysis plugin based on **Trackator evidence type and criticality**.

**v2.1 NEW**: Uses `criticalFindings[]` as priority queue and routes based on source phase.

```javascript
function intelligentPluginRouter(hypothesis, context) {
    // v2.1: Determine the best plugin for this hypothesis based on its source
    const sourcePhase = hypothesis.sourcePhase || hypothesis.trackatorEvidence?.source;
    const attackType = hypothesis.type;
    
    const routingDecision = {
        hypothesisId: hypothesis.id,
        primaryPlugin: null,
        secondaryPlugins: [],
        routingRationale: '',
        priority: hypothesis.priority || 50,
        estimatedValue: 'medium'
    };
    
    // ═══════════════════════════════════════════════════
    // ROUTING MATRIX v2.1 (evidence-type → plugin mapping)
    // ═══════════════════════════════════════════════════
    
    // 1. Critical findings from coupling analysis → Direct to Phase 4/5 (high value)
    if (sourcePhase === 'coupling-critical-findings') {
        routingDecision.primaryPlugin = 'fork_tester';
        routingDecision.secondaryPlugins = ['evidence_validator'];
        routingDecision.routingRationale = 'Critical finding from Trackator coupling analysis - pre-validated as high severity';
        routingDecision.priority = hypothesis.priority || 100;
        routingDecision.estimatedValue = hypothesis.impact?.includes('fund loss') || 
                                          hypothesis.impact?.includes('drain') ? 'critical' : 'high';
        
        console.log(`🔴 ROUTE: ${hypothesis.id} → Fork Tester (critical finding)`);
        return routingDecision;
    }
    
    // 2. Coupling cluster attacks → Reverse Engineering + Assumption Breaker
    if (attackType === 'coupling_cluster_exploitation') {
        routingDecision.primaryPlugin = 'assumption_breaker';  // Clusters need state assumption testing
        routingDecision.secondaryPlugins = ['reverse_engineering', 'coupling_analyzer'];
        routingDecision.routingRationale = 'Coupling cluster requires multi-function assumption breaking';
        routingDecision.priority = (hypothesis.priorityBoost || 0) + 70;
        routingDecision.estimatedValue = 'high';
        
        console.log(`🟠 ROUTE: ${hypothesis.id} → Assumption Breaker (cluster attack)`);
        return routingDecision;
    }
    
    // 3. Protection gap exploits → Intent Filter bypass (already validated as gap)
    if (attackType === 'protection_gap_exploitation') {
        routingDecision.primaryPlugin = 'pattern_matcher';  // Match against known protection gap patterns
        routingDecision.secondaryPlugins = ['reachability_checker'];
        routingDecision.routingRationale = 'Protection gap - match against historical exploitation patterns';
        routingDecision.priority = (hypothesis.priorityBoost || 0) + 80;
        routingDecision.estimatedValue = 'high';
        
        // Skip intent filter for protection gaps (they're pre-validated as missing)
        hypothesis.skipIntentFilter = true;
        hypothesis.bypassReason = 'Pre-validated protection gap from Trackator';
        
        console.log(`🟠 ROUTE: ${hypothesis.id} → Pattern Matcher (protection gap, skip intent filter)`);
        return routingDecision;
    }
    
    // 4. Invariant violation paths → Direct trace execution
    if (attackType === 'invariant_violation_path') {
        routingDecision.primaryPlugin = 'execution_tracer';  // Follow the pre-computed path
        routingDecision.secondaryPlugins = ['evidence_validator'];
        routingDecision.routingRationale = 'Pre-computed violation path - execute and validate';
        routingDecision.priority = (hypothesis.priorityBoost || 0) + 75;
        routingDecision.estimatedValue = hypothesis.trackatorEvidence?.feasibility === 'trivial' ? 'critical' : 'high';
        
        console.log(`🟡 ROUTE: ${hypothesis.id} → Execution Tracer (violation path)`);
        return routingDecision;
    }
    
    // 5. Hidden assumption exploits → Assumption Breaker (primary use case)
    if (attackType === 'hidden_assumption_exploitation') {
        routingDecision.primaryPlugin = 'assumption_breaker';  // Perfect match
        routingDecision.secondaryPlugins = ['reverse_engineering'];
        routingDecision.routingRationale = 'Hidden assumption - primary target for assumption breaker plugin';
        routingDecision.priority = (hypothesis.priorityBoost || 0) + 65;
        routingDecision.estimatedValue = hypothesis.trackatorEvidence?.exploitability === 'trivial' ? 'high' : 'medium';
        
        console.log(`🟡 ROUTE: ${hypothesis.id} → Assumption Breaker (assumption exploit)`);
        return routingDecision;
    }
    
    // 6. Sensitive variable targeting → Reverse Engineering (follow the money)
    if (attackType === 'sensitive_variable_targeting') {
        routingDecision.primaryPlugin = 'reverse_engineering';  // Follow value flow
        routingDecision.secondaryPlugins = ['coupling_analyzer'];
        routingDecision.routingRationale = 'Sensitive variable - follow value flows backwards';
        routingDecision.priority = (hypothesis.priorityBoost || 0) + 60;
        routingDecision.estimatedValue = hypothesis.trackatorEvidence?.securitySensitivity === 'critical' ? 'high' : 'medium';
        
        console.log(`🟢 ROUTE: ${hypothesis.id} → Reverse Engineering (variable targeting)`);
        return routingDecision;
    }
    
    // 7. Hidden coupling exploits → Specialized handler based on type
    if (attackType && attackType.startsWith('hidden_coupling_')) {
        const couplingType = attackType.replace('hidden_coupling_', '');
        
        // High-risk coupling types get specialized handling
        if (['proxy-storage-conflict', 'delegatecall-context-leak', 'storage-slot-collision'].includes(couplingType)) {
            routingDecision.primaryPlugin = 'pattern_matcher';  // Match against known proxy patterns
            routingDecision.secondaryPlugins = ['reachability_checker', 'fork_tester'];
            routingDecision.routingRationale = `High-risk ${couplingType} - match against historical proxy exploits`;
            routingDecision.priority = (hypothesis.priorityBoost || 0) + 85;
            routingDecision.estimatedValue = 'critical';
        } else {
            routingDecision.primaryPlugin = 'reachability_checker';  // Check reachability first
            routingDecision.secondaryPlugins = ['pattern_matcher'];
            routingDecision.routingRationale = `${couplingType} - verify reachability then pattern match`;
            routingDecision.priority = (hypothesis.priorityBoost || 0) + 55;
            routingDecision.estimatedValue = 'medium';
        }
        
        console.log(`🔵 ROUTE: ${hypothesis.id} → Specialized handler (${couplingType})`);
        return routingDecision;
    }
    
    // DEFAULT: Standard routing for non-v2.1 types
    const standardRouting = {
        'strong_coupling_exploitation': { plugin: 'coupling_analyzer', priority: 70 },
        'transient_coupling_exploitation': { plugin: 'reachability_checker', priority: 55 },
        'invariant_violation_chain': { plugin: 'assumption_breaker', priority: 65 },
        'high_value_intersection': { plugin: 'reverse_engineering', priority: 75 },
    };
    
    const standard = standardRouting[attackType] || { plugin: 'general_analysis', priority: 50 };
    routingDecision.primaryPlugin = standard.plugin;
    routingDecision.routingRationale = `Standard routing for ${attackType}`;
    routingDecision.priority = standard.priority + (hypothesis.priorityBoost || 0);
    
    console.log(`⚪ ROUTE: ${hypothesis.id} → ${standard.plugin} (standard)`);
    return routingDecision;
}

// v2.1: Batch router for processing all coupling attacks at once
function batchRouteCouplingAttacks(attacks, context) {
    console.log(`\n🔄 v2.1 Intelligent Plugin Routing: Processing ${attacks.length} attacks...`);
    
    const routingResults = {
        total: attacks.length,
        byPlugin: {},
        byPriority: {
            critical: [],   // priority >= 90
            high: [],       // priority >= 70
            medium: [],     // priority >= 50
            low: []         // priority < 50
        },
        skippedIntentFilter: [],
        routedAttacks: []
    };
    
    for (const attack of attacks) {
        const route = intelligentPluginRouter(attack, context);
        
        // Categorize by plugin
        if (!routingResults.byPlugin[route.primaryPlugin]) {
            routingResults.byPlugin[route.primaryPlugin] = [];
        }
        routingResults.byPlugin[route.primaryPlugin].push({
            attackId: attack.id,
            priority: route.priority,
            estimatedValue: route.estimatedValue
        });
        
        // Categorize by priority
        if (route.priority >= 90) routingResults.byPriority.critical.push(attack.id);
        else if (route.priority >= 70) routingResults.byPriority.high.push(attack.id);
        else if (route.priority >= 50) routingResults.byPriority.medium.push(attack.id);
        else routingResults.byPriority.low.push(attack.id);
        
        // Track intent filter bypasses
        if (attack.skipIntentFilter) {
            routingResults.skippedIntentFilter.push(attack.id);
        }
        
        routingResults.routedAttacks.push({
            ...attack,
            routing: route
        });
    }
    
    console.log(`\n📊 Routing Complete:`);
    console.log(`   Critical priority: ${routingResults.byPriority.critical.length}`);
    console.log(`   High priority:    ${routingResults.byPriority.high.length}`);
    console.log(`   Medium priority:  ${routingResults.byPriority.medium.length}`);
    console.log(`   Low priority:     ${routingResults.byPriority.low.length}`);
    console.log(`   Bypassed intent filter: ${routingResults.skippedIntentFilter.length}`);
    console.log(`\n   By Plugin:`);
    for (const [plugin, count] of Object.entries(routingResults.byPlugin)) {
        console.log(`      ${plugin}: ${count.length} attacks`);
    }
    
    return routingResults;
}
```



### Phase 3 Output (v2.1 ENHANCED)

```javascript
hypothesis.status = 'TESTED';
hypothesis.creativeFindings = [/* reverse engineering results */];
hypothesis.assumptionBreaks = [/* assumption breaker results */];
hypothesis.couplingAttacks = [/* v2.1: ENHANCED state coupling analysis results */];
hypothesis.desyncAttacks = [/* v2.0: sync analyzer attack results */];
hypothesis.executionTrace = { /* full trace object */ };
hypothesis.traceConclusion = { survives: boolean, reason: string };

// ═══════════════════════════════════════════════════════════════
// v2.1 NEW: Plugin Routing Results (from Intelligent Plugin Router)
// ═══════════════════════════════════════════════════════════════
hypothesis.pluginRouting = {
    primaryPlugin: string,           // Which plugin handles this
    secondaryPlugins: string[],      // Supporting plugins
    routingRationale: string,       // Why routed this way
    priority: number,               // 0-100 priority score
    estimatedValue: string          // critical | high | medium | low
};

// v2.1 NEW: Evidence Calibration (from Evidence Validator / Fix D)
hypothesis.evidenceCalibration = {
    // 6-Class Classification (Fix D)
    classification: 'proven-property' | 'potential-bug' | 'reachable-bug' | 'false-positive' | 'by-design' | 'insufficient-evidence',
    classificationConfidence: number,  // 0-100%
    
    // Reachability Analysis (Fix D)
    reachability: 'reachable' | 'unreachable' | 'unknown',
    executionPath: ExecutionPath[],    // Full call chain
    crossContractPrereqs: Array<{ targetContract, requiredState, dependencyType, canBeSatisfied }>,
    blockingRequirement: { requirement, type, whyBlocking, potentialBypass } | null,
    
    // Disproof Analysis (Fix D)
    disproofResult: FinalVerdict | null,
    disproofConfidence: number,      // 0-100%
    disproofStrategiesAttempted: DisproofStrategy[],
    
    // Multi-Dimensional Confidence (Fix D)
    confidenceBreakdown: {
        overall: number,              // 0-100 composite
        evidenceStrength: number,       // 0-100
        reachabilityConfidence: number, // 0-100
        impactConfidence: number,       // 0-100
        falsePositiveRisk: number       // 0-100 (higher = more likely FP)
    },
    remainingUnknowns: Array<{ factor, whyUnknown, impactIfWrong, suggestedInvestigation }>,
    
    // Proof Requirements 9-criteria (Fix D)
    proofRequirements: {
        met: number,
        total: number,                 // 9
        status: 'proven-reachable' | 'not-proven' | 'disproven' | 'insufficient-evidence',
        requirements: Array<{ id, requirement, category, status, hasEvidence, explanation }>
    },
    
    // Final Verdict (Fix D) - aligns with Trackator's FinalVerdict enum
    finalVerdict: 'confirmed-vulnerability' | 'potential-vulnerability' | 'false-positive' | 'by-design' | 'cannot-determine' | 'deferred',
    recommendedAction: 'immediate-fix' | 'short-term-investigation' | 'long-term-monitoring' | 'accept-risk' | 'dismiss' | 'escalate-to-auditor' | 'defer'
};
```

**v2.1 Output Schema Changes:**

| Field | v2.0 | v2.1 | Source |
|------|------|------|--------|
| `classification` | Simple string | 6-class enum from Fix D | `classificationRegistry` |
| `confidence` | Single number | Multi-dimensional breakdown | `confidenceAssessments.scoreBreakdown` |
| `reachability` | Basic boolean | Full path + cross-contract prereqs | `reachabilityAnalysis[]` |
| `disproof` | Basic result | Strategy-by-strategy confidence | `disproofEngine.results[]` |
| `verdict` | Manual derivation | From Trackator `finalVerdict` | `finalVerdict.verdicts[]` |
| `action` | Not present | `recommendedAction` enum | `finalVerdict.verdicts[].recommendedAction` |

Only hypotheses where `traceConclusion.survives === true` AND `evidenceCalibration.finalVerdict !== 'false-positive'` proceed to Phase 4.

Only hypotheses where `traceConclusion.survives === true` proceed to Phase 4.

---

## Phase 4: FUZZING

### Objective
Use Echidna/Medusa (via Fizz integration) to mechanically explore state space and find invariant violations.

**v2.0 ENHANCED**: Now includes **Disproof Engine** from Evidence Validator to eliminate false positives that fuzz testing might generate.

### Integration with Fizz Skill

Redteam-Trackator leverages the **Fizz** skill for fuzz campaign generation and execution.

**Fizz Components Used**:

| Fizz Component | Purpose in Redteam-Trackator |
|---------------|------------------------------|
| Protocol Analyzer | Understand protocol for harness generation |
| Property Generators | Generate invariants from Trackator data |
| Harness Generator | Create Echidna/Medusa compatible Solidity |
| Campaign Runner | Execute fuzz tests |
| Adversarial Profit Maximizer | Generate attack-oriented properties |

### Generating Fuzz Properties from Trackator Invariants

**Map Trackator invariants to Fizz properties**:

```javascript
function generateFizzProperties(trackatorInvariants, context) {
    const properties = [];
    
    for (const inv of trackatorInvariants) {
        const fizzProperty = mapInvariantToFizzProperty(inv, context);
        properties.push(fizzProperty);
    }
    
    // Add adversarial properties from Fizz's Adversarial Profit Maximizer
    properties.push(...generateAdversarialProperties(context));
    
    return properties;
}

function mapInvariantToFizzProperty(invariant, context) {
    return {
        propertyId: `INV_${invariant.id}`,
        english: invariant.template,
        soliditySketch: generateSoliditySketch(invariant),
        category: mapCategory(invariant.category),
        scope: invariant.relatedFunctions?.length > 1 ? 'GLOBAL' : 'SPECIFIC',
        guarantee: 'SHOULD-HOLD',  // Invariants from Trackator should hold
        evidence: `Trackator invariant: ${inv.instance}`,
        priority: invariant.severity === 'critical' ? 'HIGH' : 'MEDIUM',
        relatedFunctions: invariant.relatedFunctions || [],
        relatedStateVars: invariant.relatedStateVars || []
    };
}
```

**Category Mapping**:

| Trackator Category | Fizz Category |
|--------------------|---------------|
| `accounting` | HIGH_LEVEL |
| `bounds` | VARIABLE_TRANSITION |
| `oracle` | HIGH_LEVEL |
| `permission` | STATE_TRANSITION |

### Adversarial Properties (from Fizz)

Add attack-oriented properties:

```javascript
function generateAdversarialProperties(context) {
    return [
        {
            propertyId: 'ADV_NO_FREE_PROFIT',
            english: 'Attacker cannot end with more value than started within single transaction',
            category: 'HIGH_LEVEL',
            guarantee: 'SHOULD-HOLD',
            evidence: 'Fundamental economic invariant',
            priority: 'HIGH',
            pattern: 'D'  // From Fizz Adversarial Profit Maximizer
        },
        {
            propertyId: 'ADV_FLASH_LOAN_PROFIT',
            english: 'Flash loan cannot extract value from protocol',
            category: 'HIGH_LEVEL',
            guarantee: 'SHOULD-HOLD',
            evidence: 'Flash loan economic invariant',
            priority: 'HIGH',
            pattern: 'F'
        },
        {
            propertyId: 'ADV_WITHDRAWAL_LIVENESS',
            english: 'User with balance > 0 can always withdraw their full balance',
            category: 'VALID_STATE',
            guarantee: 'SHOULD-HOLD',
            evidence: 'Liveness guarantee',
            priority: 'HIGH',
            pattern: 'A'
        },
        {
            propertyId: 'ADV_FIRST_DEPOSITOR',
            english: 'First depositor receives non-zero shares for deposit > 0',
            category: 'HIGH_LEVEL',
            guarantee: 'SHOULD-HOLD',
            evidence: 'Share inflation protection',
            priority: 'MEDIUM',
            pattern: 'E'
        }
    ];
}
```

### Running Fuzz Campaign

```bash
# Using Fizz skill to generate suite
fizz --project /path/to/protocol --guided

# Run Echidna on generated properties
cd /path/to/protocol
echidna-test test/fizz/FuzzTester.sol --config test/fizz/echidna.yaml --format json

# Or run Medusa (faster for complex protocols)
medusa test/fizz/FuzzTester.sol --config test/fizz/medusa.json
```

### Plugin: Realism Check (BLOCK GATE #2)

**Purpose**: Filter out fuzz findings that aren't reachable on real mainnet state.

```javascript
function realismCheck(fuzzFinding, context) {
    // Check 1: Does finding require unrealistic state?
    if (requiresUnrealisticState(fuzzFinding, context)) {
        return {
            verdict: 'unrealistic',
            reason: 'Requires state that cannot be achieved on mainnet',
            keepForReview: true  // BLOCK GATE: Keep for manual review
        };
    }
    
    // Check 2: Does finding require trusted role action?
    if (requiresTrustedRoleAction(fuzzFinding, context)) {
        return {
            verdict: 'operational_error',
            reason: 'Fuzz finding requires trusted role action',
            keepForReview: false
        };
    }
    
    // Check 3: Is there enough capital/liquidity?
    if (requiresExcessiveCapital(fuzzFinding, context)) {
        return {
            verdict: 'impractical',
            reason: `Requires $${fuzzFinding.estimatedCapitalNeeded}M+ capital`,
            keepForReview: true  // Might still be valid for whale attackers
        };
    }
    
    return {
        verdict: 'realistic',
        reason: 'Fuzz finding appears achievable on mainnet',
        proceedToForkTest: true
    };
}
```

### Plugin: Disproof Engine (v2.0 NEW)

**Purpose**: Attempt to **DISPROVE** fuzz findings before accepting them as vulnerabilities. This is the opposite of typical vulnerability research—instead of proving bugs exist, we try to prove they DON'T.

**Philosophy**: > *"A finding that survives disproof attempts is stronger than one that was never challenged."*

**When Enhanced Data Available** (`context.evidence` exists):

```javascript
function disproofEngine(fuzzFinding, context) {
    const disproofAttempt = {
        findingId: fuzzFinding.id,
        attemptedDisproof: true,
        disproofResult: null,  // 'DISPROVED' | 'NOT_DISPROVED' | 'CANNOT_DETERMINE'
        disproofEvidence: [],
        residualRisk: 'unknown'
    };
    
    // DISPROOF ATTEMPT 1: Guard Code Search
    // Look for code that PREVENTS the vulnerability pattern
    const guardCodeSearch = searchForGuardCode(fuzzFinding, context);
    if (guardCodeSearch.found) {
        disproofAttempt.disproofEvidence.push({
            type: 'guard_code_found',
            location: guardCodeSearch.location,
            code: guardCodeSearch.codeSnippet,
            reason: `Guard found: ${guardCodeSearch.explanation}`
        });
        
        // If guard is effective, this might be a false positive
        if (guardCodeSearch.isEffective) {
            disproofAttempt.disproofResult = 'DISPROVED';
            disproofAttempt.residualRisk = 'low';  // Guard exists, but test it anyway
            return disproofAttempt;
        }
    }
    
    // DISPROOF ATTEMPT 2: Semantic Analysis
    // Does the "vulnerable" pattern actually lead to loss?
    const semanticAnalysis = analyzeSemantics(fuzzFinding, context);
    if (semanticAnalysis.isFalsePositive) {
        disproofAttempt.disproofEvidence.push({
            type: 'semantic_mismatch',
            reason: semanticAnalysis.reason,
            expectedBehavior: semanticAnalysis.expectedBehavior,
            actualBehavior: semanticAnalysis.actualBehavior
        });
        
        if (semanticAnalysis.confidence > 0.8) {
            disproofAttempt.disproofResult = 'DISPROVED';
            disproofAttempt.residualRisk = 'low';
            return disproofAttempt;
        }
    }
    
    // DISPROOF ATTEMPT 3: Historical Pattern Cross-Check
    // Has similar pattern been disproved before?
    if (context.evidence?.disproofEngine) {
        const historicalDisproofs = context.evidence.disproofEngine.disproofEvidence.filter(
            d => d.patternSimilarity(fuzzFinding) > 0.7
        );
        
        if (historicalDisproofs.length > 0) {
            disproofAttempt.disproofEvidence.push({
                type: 'historical_disproof_match',
                matches: historicalDisproofs.length,
                reason: `${historicalDisproofs.length} similar patterns previously disproved`
            });
        }
    }
    
    // DISPROOF ATTEMPT 4: Invariant Consistency Check
    // Would exploiting this violate invariants that PROTECT users?
    if (context.invariants) {
        const protectingInvariants = context.invariants.filter(inv => 
            inv.relatedFunctions?.some(f => 
                fuzzFinding.vulnerableFunctions?.includes(f)
            ) && inv.category === 'safety'
        );
        
        if (protectingInvariants.length > 0) {
            disproofAttempt.disproofEvidence.push({
                type: 'protecting_invariants',
                invariants: protectingInvariants.map(i => i.id),
                reason: `${protectingInvariants.length} safety invariants may prevent exploitation`
            });
        }
    }
    
    // FINAL DETERMINATION
    if (disproofAttempt.disproofEvidence.length === 0) {
        // No disproof evidence found → finding survives
        disproofAttempt.disproofResult = 'NOT_DISPROVED';
        disproofAttempt.residualRisk = 'medium-high';  // No counter-evidence, but not confirmed either
    } else if (!disproofAttempt.disproofResult) {
        // Some evidence but not conclusive
        disproofAttempt.disproofResult = 'CANNOT_DETERMINE';
        disproofAttempt.residualRisk = 'medium';  // Needs fork testing to resolve
    }
    
    return disproofAttempt;
}

function searchForGuardCode(finding, context) {
    // Search for require/assert/check patterns that might prevent exploitation
    for (const contract of context.contracts) {
        for (const func of contract.functions || []) {
            if (finding.vulnerableFunctions?.includes(func.name)) {
                // Look for guards in function body
                const hasRequire = func.body?.hasRequire === true;
                const hasAssert = func.body?.hasAssert === true;
                const hasCheckPattern = func.body?.checkPatterns?.length > 0;
                
                if (hasRequire || hasAssert || hasCheckPattern) {
                    return {
                        found: true,
                        location: `${contract.name}.${func.name}`,
                        codeSnippet: func.body.guardSnippet || 'Guard code present',
                        explanation: `Function has ${hasRequire ? 'require()' : ''}${hasAssert ? 'assert()' : ''}${hasCheckPattern ? 'check pattern' : ''}`,
                        isEffective: hasRequire  // require() is usually effective
                    };
                }
            }
        }
    }
    
    return { found: false };
}
```

### Multi-Dimensional Evidence Calibration System (v2.0 → v2.1 ENHANCED)

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
hypothesis.fuzzResults = {
    campaignRun: boolean,
    violationsFound: number,
    properties: [{ propertyId, violated, reproducible }],
    realisticFindings: [],  // Passed realism check
    
    // v2.0 NEW: Disproof engine results
    disproofResults: [{
        findingId: string,
        disproofResult: 'DISPROVED' | 'NOT_DISPROVED' | 'CANNOT_DETERMINE',
        disproofEvidence: Array,
        residualRisk: string
    }],
    
    // v2.0 NEW: Classification results
    classifications: [{
        findingId: string,
        class: string,  // Six-class system
        confidence: number,  // 0-100%
        criteriaMet: string[],
        criteriaFailed: string[]
    }]
};
```

---

## Phase 5: FORK TESTING

### Objective
Validate findings against REAL mainnet state using Foundry fork testing. **This is where the hacker lives and iterates.**

**v2.0 ENHANCED**: Now includes **9-criteria reachability proof** from Evidence Validator for court-ready evidence.

### Fork Testing Infrastructure

```javascript
const FORK_CONFIG = {
    rpcUrl: process.env.MAINNET_RPC_URL || 'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
    blockNumber: process.env.FORK_BLOCK_NUMBER || 'latest',
    maxIterations: MAX_FORK_ITERATIONS || 10,
    timeoutMs: 300000  // 5 minutes max per iteration
};
```

### Step 5.1: Smoke Fork Test

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

### Step 5.2: Deep Fork Testing (with Iteration)

**THIS IS THE HEART OF PHASE 5.**

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

## Phase 6: REPORTING

### Objective
Generate comprehensive report of all confirmed and probable findings.

### Report Structure

```markdown
# Redteam-Trackator Security Assessment Report

**Protocol:** {PROTOCOL_NAME}
**Assessment Date:** {DATE}
**Trackator Version:** {VERSION}
**Analyst:** Redteam-Trackator v2.0.0

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Hypotheses Generated | {N} |
| Confirmed Vulnerabilities | {N} |
| Probable Findings | {N} |
| Leads for Manual Review | {N} |
| False Positives Discarded | {N} |
| True Positive Rate (Est.) | {X}% |

---

## Critical Findings

### Finding #{ID}: {TITLE}

**Severity:** Critical | High | Medium | Low  
**Status:** CONFIRMED / PROBABLE  
**Category:** {bug_class}  
**Estimated Impact:** ${LOSS_USD} (based on pattern matches)

#### Description
{Clear description of the vulnerability}

#### Discovery Method
- **Phase Detected:** {0-6}
- **Source:** Pattern Match / Creative Attack / Fuzz / Fork
- **Matched Pattern:** {pattern_slug} (if applicable)

#### Technical Details

**Vulnerable Function(s):**
- `{contract}.{function}` (line {N})

**Root Cause:**
{Explanation of why this is a bug, not operational error}

#### Trackator Evidence

**State Diff (from fork test):**
| Variable | Before | After |
|----------|--------|-------|
| {var} | {val} | {val} |

**Alerts Triggered:**
- {ALERT_ID}: {description}

**Invariant Violations:**
- {INV_ID}: {expression}

#### Kill Chain
1. {Step 1}
2. {Step 2}
...
N. {Profit extraction}

#### Execution Trace Summary
{Brief summary of full A→B→C→end trace proving feasibility}

#### Fork Test Proof
- **TX Hash:** `{hash}` (mainnet fork block: {block})
- **Gas Used:** {gas}
- **Attacker Profit:** {profit}

#### Economic Assessment
| Metric | Value |
|--------|-------|
| Capital Required | {amount} |
| Gas Cost | {cost} |
| Estimated Profit | {profit} |
| Feasibility | HIGH / MEDIUM / LOW |

*Note: Economic assessment INFORMS decision, never blocks reporting.*

#### Recommendation
{Recommendation for fix}

---

## Probable Findings
{Same format but marked as PROBABLE}

## Leads for Manual Review
{Brief descriptions of interesting patterns needing human review}

## Appendix A: Discarded Hypotheses Summary
| Count | Reason |
|-------|--------|
| {N} | Operational Error (trusted role action) |
| {N} | Design Choice (intentional) |
| {N} | Unreachable (proven by trace) |
| {N} | Unrealistic State (fuzz artifact) |

## Appendix B: Trackator Context
- **Protocol Type:** {type}
- **Contracts Analyzed:** {N}
- **Entry Points:** {N}
- **Assets at Risk:** {list}
- **Invariants Checked:** {N}

## Appendix C: Trackator Multi-Phase Evidence (v2.0)
> Present when enhanced Trackator data available

### C.1 Storage Dependency Evidence
- Value-bearing variables identified: {N}
- Permissionless writers on value-bearing vars: {N}
- Contended variables (race conditions): {N}
- High-risk shared-state entries: {N}

### C.2 State Coupling Evidence  
- Strong couplings exploitable: {N}
- Hidden couplings discovered: {N}
- Invariant violation chains: {N}

### C.3 Sync Analyzer Evidence
- Critical desync risks: {N}
- Unverified assumptions (no verifier): {N}
- Race windows identified: {N}

### C.4 Evidence Validator Classification
- Six-class classification applied: YES/NO
- Confidence scores calculated: YES/NO
- Disproof engine results: {N} findings tested

## Appendix D: Confidence Scoring & Classification (v2.0)
> Detailed scoring breakdown for each finding

### D.1 Nine-Criteria Reachability Proof
See `templates/report-template.md` Appendix D for full checklist template

### D.2 Classification Distribution
| Class | Count | Action |
|-------|-------|--------|
| confirmed-vulnerability | {N} | Report as P0/P1 |
| potential-vulnerability | {N} | Report as P2 |
| false-positive | {N} | Discard |
| by-design | {N} | Note only |
| informational | {N} | Appendix |
| cannot-determine | {N} | Queue for review |

## Appendix E: Methodology Notes  <!-- Renamed from C -->
{Notes about methodology, limitations, assumptions}

## Appendix F: Raw Data Index  <!-- Renamed from D -->
{Generated artifacts and input data index}
```

### Report Generation Code

```javascript
function generateReport(allHypotheses, context) {
    const confirmed = allHypotheses.filter(h => 
        h.forkTestResult?.deepTest?.finalVerdict === 'CONFIRMED'
    );
    const probable = allHypotheses.filter(h => 
        h.forkTestResult?.deepTest?.finalVerdict === 'PROBABLE'
    );
    const leads = allHypotheses.filter(h => 
        h.status === 'LEAD' || h.reachabilityResult?.verdict === 'lead'
    );
    const discarded = allHypotheses.filter(h => 
        ['DISCARDED', 'DEAD', 'OPERATIONAL_ERROR'].includes(h.status)
    );
    
    const report = {
        metadata: {
            protocol: context.protocolType,
            date: new Date().toISOString(),
            version: '2.0.0'
        },
        executiveSummary: {
            totalHypotheses: allHypotheses.length,
            confirmedCount: confirmed.length,
            probableCount: probable.length,
            leadsCount: leads.length,
            discardedCount: discarded.length,
            truePositiveRate: estimateTPRate(confirmed.length, probable.length, allHypotheses.length)
        },
        findings: {
            critical: confirmed.filter(severityFilter('critical')),
            high: confirmed.filter(severityFilter('high')).concat(probable.filter(severityFilter('high'))),
            medium: probable.filter(severityFilter('medium')),
            leads: leads
        },
        appendix: {
            discardedSummary: categorizeDiscarded(discarded),
            trackatorContext: context,
            methodology: getMethodologyNotes()
        }
    };
    
    // Write markdown report
    const markdown = renderReportToMarkdown(report);
    writeFileSync(`${OUTPUT_DIR}/redteam-trackator-report.md`, markdown);
    
    // Also write JSON for machine consumption
    writeFileSync(`${OUTPUT_DIR}/redteam-trackator-report.json`, JSON.stringify(report, null, 2));
    
    return report;
}
```

---

## Agent Specifications

### Agent 1: Creative Hacker Agent

**File:** `agents/hacker-agent.md`

**Role:** Offensive security researcher. Thinks like attacker.

**Responsibilities:**
- Phase 0: Assist with hypothesis prioritization
- Phase 3: PRIMARY OWNER - Reverse engineering, assumption breaking
- Phase 5: PRIMARY OWNER - Fork test iteration, visualization analysis

**Mindset:**
```
"I am an attacker. I want to:
1. Steal value from this protocol
2. Brick it so users can't withdraw
3. Extract profit that shouldn't exist

I follow rules:
- Complete FULL execution traces before claiming anything
- Respect trust boundaries (admin is admin, not a target)
- Distinguish code flaws from operational errors
- Iterate on failures, learn from them"
```

**Input/Output Contract:**

| Input | Output |
|-------|--------|
| Trackator context | Creative attack hypotheses |
| Pattern matches | Enhanced attacks with historical context |
| Fork visualization | Modified exploit attempts |
| Failure analysis | Next iteration strategy |

### Agent 2: Verifier Agent

**File:** `agents/verifier-agent.md`

**Role:** Defensive skeptic. Validates findings without killing them prematurely.

**Responsibilities:**
- Phase 2: Reachability checks (BLOCK GATE)
- Phase 3: Execution trace validation
- Phase 4: Realism checks (BLOCK GATE)
- Phase 5: Fork evidence validation
- Phase 6: Final report grading

**Mindset:**
```
"I am a verifier. My job is:
1. Validate, not invalidate
2. Use BLOCK gates, not KILL gates
3. Save findings for PoC, don't delete them
4. Grade confidence honestly

I check:
- Is the execution trace COMPLETE?
- Are all preconditions satisfied?
- Is this a code bug or operational error?
- Would this work on real mainnet?

My verdicts:
- CONFIRMED: Proven on fork
- PROBABLE: Strong evidence, minor gaps
- LEAD: Interesting, needs expert review
- DEAD: Proven impossible (after thorough testing)"
```

**Input/Output Contract:**

| Input | Output |
|-------|--------|
| Hacker hypothesis | Reachability verdict (not death sentence) |
| Execution trace | Validation pass/fail with reasons |
| Fuzz finding | Realism assessment |
| Fork result | Confirmation with evidence strength |

---

## Plugin Specifications

### Plugin List

| Plugin | Phase | Purpose | File |
|--------|-------|---------|------|
| Intended Behavior | 1 | FP early filtering | `plugins/intended-behavior.md` |
| Pattern Matcher | 2 | Historical exploit matching | `plugins/pattern-matcher.md` |
| Evidence Validator | 2,4 | Six-class classification & disproof (v2.0) | Integrated into Phase 2/4 |
| Reachability | 2,3,4,5 | Feasibility verification | `plugins/reachability.md` |
| Reverse Engineering | 3 | Value flow tracing (enhanced v2.0) | `plugins/reverse-engineering.md` |
| State Coupling Analysis | 3 | Coupling-based attacks (v2.0 NEW) | Integrated into SKILL.md Phase 3 |
| Assumption Breaker | 3 | Trust assumption testing (enhanced v2.0) | `plugins/assumption-breaker.md` |
| Fuzz (via Fizz) | 4 | Mechanical exploration + Disproof Engine (v2.0) | References Fizz skill |
| Fork Test | 5 | Mainnet validation + 9-criteria proof (v2.0) | `plugins/fork-test.md` |
| Report Generator | 6 | Output formatting with evidence tables | `templates/report-template.md` |

---

## Confidence Score Calculation

Each confirmed/probable finding receives a composite confidence score:

```javascript
function calculateConfidence(finding) {
    const weights = {
        patternMatch: 0.20,    // How well does it match historical exploit?
        traceComplete: 0.20,   // Was full execution trace completed?
        fuzzValidation: 0.15,  // Did fuzz testing reproduce it?
        forkSuccess: 0.35,     // Did it work on forked mainnet?
        economicFeasibility: 0.10  // Is it profitable in practice?
    };
    
    let score = 0;
    
    // Pattern match strength
    score += weights.patternMatch * (finding.patternMatchScore || 0);
    
    // Trace completeness (binary)
    score += weights.traceComplete * (finding.executionTrace?.completed ? 1 : 0);
    
    // Fuzz validation
    score += weights.fuzzValidation * (finding.fuzzResults?.violationsFound > 0 ? 1 : 0);
    
    // Fork success (most important)
    score += weights.forkSuccess * (finding.forkTestResult?.deepTest?.success ? 1 : 0);
    
    // Economic feasibility
    score += weights.economicFeasibility * (isEconomicallyViable(finding) ? 1 : 0);
    
    finding.confidenceScore = score;
    
    // Map score to report tier
    if (score >= 0.7) finding.tier = 'CONFIRMED';
    else if (score >= 0.4) finding.tier = 'PROBABLE';
    else if (score >= 0.2) finding.tier = 'LEAD';
    else finding.tier = 'DISCARDED';
    
    return score;
}
```

---

## Error Handling & Edge Cases

### Missing Trackator Data

```javascript
if (!trackatorEnrichData) {
    console.warn('⚠️ No enrich data available - running in degraded mode');
    // Fall back to basic static analysis only
    // Skip phases that require enrich data (1, 3 partially)
}
```

### No Exploits Library

```javascript
if (!existsSync(EXPLOITS_LIBRARY_PATH)) {
    console.warn('⚠️ No exploits library - skipping pattern matching');
    // Proceed with creative attack phase only
}
```

### Fizz Not Available

```javascript
if (!checkFizzAvailable()) {
    console.warn('⚠️ Fizz skill not available - skipping fuzz phase');
    // Continue with fork testing only
}
```

### Fork RPC Issues

```javascript
try {
    await runForkTest();
} catch (error) {
    if (error.code === 'RPC_ERROR') {
        console.error('❌ Fork RPC unavailable - skipping Phase 5');
        hypothesis.forkTestResult = { error: 'RPC_UNAVAILABLE', skipped: true };
        // Still report findings from earlier phases with lower confidence
    }
}
```

---

## Quality Assurance Checklist

Before finalizing report, verify:

- [ ] All confirmed findings have COMPLETE execution traces (A→B→C→end)
- [ ] No finding relies on "admin is malicious" scenario
- [ ] No finding relies on "key compromised" scenario  
- [ ] All operational errors properly excluded
- [ ] All design choices noted but not reported as vulnerabilities
- [ ] Fork test TX hashes are valid and verifiable
- [ ] Economic assessments inform but don't block findings
- [ ] Report clearly distinguishes CONFIRMED vs PROBABLE vs LEAD
- [ ] Trackator evidence cited for each finding
- [ ] Kill chains are technically accurate
- [ ] Recommendations are actionable
- [ ] **v2.0**: Enhanced Trackator data utilized (storage/coupling/sync/evidence)
- [ ] **v2.0**: Disproof engine ran on all fuzz findings
- [ ] **v2.0**: 6-class classification applied to all findings
- [ ] **v2.0**: State coupling analysis performed (if data available)
- [ ] **v2.0**: Sync analyzer risks evaluated (if data available)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2026-07-30 | **MAJOR**: Trackator Enhanced Integration - Storage Dependency Analyzer, State Coupling Detector, Sync Analyzer, Evidence Validator; Disproof Engine; 6-class classification; 9-criteria reachability proof; Coupling-based attack patterns |
| 1.0.0 | 2026-07-26 | Initial release with 6-phase pipeline |

---

## Dependencies

- **Trackator**: Static/runtime analysis tool (required)
- **Fizz**: Fuzz testing skill (recommended, optional)
- **Exploits-class-library**: Historical exploit patterns (recommended)
- **Foundry**: Fork testing framework (required for Phase 5)
- **Echidna/Medusa**: Fuzzers (required for Phase 4)
