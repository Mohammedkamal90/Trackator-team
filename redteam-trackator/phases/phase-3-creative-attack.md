# Phase 3: CREATIVE ATTACK

> **Part of**: [RedTeam Trackator SKILL.md](../SKILL.md) | **Phase**: 3 of 6
> **Previous**: [Phase 2 - Pattern Matching](phase-2-pattern-matching.md) | **Next**: [Phase 4 - Fuzzing](phase-4-fuzzing.md)
> **Source**: Original SKILL.md Lines 852-2063 (~1200 lines → condensed to ~488 lines)
> **Bug Fix Applied**: ✅ Duplicate gating condition removed (kept evidenceCalibration check)

---

## Objective

**Where the Hacker agent lives.** Think like an attacker. Break assumptions. Follow value flows backwards. Find NEW vulnerabilities that pattern matching missed.

**v2.0 ENHANCED**: With Trackator's Storage Dependency Analyzer, State Coupling Detector, and Sync Analyzer data, the Hacker now has **weaponized intelligence** for:
- **Value-bearing variable topology** (Storage Dep.)
- **Function coupling graphs** (State Coupling)
- **Assumption dependency chains** (Sync Analyzer)

---

## Agent: Creative Hacker Agent

**Role**: Offensive mindset. Think like an attacker trying to steal value, brick protocol, or extract profit.

### Mindset Rules

| # | Rule | Version |
|---|------|---------|
| 1 | "How would I steal from this protocol?" | Original |
| 2 | "How would I brick it so users can't withdraw?" | Original |
| 3 | "What edge states break core assumptions?" | Original |
| 4 | "If I manipulate THIS input, what breaks downstream?" | Original |
| 5 | "Where's the money? Follow value-bearing variables to their writers" | v2.0 NEW |
| 6 | "What's coupled? Split atomic operations across transactions" | v2.0 NEW |
| 7 | "What's stale? Exploit assumption gaps between producer and consumer" | v2.0 NEW |

---

## Plugin: Reverse Engineering Plugin

**Purpose**: Follow Trackator value flows BACKWARDS to find manipulation points.

### Algorithm Summary

```javascript
function reverseEngineer(context) {
    const creativeHypotheses = [];
    
    // Start from assets at risk, trace money flows backwards
    for (const asset of context.assetsAtRisk) {
        const relevantFlows = context.moneyFlows.filter(flow => 
            flow.involvesAsset(asset.name)
        );
        
        for (const flow of relevantFlows) {
            const manipulationPoints = traceFlowBackwards(flow, context);
            // Generate hypotheses for each manipulation point
            creativeHypotheses.push(...manipulationPoints.map(point => ({
                id: `CREATIVE_${Date.now()}`,
                type: 'reverse_engineering',
                targetAsset: asset.name,
                manipulationPoint: point.function,
                manipulationType: point.type,  // 'input', 'state', 'timing'
                attackIdea: point.description,
                sourcePhase: 3,
                status: 'HYPOTHESIS'
            })));
        }
    }
    return creativeHypotheses;
}
```

### Manipulation Point Types

| Type | Description | Example Attack |
|------|-------------|----------------|
| `input` | External input can be manipulated | Manipulate price oracle before stake() |
| `state` | Depends on manipulable state variable | Alter rewardPerTokenStored |
| `timing` | Timing dependency enables front-run | Front-run or sandwich transactions |

### Example Attack Idea

```
Asset: _balances (StakingRewards)
Flow: stake() → _balances[user] += amount

Manipulation Point:
- What if rewardPerTokenStored is manipulated BEFORE stake()?
- The earned() calculation uses rewardPerTokenStored
- If we manipulate it, we might get inflated rewards

Attack Chain:
1. Call notifyRewardAmount() with huge amount (if accessible)
2. Immediately call stake()
3. rewardPerTokenStored spikes → our share inflates
4. Call getReward() → profit from inflated calculation
```

> **Full implementation**: See [references/code-examples.md](../references/code-examples.md#reverse-engineering-plugin)

---

## Plugin: Assumption Breaker Plugin

**Purpose**: Systematically test each Trackator trust assumption to see if breaking it leads to exploitation.

**CRITICAL RULE**: Only test assumptions that can be broken by EXTERNAL attackers, not by trusted roles being malicious.

**v2.0 ENHANCED**: Leverages Sync Analyzer's `assumptionDependencyGraph` and `criticalDesyncRisks`.

### Allowed vs Disallowed Assumption Breaks

| Category | Allowed? | Reason |
|----------|----------|--------|
| Oracle prices | ✅ YES | External market force |
| External contract behavior | ✅ YES | May have bugs, may be upgradeable |
| Price feed timeliness | ✅ YES | MEV/front-runnable |
| Governance capture | ❌ NO | Trusted role |
| Admin key compromise | ❌ NO | Operational security |
| Keeper misbehavior | ❌ NO | Trusted role |

### Attack Generation Summary

```javascript
function assumptionBreaker(context) {
    const attacks = [];
    
    // v2.0: Prioritize critical desync risks from Sync Analyzer
    if (context.sync?.criticalDesyncRisks) {
        attacks.push(...breakCriticalDesyncRisks(context));
    }
    
    // Test each trust assumption (skip governance)
    for (const assumption of context.trustAssumptions) {
        if (assumption.category === 'governance') continue;
        
        switch (assumption.category) {
            case 'oracle': attacks.push(...breakOracleAssumption(assumption)); break;
            case 'external-contract': attacks.push(...breakExternalContract(assumption)); break;
            case 'price-feed': attacks.push(...breakPriceFeedAssumption(assumption)); break;
        }
    }
    return attacks;
}
```

### v2.0 Desync Risk Attack Types

| Risk Type | ID Prefix | Description |
|-----------|-----------|-------------|
| `stale-price` | `DESYNC_STALE_` | Exploit stale price within window |
| `missing-verifier` | `DESYNC_NOVERIFY_` | Exploit unverified assumption |
| `race-window` | `DESYNC_RACE_` | Exploit race condition window |

> **Full implementation**: See [references/code-examples.md](../references/code-examples.md#assumption-breaker-plugin)

---

## ★ MANDATORY: Full Execution Trace

**BEFORE escalating ANY creative hypothesis to Verifier, Hacker MUST complete full execution trace.**

### Trace Structure

```javascript
function buildExecutionTrace(hypothesis, context) {
    const trace = {
        hypothesisId: hypothesis.id,
        steps: [],           // Array of traced function calls
        finalState: null,    // State after full execution
        conclusion: null,    // { survives: boolean, reason: string, severity: string }
        completed: false
    };
    
    // DFS through call stack, recording:
    // - Function name, contract, modifiers
    // - CEI pattern detection
    // - State variables read/written
    // - External calls (reentrancy points)
    // - Cycle detection
    
    // Safety limit: 100 steps max
    return trace;
}
```

### Conclusion Logic

```javascript
function drawConclusion(trace, hypothesis) {
    const externalCalls = trace.steps.filter(s => s.hasExternalCall);
    const stateUpdatesAfterCalls = trace.steps.filter(s => 
        s.stateVariablesWritten?.length > 0 && occurredAfter(externalCalls, s)
    );
    
    // Reentrancy possible if external calls before state updates
    if (externalCalls.length > 0 && stateUpdatesAfterCalls.length > 0) {
        return { survives: true, reason: 'External calls before state updates - reentrancy possible', severity: 'high' };
    }
    
    // Check for guards
    const hasGuard = trace.steps.some(s => s.modifiers?.includes('nonReentrant'));
    if (hasGuard && externalCalls.length > 0) {
        return { survives: false, reason: 'nonReentrant guard present', severity: 'mitigated' };
    }
    
    return { survives: true, reason: 'No obvious mitigation found', severity: 'medium' };
}
```

### Key Trace Step Fields

| Field | Type | Purpose |
|-------|------|---------|
| `function` | string | Function name being traced |
| `contract` | string | Contract containing function |
| `modifiers` | string[] | Access control modifiers |
| `hasExternalCall` | boolean | ⚠️ Potential reentrancy point |
| `ceiPattern` | string | Checks-Effects-Interactions pattern |
| `stateVariablesRead` | string[] | State dependencies |
| `stateVariablesWritten` | string[] | State mutations |
| `calls` | string[] | Internal/external calls made |

> **Full implementation**: See [references/code-examples.md](../references/code-examples.md#execution-trace)

---

## Plugin: State Coupling Analysis (v2.0 → v2.1 ENHANCED)

**Purpose**: Use Trackator's State Coupling Detector data to find **coupling-based attack vectors** invisible in individual function analysis.

> *"Two functions that share state are safer than they look—until you realize an attacker can call both in one transaction."*

### v2.1 Data Sources Consumed

| Source Field | Content | Usage |
|--------------|---------|-------|
| `functionDependencyMatrix` | Dependency graph with clusters | Find strong couplings |
| `hiddenCouplings[]` | 13 coupling types | Detect hidden attack surfaces |
| `invariantFunctionMap` | Violation paths + protection gaps | Find invariant exploits |
| `variableClassification[]` | Security-sensitive variables | Target value-bearing vars |
| `topStateIntersections[]` | High-value state intersections | Prioritize by value-at-risk |
| `hiddenAssumptions[]` | Exploitability-rated assumptions | Break hidden assumptions |
| `criticalFindings[]` | Pre-computed priority queue | Quick access to worst issues |

### Attack Patterns Overview

#### Pattern 1: Strong Coupling + Permissionless Entry
- **Target**: Functions with `couplingStrength >= 70` sharing value-bearing variables
- **Condition**: At least one function is permissionless
- **Output**: `COUPLING_STRONG_*` or `CLUSTER_*` hypotheses

#### Pattern 2: Hidden Couplings (All 13 Types)
```
Exploitable Types: proxy-storage-conflict, delegatecall-context-leak, 
callback-state-dependence, storage-slot-collision, cross-contract-assumed-state,
struct-layout-assumption, transient, timestamp-dependent, inheritance-storage-overlap,
library-storage-sharing, multi-contract-consistency, protocol-dependent,
immutable-pattern-violation
```
- **Filter**: Severity = critical/high, confidence ≠ speculative
- **Output**: `COUPLING_HIDDEN_{type}*` hypotheses

#### Pattern 3: Invariant Violation Paths (v2.1 Pre-computed)
- **Source**: `invariantFunctionMap.violationPaths[]`
- **Filter**: Feasibility ≠ impossible
- **Output**: `VIOL_PATH_*` hypotheses with execution steps

#### Pattern 3.5: Protection Gap Exploitation (v2.1 NEW)
- **Source**: `invariantFunctionMap.protectionGaps[]`
- **Filter**: Severity = critical/high
- **Output**: `PROTECT_GAP_*` hypotheses

#### Pattern 4: Top State Intersections
- **Source**: `topStateIntersections.intersections[]` (top 5)
- **Analysis**: Permissionless participants, writer functions
- **Output**: `COUPLING_TOP_{rank}` hypotheses

#### Pattern 5: Hidden Assumption Exploitation (v2.1 NEW)
- **Source**: `hiddenAssumptions.assumptions[]` (top 10 by exploitability)
- **Filter**: Exploitability = trivial or easy
- **Output**: `ASSUMP_*` hypotheses

#### Pattern 6: Variable Classification Targeting (v2.1 NEW)
- **Source**: `variableClassification.classifications[]` (top 8 sensitive)
- **Filter**: Has permissionless writers
- **Output**: `VAR_TARGET_{var}_{contract}` hypotheses

### Sample Output Structure

```javascript
{
    id: 'COUPLING_STRONG_StakingRewards_stake',
    type: 'strong_coupling_exploitation',
    description: 'Exploit STRONG coupling (85/100) between stake → getReward',
    attackIdea: 'Call stake() to manipulate shared state, then getReward()...',
    prerequisiteChain: [
        'Functions share 3 variables via direct-state dependency',
        'stake() is permissionless',
        'Risk factors: value-bearing, no-atomicity-guard'
    ],
    trackatorEvidence: {
        couplingStrength: 85,
        sharedVariables: ['_balances', '_totalSupply', 'rewardPerTokenStored'],
        valueBearingInvolved: true
    },
    estimatedDifficulty: 'easy',
    priorityBoost: 15,
    status: 'HYPOTHESIS'
}
```

> **Full implementation (~500 lines)**: See [references/code-examples.md](../references/code-examples.md#state-coupling-analysis)

---

## Plugin: Intelligent Plugin Router (v2.1 NEW)

**Purpose**: Route hypotheses to the most effective analysis plugin based on **Trackator evidence type and criticality**.

### Routing Matrix

| Source/Type | Primary Plugin | Secondary Plugins | Priority Boost | Notes |
|-------------|---------------|-------------------|-----------------|-------|
| `coupling-critical-findings` | fork_tester | evidence_validator | Base+100 | Pre-validated high severity |
| `coupling_cluster_exploitation` | assumption_breaker | reverse_engineering, coupling_analyzer | Base+70 | Multi-function testing needed |
| `protection_gap_exploitation` | pattern_matcher | reachability_checker | Base+80 | Skip intent filter |
| `invariant_violation_path` | execution_tracer | evidence_validator | Base+75 | Follow pre-computed path |
| `hidden_assumption_exploitation` | assumption_breaker | reverse_engineering | Base+65 | Perfect match |
| `sensitive_variable_targeting` | reverse_engineering | coupling_analyzer | Base+60 | Follow value flow |
| `hidden_coupling_(proxy/delegatecall/slot)` | pattern_matcher | reachability_checker, fork_tester | Base+85 | High-risk types |
| Other `hidden_coupling_*` | reachability_checker | pattern_matcher | Base+55 | Verify reachability first |
| Standard types | *varies* | - | Base+50 | Default routing |

### Batch Routing Output

```javascript
{
    total: 42,
    byPlugin: { fork_tester: 8, assumption_breaker: 12, ... },
    byPriority: { critical: [], high: [], medium: [], low: [] },
    skippedIntentFilter: ['PROTECT_GAP_1', ...],  // Pre-validated gaps
    routedAttacks: [{ ...attack, routing: {...} }]
}
```

> **Full implementation**: See [references/code-examples.md](../references/code-examples.md#intelligent-plugin-router)

---

## Phase 3 Output (v2.1 ENHANCED)

### Core Output Fields

```javascript
hypothesis.status = 'TESTED';
hypothesis.creativeFindings = [];      // Reverse engineering results
hypothesis.assumptionBreaks = [];       // Assumption breaker results  
hypothesis.couplingAttacks = [];         // v2.1: State coupling analysis
hypothesis.desyncAttacks = [];          // v2.0: Sync analyzer attacks
hypothesis.executionTrace = {};         // Full trace object
hypothesis.traceConclusion = { survives: boolean, reason: string };
```

### v2.1 New: Plugin Routing Results

```javascript
hypothesis.pluginRouting = {
    primaryPlugin: string,           // Which plugin handles this
    secondaryPlugins: string[],      // Supporting plugins
    routingRationale: string,       // Why routed this way
    priority: number,               // 0-100 priority score
    estimatedValue: 'critical' | 'high' | 'medium' | 'low'
};
```

### v2.1 New: Evidence Calibration (Fix D Integration)

```javascript
hypothesis.evidenceCalibration = {
    // 6-Class Classification
    classification: 'proven-property' | 'potential-bug' | 'reachable-bug' | 
                    'false-positive' | 'by-design' | 'insufficient-evidence',
    classificationConfidence: number,  // 0-100%
    
    // Reachability Analysis
    reachability: 'reachable' | 'unreachable' | 'unknown',
    blockingRequirement: { requirement, type, whyBlocking, potentialBypass } | null,
    
    // Disproof Analysis
    disproofResult: FinalVerdict | null,
    disproofConfidence: number,      // 0-100%
    
    // Multi-Dimensional Confidence
    confidenceBreakdown: {
        overall: number,              // 0-100 composite
        evidenceStrength: number,
        reachabilityConfidence: number,
        impactConfidence: number,
        falsePositiveRisk: number     // Higher = more likely FP
    },
    
    // Proof Requirements (9-criteria)
    proofRequirements: {
        met: number,
        total: 9,
        status: 'proven-reachable' | 'not-proven' | 'disproven' | 'insufficient-evidence'
    },
    
    // Final Verdict (aligns with Trackator FinalVerdict enum)
    finalVerdict: 'confirmed-vulnerability' | 'potential-vulnerability' | 
                  'false-positive' | 'by-design' | 'cannot-determine' | 'deferred',
    recommendedAction: 'immediate-fix' | 'short-term-investigation' | 
                       'long-term-monitoring' | 'accept-risk' | 'dismiss' | 
                       'escalate-to-auditor' | 'defer'
};
```

### v2.0 → v2.1 Schema Changes

| Field | v2.0 | v2.1 | Source |
|-------|------|------|--------|
| `classification` | Simple string | 6-class enum from Fix D | `classificationRegistry` |
| `confidence` | Single number | Multi-dimensional breakdown | `confidenceAssessments.scoreBreakdown` |
| `reachability` | Basic boolean | Full path + cross-contract prereqs | `reachabilityAnalysis[]` |
| `disproof` | Basic result | Strategy-by-strategy confidence | `disproofEngine.results[]` |
| `verdict` | Manual derivation | From Trackator `finalVerdict` | `finalVerdict.verdicts[]` |
| `action` | Not present | `recommendedAction` enum | `finalVerdict.verdicts[].recommendedAction` |

> **Full structure definitions**: See [references/trackator-fields.md](../references/trackator-fields.md#evidence-calibration)

---

## 🔒 Gating Condition (BUG FIXED)

**✅ FIXED**: Removed duplicate gating condition. Only the complete version is retained:

> **Only hypotheses where `traceConclusion.survives === true` AND `evidenceCalibration.finalVerdict !== 'false-positive'` proceed to Phase 4.**

### Bug Details (Original Lines 2058-2060)

| Line | Original Text | Action |
|------|---------------|--------|
| 2058 | `survives === true AND evidenceCalibration.finalVerdict !== 'false-positive'` | ✅ **KEPT** (complete version) |
| 2060 | `survives === true` only | ❌ **REMOVED** (duplicate/incomplete) |

The first version is more correct as it includes both the trace survival check AND the evidence calibration false-positive filter.

---

## Quick Reference: Phase 3 Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PHASE 3: CREATIVE ATTACK                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. REVERSE ENGINEERING                                              │
│     └── Assets at risk → Money flows → Manipulation points           │
│                                                                      │
│  2. ASSUMPTION BREAKER                                               │
│     └── Trust assumptions → External-only breaks → Desync risks      │
│                                                                      │
│  3. ★ FULL EXECUTION TRACE (MANDATORY)                              │
│     └── Call stack DFS → CEI analysis → Reentrancy check             │
│     └── Output: traceConclusion = { survives, reason, severity }     │
│                                                                      │
│  4. STATE COUPLING ANALYSIS (v2.1)                                  │
│     └── Critical findings → Clusters → Hidden couplings              │
│     └── Invariant violations → Protection gaps → Assumptions        │
│     └── Variable targeting → Top intersections                       │
│                                                                      │
│  5. INTELLIGENT PLUGIN ROUTER (v2.1)                                │
│     └── Route each hypothesis to optimal analysis plugin            │
│     └── Set priority, estimate value, flag intent-filter skips       │
│                                                                      │
│  6. EVIDENCE CALIBRATION (v2.1)                                     │
│     └── 6-class classification → Reachability → Disproof             │
│     └── Multi-dimensional confidence → Final verdict                 │
│                                                                      │
│  GATING: survives=true AND verdict≠false-positive → PHASE 4          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

*End of Phase 3: CREATIVE ATTACK*
