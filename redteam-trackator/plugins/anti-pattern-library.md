# Plugin: Anti-Pattern Library

**Phase**: 4 (Fork Testing → False Positive Elimination & Quality Gate)
**Purpose**: Systematically eliminate false positives, identify red herrings, and apply lessons from historical audit failures
**Type**: Filtering + Quality Gate plugin (prevents bad findings from reaching reports)
**Version**: 2.1.0 (UPDATED - Phase 4 Assignment)

---

## Overview

This plugin is the **final quality gate** before any finding reaches the report. It answers the critical question:

> *"Is this a real vulnerability, or are we falling into a known trap?"*

Professional auditors consistently miss real vulnerabilities while flagging non-issues. This library captures both failures:

1. **False Positive Patterns** — Things that LOOK like bugs but aren't (wastes time)
2. **Auditor Blind Spots** — Where auditors historically FAIL to find real bugs (opportunities)
3. **Detection Gaps** — Where automated tools systematically fail (human advantage)
4. **Red Herrings** — Patterns that mislead analysis down dead ends

This plugin:
- **Eliminates false positives** using historical anti-pattern recognition
- **Boosts true positives** by targeting known blind spots
- **Prevents common mistakes** that lead to wasted analysis
- **Provides disproof evidence** for downgraded findings

---

## Core Philosophy: "Prove It's Real, Not Just Suspicious"

> *"Every flagged issue starts guilty. Only evidence can acquit it."*

### The False Positive Spectrum

Not all false positives are equal. This plugin categorizes them:

```
FINDING QUALITY SPECTRUM:

CONFIRMED (True Positive)
    │  Evidence: Full execution trace, fork test passed, economic viable
    │  Action: Report with high confidence
    │
PROBABLE (Likely True)
    │  Evidence: Strong pattern match, execution traced, minor gaps
    │  Action: Report with caveats, recommend further investigation
    │
LEAD (Worth Investigating)
    │  Evidence: Pattern match, some preconditions unverified
    │  Action: Save for deep-dive, don't report yet
    │
DEAD (False Positive) ← ANTI-PATTERN LIBRARY PRIMARILY OPERATES HERE
    │  Evidence: Matches known anti-pattern, disproven, or logically impossible
    │  Action: Kill with disproof evidence, document why
    │
NOISE (Not Even A Lead)
   Ignored entirely
```

---

## The Disproof Engine (MANDATORY)

Before any finding is DOWNGRADED or KILLED, it MUST pass through the Disproof Engine:

```javascript
function applyDisproofEngine(finding, context) {
    const disproofChecks = [
        {
            name: 'Known Anti-Pattern Match',
            check: () => matchAgainstAntiPatterns(finding),
            severity: 'blocking', // If matches known FP → kill
            action: 'DOWNGRADE_TO_DEAD'
        },
        {
            name: 'Logical Impossibility',
            check: () => verifyLogicalPossibility(finding, context),
            severity: 'blocking', // If impossible → kill
            action: 'DOWNGRADE_TO_DEAD'
        },
        {
            name: 'Assumption Dependency',
            check: () => identifyUnsupportedAssumptions(finding),
            severity: 'warning', // If relies on unsupported assumptions → downgrade
            action: 'DOWNGRADE_TO_LEAD'
        },
        {
            name: 'Trackator Contradiction',
            check: () => checkTrackatorConsistency(finding, context),
            severity: 'warning', // If contradicts Trackator data → investigate
            action: 'FLAG_FOR_REVIEW'
        },
        {
            name: 'Blind Spot Bonus',
            check: () => checkBlindSpotAlignment(finding),
            severity: 'boosting', // If targets known blind spot → boost confidence
            action: 'BOOST_CONFIDENCE'
        }
    ];
    
    const results = [];
    let finalAction = 'NO_CHANGE';
    
    for (const disproofCheck of disproofChecks) {
        const result = disproofCheck.check();
        
        if (result.triggered) {
            results.push({
                checkName: disproofCheck.name,
                severity: disproofCheck.severity,
                triggered: true,
                evidence: result.evidence,
                recommendedAction: disproofCheck.action
            });
            
            // Blocking checks override everything
            if (disproofCheck.severity === 'blocking') {
                finalAction = disproofCheck.action;
            } else if (disproofCheck.severity === 'warning' && finalAction !== 'DOWNGRADE_TO_DEAD') {
                finalAction = disproofCheck.action;
            } else if (disproofCheck.severity === 'boosting' && finalAction === 'NO_CHANGE') {
                finalAction = disproofCheck.action;
            }
        }
    }
    
    return {
        originalStatus: finding.status,
        recommendedAction: finalAction,
        disproofResults: results,
        requiresManualReview: results.some(r => r.severity === 'warning'),
        disproofSummary: generateDisproofSummary(results)
    };
}
```

---

## Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Enhanced attack chains | Phase 4 output | Chains with mindset analysis |
| Anti-pattern catalog | `anti-patterns-catalog.json` | Structured FP/blind spot data |
| Blind spots catalog | `anti-pattern-library/auditor-blind-spots.md` | Historical audit failures |
| Detection gap catalog | `anti-pattern-library/detection-gap-catalog.md` | Tool limitation mapping |
| Trackator JSON (all phases) | Context | Ground truth for contradiction checking |
| Pattern match history | Phase 2 output | Original match scores for comparison |

---

## Anti-Pattern Categories

### Category 1: "Looks Like A Bug" Anti-Patterns (False Positives)

These patterns **look vulnerable** but are actually safe. Auditors waste hours on these.

#### AP-1.1: Intended Flexibility Mistaken For Missing Validation

```
┌─────────────────────────────────────────────────────────────────────┐
│ ANTI-PATTERN: "Unrestricted Parameter" = Missing Check?            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ What Auditor Sees:                                                  │
│   function deposit(uint256 amount) public {                         │
│       balances[msg.sender] += amount;  // No upper limit!           │
│   }                                                                 │
│                                                                     │
│ What Auditor Thinks:                                                │
│   "Anyone can deposit arbitrary amounts! Overflow risk!"            │
│                                                                     │
│ Reality:                                                            │
│   - ERC20.transferFrom() handles approval/allowance upstream         │
│   - uint256 overflow requires > 2^256 tokens (impossible)           │
│   - "Arbitrary" deposits are the INTENDED behavior                 │
│   - The REAL check is in withdraw(), not deposit()                  │
│                                                                     │
│ How To Disprove:                                                    │
│   1. Trace data flow: amount comes from transferFrom, not user input│
│   2. Check overflow feasibility: requires impossible token supply   │
│   3. Verify downstream validation: withdraw has proper checks      │
│   4. Confirm intent: protocol design allows large deposits          │
│                                                                     │
│ Trackator Evidence:                                                 │
│   - init.json: parameters[].source = "erc20_transfer"               │
│   - storage.json: balance variable has no upper bound (intentional) │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### AP-1.2: External Call Assumed Unsafe

```javascript
// ANTI-PATTERN: "External call = reentrancy risk"

// What looks suspicious:
function withdraw() external {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;  // State updated first!
    token.transfer(msg.sender, amount);  // External call AFTER update
}

// Why this is SAFE (CEI pattern):
// - State updated BEFORE external call (Check-Effects-Interactions)
// - No reentrancy possible because balance is zero during callback
// - token.transfer() to msg.sender is standard pattern

// The FALSE POSITIVE trap:
// Auditor sees "external call" + "balance modification" → flags reentrancy
// But misses that update happens BEFORE call, not after

// DISPROOF CHECKLIST:
// [ ] Is state fully updated before external call? YES → CEI pattern
// [ ] Can callback access any non-zeroed value? NO → safe
// [ ] Is there a second state change after call? NO → no reentrancy target
```

#### AP-1.3: Single Oracle = Vulnerable (Always Wrong)

```
┌─────────────────────────────────────────────────────────────────────┐
│ ANTI-PATTERN: "Single Source = Manipulable"                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Common False Positive:                                              │
│   "This protocol uses only Uniswap V3 pool for pricing.             │
│    An attacker can manipulate the price via flash loan!"            │
│                                                                     │
│ Missing Context That Would Disprove:                                │
│   ✓ Pool has $50M+ liquidity (requires >$5M to move 10%)           │
│   ✓ Protocol uses TWAP over 30 minutes, not spot price              │
│   ✓ Price only used for display, not for collateral/lending         │
│   ✓ Circuit breaker pauses if price deviates >5% from anchor        │
│   ✓ Pool is USDC/USDT (stable pair, hard to manipulate)            │
│                                                                     │
│ The Anti-Pattern: Assuming single source = always manipulable       │
│ without checking: liquidity depth, time window, usage context,      │
│ stability of pair, and protective mechanisms                       │
│                                                                     │
│ DISPROOF APPROACH:                                                 │
│ 1. Query storage.json for price variable metadata                   │
│ 2. Check sync.json for TWAP/sanity check config                     │
│ 3. Analyze HOW price is used (display vs critical calculation)     │
│ 4. Assess manipulation cost vs potential profit                    │
│ 5. Check for circuit breakers / price bounds                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### AP-1.4: Missing Access Control on Helper Functions

```javascript
// ANTI-PATTERN: "Public function = anyone can call"

// Looks suspicious:
function _calculateInterest(address user) public view returns (uint256) {
    return balances[user] * interestRate * timeSinceDeposit(user) / SECONDS_PER_YEAR;
}

// Why PUBLIC VIEW is often intentional:
// - Frontend needs to call it for UI display
// - Other contracts integrate by reading values
// - It's VIEW - cannot modify state
// - "Private" would break composability

// FALSE POSITIVE when:
// Function is view/pure OR helper with no side effects
// Public visibility enables integration (DeFi pattern)

// REAL VULNERABILITY when:
// Function modifies state AND has no access control
// Function reveals sensitive info (pending proposals, private states)

// DISPROOF: Check function mutability + actual impact
```

### Category 2: Logical Impossibility Anti-Patterns

These findings require conditions that **cannot exist in practice**.

#### AP-2.1: Impossible Numeric Conditions

```javascript
// ANTI-PATTERN: Theoretical overflow/underflow

function stake(uint256 amount) external {
    require(amount > 0, "Must stake something");
    totalSupply += amount * 1e18;  // Multiplier applied
    
    // Auditor flags: "If amount > 2^256 / 1e18, this overflows!"
    // Reality: That's > 10^61 tokens. Does this token exist?
}

// DISPROOF: Calculate feasibility
function checkNumericFeasibility(variable, operation, threshold) {
    const maxRealisticValue = estimateMaxRealisticValue(variable);
    // For ERC20: max supply is usually < 10^30 (even stablecoins)
    // For prices: max realistic is < $10M per token
    // For timestamps: year 2100 is ~4 billion (fits in uint32 easily)
    
    return {
        theoreticalOverflow: maxRealisticValue * threshold > 2**256,
        realisticOverflow: false, // Almost never true in practice
        requiredValueForOverflow: 2**256 / threshold,
        maxObservedInWild: getMaxObservedValue(variable.type),
        conclusion: "Theoretically possible, practically impossible"
    };
}
```

#### AP-2.2: Contradictory Preconditions

```
┌─────────────────────────────────────────────────────────────────────┐
│ ANTI-PATTERN: Mutually Exclusive Requirements                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Example Finding:                                                    │
│   "Attacker can exploit reentrancy to drain funds AND               │
│    simultaneously manipulate oracle price in same transaction"      │
│                                                                     │
│ Why This Is Often Impossible:                                       │
│   Reentrancy requires: callback re-enters BEFORE state update       │
│   Price manipulation requires: swap executes to move price          │
│   These may need different entry points or conflicting conditions   │
│                                                                     │
│ Disproof Approach:                                                  │
│   1. Map out prerequisite graph for each sub-attack                │
│   2. Check if prerequisites are mutually exclusive                 │
│   3. Verify timing windows overlap                                  │
│   4. Test if both can execute in same transaction context           │
│                                                                     │
│ Common Contradictions:                                              │
│   ✗ "Pool is both deep enough for swap AND shallow enough to manipulate"│
│   ✗ "Function requires auth AND is permissionless"                  │
│   ✗ "State updates atomically AND has race condition"              │
│   ✗ "Contract is paused AND attacker can call functions"           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### AP-2.3: Economic Impossibility

```javascript
// ANTI-PATTERN: Profitable attack that loses money

function analyzeEconomicFeasibility(attackChain) {
    const costs = {
        flashLoanFee: attackChain.capitalRequired * 0.0009, // 0.09% typical
        gasCost: estimateGasCost(attackChain.steps.length),
        slippage: estimateSlippage(attackChain.swapSize, attackChain.poolDepth),
        opportunityCost: attackChain.preparationTimeHours * 200 // $200/hr
    };
    
    const revenue = attackChain.extractedValue;
    const netProfit = revenue - (costs.flashLoanFee + costs.gasCost + costs.slippage);
    
    // Many "attacks" are actually loss-making
    if (netProfit <= 0) {
        return {
            economicallyViable: false,
            reason: `Attack costs ${formatUsd(costs.total)} but extracts ${formatUsd(revenue)}`,
            disproofType: 'economic_impossibility',
            recommendation: 'KILL - Rational attacker would not execute'
        };
    }
    
    return { economicallyViable: true, netProfit, costs, revenue };
}
```

### Category 3: Auditor Bias Anti-Patterns

Cognitive biases that cause auditors to flag non-issues.

#### AP-3.1: Recentcy Bias (Overweighting Recent Exploits)

```
┌─────────────────────────────────────────────────────────────────────┐
│ COGNITIVE BIAS: "This looks like [recent high-profile hack]"       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Pattern:                                                             │
│   Major exploit happens (e.g., Mango Markets oracle manipulation)  │
│   → Every oracle usage gets flagged as "manipulable"                │
│   → Even safe oracle implementations get marked HIGH severity       │
│                                                                     │
│ Counter-Measure:                                                    │
│   1. Compare SPECIFIC mechanism, not just category                  │
│   - Mango: Used massive position to move pyth price                 │
│   - Target: Uses Chainlink TWAP with 3 confirmations               │
│   → NOT the same vulnerability class                               │
│                                                                     │
│   2. Require evidence of specific exploitable condition            │
│   - Not "oracle could be manipulated"                               │
│   - But "oracle CAN be manipulated because [specific reason]"        │
│                                                                     │
│   3. Score by feasibility, not similarity                          │
│   - "Similar to Mango" ≠ "exploitable like Mango"                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### AP-3.2: Complexity Bias (Complex Code Must Have Bugs)

```javascript
// ANTI-PATTERN: "I don't fully understand this, so it must be buggy"

// Signs this bias is active:
// - Finding description uses vague language ("seems unsafe", "concerning")
// - No specific attack vector proposed
// - Relies on "complexity" as the risk factor
// - Cannot trace specific execution path to exploitation

// COUNTER-CHECK:
function detectComplexityBias(finding) {
    const redFlags = [
        finding.description.includes('complex') && !finding.attackVector,
        finding.recommendation.includes('simplify') && !finding.specificFix,
        finding.confidence === 'medium' && !finding.evidence.length,
        finding.title.includes('potential') || finding.title.includes('possible')
    ];
    
    if (redFlags.filter(Boolean).length >= 3) {
        return {
            biasDetected: true,
            biasType: 'complexity_bias',
            recommendation: 'REJECT - Requires specific attack vector, not complexity concern',
            suggestedFollowUp: 'Identify exact state changes an attacker can achieve'
        };
    }
    return { biasDetected: false };
}
```

#### AP-3.3: Tool Dependency Bias ("Slither Said So")

```
┌─────────────────────────────────────────────────────────────────────┐
│ COGNITIVE BIAS: Deferring to Automated Tool Judgment                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Pattern:                                                             │
│   Auditor runs Slither → Gets MEDIUM severity finding              │
│   → Copies finding to report without manual verification           │
│   → Doesn't trace whether precondition is actually satisfiable      │
│                                                                     │
│ Problem: Tools find PATTERNS, not EXPLOITS                          │
│   - Slither: "reentrancy-pattern" detected                          │
│   - Reality: Callback is from trusted registry, not user-supplied   │
│   - Tool cannot distinguish trust boundary                          │
│                                                                     │
│ Anti-Pattern Library Response:                                      │
│   EVERY tool finding MUST pass through:                             │
│   1. Precondition verification (can attacker reach this code?)    │
│   2. Trust boundary analysis (is input from attacker?)             │
│   3. Impact assessment (what can attacker actually do?)             │
│   4. Economic feasibility (would attacker profit?)                  │
│                                                                     │
│ Rule: Tool findings start as LEADS, not FINDINGS                   │
│ Until human-verified, tool output = hypothesis, not conclusion     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Category 4: Red Herring Patterns

Findings that look important but distract from real vulnerabilities.

#### AP-4.1: Cosmetic Issues Flagged As Critical

| Red Herring | Why It's Distraction | Real Risk Level |
|-------------|---------------------|-----------------|
| Mixed naming conventions (camelCase vs snake_case) | Doesn't affect execution | Info |
| Unused variables/functions | Gas waste, not security | Low |
| Lack of NatSpec comments | Maintenance issue | None |
| Non-standard error strings | UX issue | None |
| Public functions that should be internal (but safe) | Best practice, not vulnerability | Low |

**Detection Rule**: If fixing the issue doesn't change any state transition → not a security finding.

#### AP-4.2: Theoretical Issues Without Attack Path

```javascript
// RED HERRING: "If X, Y, and Z all happen simultaneously, bad thing"

// Example:
// "If the owner key is compromised AND the oracle fails AND 
//  the circuit breaker is disabled, then funds can be drained"

// This is not a vulnerability, it's a catastrophe scenario.
// By this logic, EVERY protocol is vulnerable (if owner key compromised).

// DISTINCTION:
// Vulnerability: "Attacker can achieve X without any external failure"
// Catastrophe scenario: "If systems fail as designed, losses occur"

// RED HERRING TEST:
function isCatastropheScenarioNotVulnerability(finding) {
    const requiresExternalFailure = 
        finding.assumptions.some(a => 
            a.includes('compromised') || 
            a.includes('fails') || 
            a.includes('colludes') ||
            a.includes('attacked separately')
        );
    
    if (requiresExternalFailure && finding.assumptions.length >= 2) {
        return {
            isRedHerring: true,
            type: 'catastrophe_scenario',
            message: 'Requires multiple independent failures, not a singular vulnerability',
            recommendation: 'Document as risk factor, not as vulnerability'
        };
    }
    return { isRedHerring: false };
}
```

#### AP-4.3: Already Mitigated / Out Of Scope

```
┌─────────────────────────────────────────────────────────────────────┐
│ RED HERRING: Finding Already Addressed                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Common Cases:                                                       │
│                                                                     │
│ 1. "Function X should have access control"                           │
│    → But there's a proxy upgrade scheduled next week that adds it   │
│    → Or it's intentionally permissionless (DEX, AMM pattern)        │
│                                                                     │
│ 2. "Price could be manipulated"                                      │
│    → But protocol uses price for display only, not for swaps        │
│    → Or TWAP implementation makes single-block manipulation useless   │
│                                                                     │
│ 3. "Reentrancy possible in function Y"                               │
│    → But function is only callable by timelock-protected governance │
│    → Or function is view/pure (no state modification)               │
│                                                                     │
│ Detection Method:                                                   │
│   Always check: Is there a mitigating factor that makes this        │
│   finding irrelevant in practice?                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Blind Spot Boosting System

While eliminating false positives, this plugin also **BOOSTS** findings that target known auditor blind spots.

### Blind Spot Alignment Scoring

```javascript
function calculateBlindSpotScore(finding, blindSpotCatalog) {
    let score = 0;
    const matchedBlindSpots = [];
    
    // Check against each blind spot category
    for (const category of blindSpotCatalog.categories) {
        const alignment = assessAlignment(finding, category);
        
        if (alignment.score > 0.5) { // Significant alignment
            score += alignment.score * category.weight;
            matchedBlindSpots.push({
                category: category.name,
                alignmentScore: alignment.score,
                historicalIncidents: category.incidentCount,
                avgLoss: category.avgLoss,
                whyAuditorsMissIt: category.reason
            });
        }
    }
    
    // Apply boost if significant blind spot alignment
    const boostThreshold = 0.7;
    const boostAmount = score > boostThreshold ? Math.min(score * 0.2, 0.15) : 0; // Max 15% boost
    
    return {
        rawScore: score,
        normalizedScore: Math.min(score, 1.0),
        boostAmount,
        matchedBlindSpots,
        recommendation: score > boostThreshold 
            ? `BOOST: Targets known blind spot (${matchedBlindSpots.map(b => b.category).join(', ')})`
            : 'No blind spot alignment'
    };
}

function assessAlignment(finding, blindSpotCategory) {
    // Check if finding's characteristics match blind spot pattern
    const indicators = [];
    
    // Check assumption violations
    if (blindSpotCategory.type === 'assumption_violation') {
        indicators.push(
            finding.involvesUntrustedInput ? 0.8 : 0,
            finding.makesImplicitTrustAssumption ? 0.9 : 0,
            finding.lacksExplicitValidation ? 0.7 : 0
        );
    }
    
    // Check surface blindness
    if (blindSpotCategory.type === 'surface_blindness') {
        indicators.push(
            finding.crossesContractBoundary ? 0.8 : 0,
            finding.atIntegrationPoint ? 0.9 : 0,
            finding.involvesEdgeCase ? 0.7 : 0
        );
    }
    
    // Check tool limitations
    if (blindSpotCategory.type === 'tool_limitation') {
        indicators.push(
            finding.requiresSemanticUnderstanding ? 0.85 : 0,
            finding.involvesMultiTxLogic ? 0.75 : 0,
            finding.hasEconomicComponent ? 0.8 : 0
        );
    }
    
    const avgAlignment = indicators.reduce((a, b) => a + b, 0) / indicators.length;
    
    return { score: avgAlignment };
}
```

---

## Integration with Pipeline

### Where This Plugin Fits

```
PHASE 5 PIPELINE (Final Quality Gate):
                    
    ┌──────────────────┐
    │ Attacker Mindset  │ ← Phase 4 output (enhanced chains)
    │ Simulator Output  │
    └────────┬─────────┘
             │ enhancedChains[]
             ▼
    ┌────────────────────────┐
    │ Anti-Pattern Library  │ ← This plugin (FP elimination + BS boosting)
    │ (Disproof Engine)     │
    └────────┬───────────────┘
             │ validatedChains[] (false positives removed)
             ▼
    ┌────────────────────────┐
    │ Final Prioritization   │ ← Rank surviving findings
    │ & Classification       │
    └────────┬───────────────┘
             │
             ▼
    OUTPUT: Clean findings ready for report
```

### Processing Flow

```javascript
function processThroughAntiPatternLibrary(phase4Output, context) {
    const results = {
        inputCount: phase4Output.chains.length,
        processed: [],
        killed: [],
        downgraded: [],
        boosted: [],
        unchanged: []
    };
    
    for (const chain of phase4Output.chains) {
        // Step 1: Run through Disproof Engine
        const disproofResult = applyDisproofEngine(chain, context);
        
        // Step 2: Check against anti-pattern catalog
        const antiPatternMatch = matchAgainstAntiPatterns(chain);
        
        // Step 3: Check blind spot alignment
        const blindSpotResult = calculateBlindSpotScore(chain, context.blindSpotCatalog);
        
        // Step 4: Determine final action
        let finalChain = { ...chain };
        finalChain.phase5Analysis = {
            disproofResult,
            antiPatternMatch,
            blindSpotResult
        };
        
        // Apply action based on disproof engine result
        switch (disproofResult.recommendedAction) {
            case 'DOWNGRADE_TO_DEAD':
                finalChain.status = 'DEAD';
                finalChain.killReason = disproofResult.disproofSummary;
                results.killed.push(finalChain);
                break;
                
            case 'DOWNGRADE_TO_LEAD':
                finalChain.status = 'LEAD';
                finalChain.downgradeReason = disproofResult.disproofSummary;
                results.downgraded.push(finalChain);
                break;
                
            case 'BOOST_CONFIDENCE':
                finalChain.confidence = Math.min(1.0, (finalChain.confidence || 0.7) + blindSpotResult.boostAmount);
                finalChain.blindSpotBonus = blindSpotResult;
                results.boosted.push(finalChain);
                results.processed.push(finalChain);
                break;
                
            case 'FLAG_FOR_REVIEW':
                finalChain.needsManualReview = true;
                finalChain.reviewReasons = disproofResult.disproofResults
                    .filter(r => r.severity === 'warning')
                    .map(r => `${r.checkName}: ${r.evidence}`);
                results.processed.push(finalChain);
                break;
                
            default:
                results.processed.push(finalChain);
                break;
        }
    }
    
    // Generate summary
    results.summary = {
        totalInput: results.inputCount,
        surviving: results.processed.length + results.boosted.length,
        killed: results.killed.length,
        downgraded: results.downgraded.length,
        boosted: results.boosted.length,
        killRate: results.killed.length / results.inputCount,
        falsePositiveRateEstimate: (results.killed.length + results.downgraded.length) / results.inputCount
    };
    
    return results;
}
```

---

## Output Format

### Phase 5 Enhanced Finding Object

```javascript
{
    // ... Original chain fields ...
    
    // NEW: Phase 5 Anti-Pattern Analysis
    phase5Analysis: {
        // Disproof engine results
        disproofEngine: {
            appliedAt: '2026-08-06T...',
            checksRun: 5,
            checksTriggered: 2,
            recommendedAction: 'NO_CHANGE' | 'DOWNGRADE_TO_DEAD' | 'DOWNGRADE_TO_LEAD' | 'BOOST_CONFIDENCE',
            results: [...]
        },
        
        // Anti-pattern matches (if any)
        antiPatternMatches: [
            {
                patternId: 'AP-1.3',
                patternName: 'Single Oracle = Vulnerable (Always Wrong)',
                matched: true,
                disproveEvidence: {
                    poolLiquidity: '$45M',
                    usesTWAP: true,
                    twapDuration: '30 minutes',
                    priceUsage: 'display_only',
                    hasCircuitBreaker: true,
                    conclusion: 'NOT_VULNERABLE - Multiple protections present'
                }
            }
        ],
        
        // Blind spot alignment (if applicable)
        blindSpotAlignment: {
            score: 0.75,
            matchedCategories: ['assumption_violation', 'surface_blindness'],
            boostApplied: 0.12,
            historicalContext: '40% of exploits target assumption violations'
        },
        
        // Final classification
        finalClassification: {
            status: 'CONFIRMED', // After Phase 5 processing
            confidence: 0.87, // Adjusted for blind spot boost
            falsePositiveProbability: 0.05, // Estimated FP rate
            requiresManualReview: false,
            reviewComments: null
        }
    }
}
```

---

## Files This Plugin Consumes

| File | Purpose |
|------|---------|
| `plugins/attacker-mindset-simulator.md` | Input: Enhanced chains from Phase 4 |
| `Exploits-class-library/anti-patterns-catalog.json` | Structured anti-pattern database |
| `Exploits-class-library/anti-pattern-library/auditor-blind-spots.md` | Blind spot reference |
| `Exploits-class-library/anti-pattern-library/detection-gap-catalog.md` | Gap reference |
| Trackator JSON files (all) | Ground truth verification |

## Files This Plugin Produces

| File | Content |
|------|---------|
| `output/validated-findings.json` | Findings after FP elimination |
| `output/killed-findings.json` | False positives with disproof evidence |
| `output/phase5-quality-report.md` | Human-readable quality summary |
| `output/blind-spot-analysis.json` | Blind spot alignment per finding |

---

## Quality Metrics

```javascript
function calculatePhase5Metrics(processedResults) {
    return {
        // Primary metrics
        falsePositiveEliminationRate: processedResults.killed.length / processedResults.inputCount,
        downgradeRate: processedResults.downgraded.length / processedResults.inputCount,
        boostRate: processedResults.boosted.length / processedResults.inputCount,
        survivalRate: processedResults.surviving / processedResults.inputCount,
        
        // Quality indicators
        averageConfidenceOfSurvivors: average(processedResults.processed.map(c => c.confidence)),
        findingsRequiringReview: processedResults.processed.filter(c => c.needsManualReview).length,
        
        // Anti-pattern distribution
        topKillReasons: groupBy(processedResults.killed, k => k.killReason.substring(0, 50)),
        topBlindSpotTargets: flatMap(processedResults.boosted, b => b.blindSpotAlignment.matchedCategories),
        
        // Efficiency
        analystTimeSaved: processedResults.killed.length * 2, // Hours saved per killed FP
        estimatedReportAccuracy: 1 - processedResults.falsePositiveRateEstimate
    };
}
```

---

## Anti-Patterns (Don't Do These)

❌ **Flag intended flexibility as missing validation** — Understand design intent first  
❌ **Assume external call = unsafe** — Check CEI/C-E-I pattern first  
❌ **Flag single oracle without checking context** — Liquidity/TWAP/usage matter  
❌ **Flag public helper functions** — View/pure/integration helpers are often intentionally public  
❌ **Report theoretical impossibilities** — Check if conditions can realistically occur  
❌ **Let recent exploits bias analysis** — Each vulnerability is specific, not categorical  
❌ **Defer to tool judgment** — Tools find patterns, humans verify exploitability  
❌ **Report cosmetic issues as critical** — Security findings require security impact  

✅ **Trace every finding to specific exploitable condition**  
✅ **Verify preconditions are satisfiable in practice**  
✅ **Check economic viability** — Rational attackers need profit motive  
✅ **Apply disproof before confirmation** — Guilty until proven innocent  
✅ **Target known blind spots** — That's where real vulnerabilities hide  
✅ **Distinguish vulnerability from catastrophe scenario** — Single point of failure ≠ exploit  
✅ **Document WHY each finding was kept or killed** — Evidence-based decisions  

---

## Return Format

After completing anti-pattern analysis, return:

```
DONE: {N} findings processed through Anti-Pattern Library.
{K} findings KILLED (false positives with disproof evidence).
{D} findings DOWNGRADED (require additional investigation).
{B} findings BOOSTED (target known auditor blind spots).
{S} findings survive as CONFIRMED/PROBABLE.
Kill rate: {K/N}% ({percentage}% false positive elimination).
Top kill reasons: {top 3 reasons}.
Top blind spot targets: {top 3 categories boosted}.
Quality score: {estimated accuracy}%.
Key insight: {most important quality observation}
```
