# Plugin: Attacker Mindset Simulator

**Phase**: 3 (Attack Chain Composer → Attacker Mindset Simulation)
**Purpose**: Apply real attacker psychology, economics, and decision-making to validate and prioritize attack chains
**Type**: Analysis plugin (simulates attacker reasoning, scores by exploitability)
**Version**: 2.1.0 (UPDATED - Phase 3 Assignment)

---

## Overview

This plugin transforms technically valid attack chains into **realistically exploitable scenarios** by simulating how actual attackers make decisions. A vulnerability may be technically present, but real attackers ask:

1. **"Is it worth my time?"** — Profit vs. effort calculation
2. **"Can I actually execute this?"** — Capital, skill, tooling requirements
3. **"Will I get caught?"** — Traceability, attribution risk
4. **"Is there something easier?"** — Opportunity cost vs. alternative targets
5. **"What am I missing?"** — Blind spots in our own analysis

This plugin:
- **Scores chains** by real-world exploitability (not just technical feasibility)
- **Applies attacker profiles** (different attackers have different motivations)
- **Identifies missed attacks** that pure pattern matching wouldn't find
- **Prioritizes findings** by which ones real attackers would actually exploit
- **Enforces Reality Check Gate** before any finding becomes CONFIRMED

---

## Core Philosophy: "Think Like the Enemy"

> *"The best defense thinks like the offense. Not legally — tactically."*

### The Attacker's Decision Framework

Real attackers DON'T maximize bug count. They maximize **risk-adjusted expected value**:

```
Attacker EV = (Profit × Success Probability) - (Cost + Risk Penalty)

Where:
- Profit          = Extractable value (from Phase 2)
- Success Probability = Technical feasibility × Execution confidence  
- Cost            = Capital + Gas + Time + Tooling development
- Risk Penalty    = (Detection probability × Seizure probability × Loss if caught) + Reputation cost
```

If Attacker EV < Threshold → **Real attacker won't exploit** → Finding is lower priority

---

## The Reality Check Gate (MANDATORY)

Before ANY attack chain can achieve **CONFIRMED** status, it MUST pass all 5 reality checks:

```javascript
function canConfirmFinding(attackChain, attackerContext) {
    const realityChecks = [
        {
            name: 'Economic Viability',
            check: () => {
                const ev = calculateAttackerEV(attackChain);
                return ev.profit > ev.totalCost && ev.riskAdjustedEV > attackerContext.minEVThreshold;
            },
            failureMessage: 'Attack is not economically viable for rational attacker'
        },
        {
            name: 'Resource Feasibility',
            check: () => {
                const resources = assessRequiredResources(attackChain);
                return resources.requiredCapital <= attackerContext.maxCapital &&
                       resources.technicalDifficulty <= attackerContext.maxSkillLevel;
            },
            failureMessage: 'Required resources exceed typical attacker capabilities'
        },
        {
            name: 'Execution Window',
            check: () => {
                const window = analyzeExecutionWindow(attackChain);
                return window.exists === true && 
                       window.durationMs >= attackChain.minimumExecutionTime &&
                       !window.expired;
            },
            failureMessage: 'Execution window does not exist or has closed'
        },
        {
            name: 'Competitive Landscape',
            check: () => {
                const competition = assessCompetition(attackChain);
                // Attack is still viable even with competition, but score reflects it
                return competition.blockable === false || competition.firstMoverAdvantage > 0.3;
            },
            failureMessage: 'Attack is blockable by others with no first-mover advantage'
        },
        {
            name: 'Defender Response',
            check: () => {
                const response = simulateDefenderResponse(attackChain);
                // Even if defenders CAN respond, attack may still be viable before response
                return response.timeToPatchMs > attackChain.estimatedExecutionTimeMs ||
                       response.detectionProbability < 0.9;
            },
            failureMessage: 'Defenders can detect/block faster than attack executes'
        }
    ];
    
    const results = realityChecks.map(check => ({
        name: check.name,
        passed: check.check(),
        ...(check.check() ? {} : { reason: check.failureMessage })
    }));
    
    const allPassed = results.every(r => r.passed);
    
    return {
        canConfirm: allPassed,
        maxAllowedStatus: allPassed ? 'CONFIRMED' : 'PROBABLE',
        realityCheckResults: results,
        blockedBy: results.filter(r => !r.passed).map(r => r.name),
        recommendation: generateAttackerRecommendation(attackChain, results)
    };
}
```

---

## Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Gated attack chains | Attack Chain Composer output | Chains that passed Phase 2 gate |
| Protocol context | Phase 0 output | TVL, tokenomics, deployment status |
| Attacker profiles | `attacker-profiles.json` | Known attacker archetypes |
| Historical data | `attack-chain-templates.json` | Incident outcomes, profits, timelines |
| On-chain data | External (optional) | Current pool depths, gas prices, activity |
| **MEV/Flash loan data** | **External** | Current flash loan pools, MEV opportunities |

---

## Attacker Profile System

### Known Attacker Archetypes

Based on analysis of 904+ DeFi incidents, we identify distinct attacker profiles:

#### Profile 1: The Economic Opportunist (70% of attacks)

```
┌─────────────────────────────────────────────────────────────────────┐
│ ECONOMIC OPPORTUNIST                                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Motivation: Pure profit maximization                               │
│ Capital: $10K - $5M (often borrowed via flash loan)                │
│ Skill Level: Medium-High (can deploy contracts, understand DeFi)   │
│ Time Horizon: Hours to days (opportunistic)                        │
│ Risk Tolerance: High (uses mixers, fresh wallets)                  │
│ Targets: High TVL, known patterns, easy extraction                 │
│                                                                     │
│ Decision Process:                                                   │
│   1. Scan for known vulnerable patterns (oracle manipulation, etc.) │
│   2. Calculate profit/cost ratio                                   │
│   3. If > 10x return, prepare exploit                              │
│   4. Execute when conditions optimal (gas, liquidity)              │
│                                                                     │
│ Historical Examples:                                               │
│   - Mango Markets attacker ($114M)                                 │
│   - Platypus Finance ($2M)                                         │
│   - LAVA ($578K)                                                   │
│                                                                     │
│ Detection Signatures:                                               │
│   - Fresh wallet (≤ 7 days old)                                    │
│   - Single large transaction                                       │
│   - Funds routed through Tornado Cash or bridge                    │
│   - Exploits known pattern exactly                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Economic Model:**
```javascript
const economicOpportunist = {
    profileId: 'economic_opportunist',
    weight: 0.70, // 70% of attacks fit this profile
    minEVThreshold: 50000, // Won't attack for less than $50K expected value
    maxCapital: 5000000, // Can access up to $5M (flash loans)
    skillLevel: 0.7, // 0-1 scale
    riskTolerance: 0.8, // Willing to take risks
    timeHorizonHours: 48, // Wants quick profit
    preferredAttackTypes: [
        'flash_loan_price_manipulation',
        'oracle_manipulation',
        'accounting_error'
    ],
    costStructure: {
        fixedCost: 500, // Basic tooling (~$500)
        variableCostPercent: 0.001, // 0.1% of capital used
        timeCostPerHour: 200, // Opportunity cost
        riskPenaltyMultiplier: 0.1 // 10% of profit if detected
    }
};
```

#### Profile 2: The Strategic Insider (15% of attacks)

```
┌─────────────────────────────────────────────────────────────────────┐
│ STRATEGIC INSIDER                                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Motivation: High-value targeted exploitation                        │
│ Capital: $100K - $50M (significant reserves)                       │
│ Skill Level: Very High (deep protocol knowledge, possibly insider)  │
│ Time Horizon: Weeks to months (patient preparation)                 │
│ Risk Tolerance: Medium (careful operational security)               │
│ Targets: Specific protocols, governance systems, bridges           │
│                                                                     │
│ Decision Process:                                                   │
│   1. Identify target with deep research                            │
│   2. Find novel or complex attack vector                           │
│   3. Prepare infrastructure over weeks                             │
│   4. Execute at optimal moment (governance, upgrade, etc.)         │
│                                                                     │
│ Historical Examples:                                               │
│   - BAYC hacker ($144M) - social engineering + technical           │
│   - Wormhole hacker ($133M) - sophisticated bridge exploit          │
│   - Poly Network attacker ($611M) - novel cross-chain              │
│                                                                     │
│ Detection Signatures:                                               │
│   - Carefully prepared wallet (funded weeks prior)                 │
│   - Multiple test transactions before attack                       │
│   - May pose as white hat initially                                │
│   - Complex multi-step exploit                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Economic Model:**
```javascript
const strategicInsider = {
    profileId: 'strategic_insider',
    weight: 0.15,
    minEVThreshold: 1000000, // Only interested in $1M+
    maxCapital: 50000000,
    skillLevel: 0.95,
    riskTolerance: 0.4, // More careful
    timeHorizonHours: 720, // ~30 days
    preferredAttackTypes: [
        'access_control_takeover',
        'governance_manipulation',
        'bridge_exploit',
        'novel_combination'
    ],
    costStructure: {
        fixedCost: 50000, // Significant R&D investment
        variableCostPercent: 0.01,
        timeCostPerHour: 500,
        riskPenaltyMultiplier: 0.3 // Higher penalty (more to lose)
    }
};
```

#### Profile 3: The Script Kiddie / Copycat (10% of attacks)

```
┌─────────────────────────────────────────────────────────────────────┐
│ SCRIPT KIDDIE / COPYCAT                                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Motivation: Replicate public exploits for easy profit              │
│ Capital: $100 - $10K (limited resources)                           │
│ Skill Level: Low-Medium (follows tutorials, uses public tools)     │
│ Time Horizon: Hours (wants immediate results)                      │
│ Risk Tolerance: Very High (doesn't understand risks well)           │
│ Targets: Recently exploited patterns, unprotected forks             │
│                                                                     │
│ Decision Process:                                                   │
│   1. Monitor Twitter/Discord for new exploits                      │
│   2. Find forks of exploited protocol                              │
│   3. Copy-paste or slightly modify public PoC                     │
│   4. Execute quickly before others or before patch                 │
│                                                                     │
│ Historical Examples:                                               │
│   - Fork exploiters (multiple small DeFi projects)                 │
│   - Same-day copycats after major exploit announcements            │
│                                                                     │
│ Detection Signatures:                                               │
│   - Uses similar contract addresses to public PoC                  │
│   - Executes within 24h of original exploit publication            │
│   - Small extraction amounts (misses optimization)                 │
│   - May leave funds in traceable addresses                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Economic Model:**
```javascript
const scriptKiddie = {
    profileId: 'script_kiddie',
    weight: 0.10,
    minEVThreshold: 1000, // Even small profits attract them
    maxCapital: 10000,
    skillLevel: 0.3,
    riskTolerance: 0.95, // Doesn't fully understand risk
    timeHorizonHours: 6, // Wants instant gratification
    preferredAttackTypes: [
        'known_public_exploit',
        'fork_exploit',
        'simple_reentrancy',
        'basic_access_control'
    ],
    costStructure: {
        fixedCost: 0, // Uses free tools
        variableCostPercent: 0.05, // Higher gas inefficiency
        timeCostPerHour: 10, // Low opportunity cost
        riskPenaltyMultiplier: 0.01 // Underestimates risk
    }
};
```

#### Profile 4: The White Hat Turned Rogue (5% of attacks)

```
┌─────────────────────────────────────────────────────────────────────┐
│ WHITE HAT TURNED ROGUE                                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│ Motivation: Found bug during audit, decides to exploit              │
│ Capital: Variable (may have white-hat funding sources)             │
│ Skill Level: Expert (professional auditor level)                   │
│ Time Horizon: Triggered by specific events                          │
│ Risk Tolerance: Low-Medium (knows consequences)                    │
│ Targets: Protocols they audited or researched deeply               │
│                                                                     │
│ Decision Process:                                                   │
│   1. Discover vulnerability during legitimate research             │
│   2. Assess bounty vs exploitation value                           │
│   3. If exploitation >> bounty, may rationalize attack             │
│   4. Execute with knowledge of monitoring systems                  │
│                                                                     │
│ Detection Signatures:                                               │
│   - Wallet previously involved in white-hat activities             │
│   - Exploit shows deep protocol understanding                      │
│   - May attempt negotiation before/during exploitation             │
│   - Often targets specific high-value extraction                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Economic Model:**
```javascript
const whiteHatRogue = {
    profileId: 'white_hat_rogue',
    weight: 0.05,
    minEVThreshold: 500000, // Bounty must be much lower than exploit value
    maxCapital: 1000000,
    skillLevel: 0.99,
    riskTolerance: 0.2, // Knows risks well
    timeHorizonHours: 168, // ~1 week
    preferredAttackTypes: [
        'complex_novel_exploit',
        'logic_flaw',
        'business_logic_exploit'
    ],
    costStructure: {
        fixedCost: 10000, // Has existing tooling
        variableCostPercent: 0.002,
        timeCostPerHour: 1000, // High opportunity cost (reputation)
        riskPenaltyMultiplier: 0.5 // Career-ending if caught
    }
};
```

---

## Core Algorithms

### Algorithm 1: Calculate Attacker Expected Value

```javascript
function calculateAttackerEV(attackChain, attackerProfile = null) {
    const profile = attackerProfile || selectMostLikelyProfile(attackChain);
    
    // Base profit estimate from Phase 2
    const baseProfit = attackChain.extractedValueEstimate.likely || 0;
    
    // Adjust for execution success probability
    const successProbability = calculateSuccessProbability(attackChain, profile);
    
    // Calculate costs
    const capitalCost = estimateCapitalRequirement(attackChain);
    const gasCost = estimateGasCost(attackChain);
    const toolingCost = profile.costStructure.fixedCost;
    const timeCost = estimateTimeRequirement(attackChain, profile) * profile.costStructure.timeCostPerHour;
    
    // Total direct cost
    const totalDirectCost = capitalCost + gasCost + toolingCost + timeCost;
    
    // Risk penalty (probability of detection × consequences)
    const detectionProbability = estimateDetectionProbability(attackChain);
    const seizureProbability = detectionProbability > 0 ? 0.3 : 0; // 30% seized if detected
    const lossIfSeized = baseProfit * 0.8; // Lose 80% of profit if seized
    const reputationCost = profile.skillLevel > 0.8 ? 500000 : 0; // High-skill attackers lose reputation income
    
    const riskPenalty = (detectionProbability * seizureProbability * lossIfSeized) + 
                        (detectionProbability * reputationCost);
    
    // Expected Value calculation
    const grossEV = baseProfit * successProbability;
    const netEV = grossEV - totalDirectCost - riskPenalty;
    
    // Risk-adjusted EV (attacker's risk tolerance affects valuation)
    const riskAdjustedEV = applyRiskTolerance(netEV, profile.riskTolerance, detectionProbability);
    
    return {
        baseProfit,
        successProbability: Math.round(successProbability * 100) + '%',
        costs: {
            capital: capitalCost,
            gas: gasCost,
            tooling: toolingCost,
            time: timeCost,
            totalDirect: totalDirectCost
        },
        riskAnalysis: {
            detectionProbability: Math.round(detectionProbability * 100) + '%',
            seizureProbability: Math.round(seizureProbability * 100) + '%',
            riskPenalty
        },
        grossEV: Math.round(grossEV),
        netEV: Math.round(netEV),
        riskAdjustedEV: Math.round(riskAdjustedEV),
        profitToCostRatio: totalDirectCost > 0 ? Math.round(netEV / totalDirectCost * 100) / 100 : Infinity,
        verdict: netEV > profile.minEVThreshold ? 'VIABLE' : 'NOT_VIABLE',
        profileUsed: profile.profileId
    };
}

function calculateSuccessProbability(attackChain, profile) {
    let probability = 0.85; // Base probability for gated chain
    
    // Adjust for technical complexity
    if (attackChain.feasibility.complexity === 'expert') {
        probability -= (1 - profile.skillLevel) * 0.3;
    } else if (attackChain.feasibility.complexity === 'hard') {
        probability -= (1 - profile.skillLevel) * 0.15;
    }
    
    // Adjust for capital requirements
    const requiredCapital = parseCapitalString(attackChain.feasibility.requiredCapital);
    if (requiredCapital > profile.maxCapital * 0.8) {
        probability -= 0.1; // Capital constraints reduce success
    }
    
    // Adjust for timing sensitivity
    if (attackChain.executionPath.requiresSingleTx) {
        probability += 0.05; // Atomic = more predictable
    } else {
        probability -= 0.05; // Multi-TX = more failure points
    }
    
    // Adjust for historical precedent
    if (attackChain.historicalMatches?.length > 0) {
        const avgSimilarity = attackChain.historicalMatches.reduce((sum, m) => sum + parseFloat(m.similarity), 0) / attackChain.historicalMatches.length;
        probability += (avgSimilarity / 100 - 0.5) * 0.1; // Higher similarity = higher confidence
    }
    
    return Math.max(0.1, Math.min(0.99, probability)); // Clamp between 10%-99%
}
```

### Algorithm 2: Assess Required Resources

```javascript
function assessRequiredResources(attackChain) {
    // Capital requirements
    const capitalMatch = attackChain.feasibility.requiredCapital?.match(/\$?([\d.]+)([KM]?)/i);
    const requiredCapital = capitalMatch ? parseFloat(capitalMatch[1]) * (capitalMatch[2] === 'K' ? 1000 : capitalMatch[2] === 'M' ? 1000000 : 1) : 0;
    
    // Technical difficulty mapping
    const difficultyMap = {
        'easy': 0.2,
        'medium': 0.5,
        'hard': 0.75,
        'expert': 0.95
    };
    
    const technicalDifficulty = difficultyMap[attackChain.feasibility.complexity] || 0.5;
    
    // Time requirement estimation
    const timeEstimates = {
        'flash_loan_price_manipulation': { prep: 24, exec: 1 }, // hours
        'reentrancy_drain': { prep: 48, exec: 2 },
        'access_control_takeover': { prep: 72, exec: 4 },
        'oracle_governance_manipulation': { prep: 168, exec: 48 },
        'cross_contract_coupling': { prep: 96, exec: 8 }
    };
    
    const timeEstimate = timeEstimates[attackChain.type] || { prep: 48, exec: 8 };
    
    // Tooling requirements
    const toolingRequirements = [];
    if (attackChain.executionPath.requiresSingleTx) {
        toolingRequirements.push('Flash loan contract deployment');
    }
    if (attackChain.steps.some(s => s.patternSlug.includes('reentrancy'))) {
        toolingRequirements.push('Malicious callback contract');
    }
    if (attackChain.steps.some(s => s.patternSlug.includes('signature'))) {
        toolingRequirements.push('Signature forgery/oracle');
    }
    if (toolingRequirements.length === 0) {
        toolingRequirements.push('Basic EOA transaction construction');
    }
    
    return {
        requiredCapital,
        technicalDifficulty,
        estimatedPrepTimeHours: timeEstimate.prep,
        estimatedExecTimeHours: timeEstimate.exec,
        totalTimeHours: timeEstimate.prep + timeEstimate.exec,
        toolingRequirements,
        canAutomate: technicalDifficulty < 0.6, // Can be scripted
        needsManualIntervention: technicalDifficulty >= 0.7 // Human judgment needed
    };
}
```

### Algorithm 3: Analyze Execution Window

```javascript
function analyzeExecutionWindow(attackChain, currentOnChainState = null) {
    const window = {
        exists: true,
        type: null,
        opensAt: null,
        closesAt: null,
        durationMs: null,
        expired: false,
        optimalTiming: null,
        triggers: [],
        blockers: []
    };
    
    // Determine window type based on chain type
    switch (attackChain.type) {
        case 'flash_loan_price_manipulation':
            window.type = 'continuous_with_optimal';
            window.durationMs = Infinity; // Always possible
            window.optimalTiming = {
                condition: 'Low gas + High pool liquidity + No active watchers',
                checkFrequency: 'monitor_continuously',
                idealDayOfWeek: 'weekend', // Less monitoring
                idealHourUTC: 2-6 // Low activity hours
            };
            window.triggers = [
                'Large pool imbalance detected',
                'Oracle price deviation from TWAP',
                'Low gas prices (< 20 gwei)'
            ];
            break;
            
        case 'reentrancy_drain':
            window.type = 'continuous_until_patched';
            window.durationMs = Infinity; // Available until fix deployed
            window.optimalTiming = {
                condition: 'High contract balance + Low monitoring',
                checkFrequency: 'monitor_balance'
            };
            window.triggers = [
                'Contract balance above threshold',
                'No pending upgrade/proposal'
            ];
            window.blockers = [
                'Contract upgraded with nonReentrant guard',
                'Balance drained below threshold'
            ];
            break;
            
        case 'access_control_takeover':
            window.type = 'event_triggered';
            // Check for timelock, governance delay, etc.
            const governanceDelay = extractGovernanceDelay(attackChain);
            window.durationMs = governanceDelay ? governanceDelay * 3600 * 1000 : null;
            window.triggers = [
                'Governance proposal submitted',
                'Timelock started',
                'Owner change initiated'
            ];
            window.blockers = [
                'Timelock cancelled',
                'Emergency measures activated',
                'Multi-sig blocks execution'
            ];
            break;
            
        case 'oracle_governance_manipulation':
            window.type = 'extended_preparation';
            window.durationMs = 7 * 24 * 3600 * 1000; // Days to weeks
            window.optimalTiming = {
                condition: 'Governance apathy + Upcoming vote deadline',
                checkFrequency: 'daily'
            };
            window.triggers = [
                'Governance participation low (< 30%)',
                'Proposal submission window open',
                'Price volatility period approaching'
            ];
            break;
            
        case 'cross_contract_coupling':
            window.type = 'race_condition';
            window.durationMs = 15000; // 15 second race window typically
            window.optimalTiming = {
                condition: 'High mempool activity + Block propagation delay',
                checkFrequency: 'per_block'
            };
            window.triggers = [
                'Function A called (sets favorable state)',
                'Block nearly full (delay Function B processing)'
            ];
            window.blockers = [
                'Mutex/lock implemented',
                'Atomic execution enforced',
                'Front-run by searcher'
            ];
            break;
    }
    
    // Check if window has expired (for event-triggered windows)
    if (currentOnChainState && window.type === 'event_triggered') {
        const eventAge = calculateEventAge(currentOnChainState.triggerEvent);
        if (eventAge > window.durationMs) {
            window.expired = true;
            window.exists = false;
        }
    }
    
    return window;
}
```

### Algorithm 4: Assess Competition & MEV

```javascript
function assessCompetition(attackChain) {
    const competition = {
        competitive: false,
        competitorCount: 0,
        blockable: false,
        firstMoverAdvantage: 1.0, // 0-1 scale
        mevExposure: 'none', // none | low | medium | high
        recommendations: []
    };
    
    // Analyze attack type for competitiveness
    const competitivePatterns = [
        'flash_loan_price_manipulation',
        'arbitrage',
        'liquidation_incentive_miscalculation'
    ];
    
    if (competitivePatterns.includes(attackChain.type)) {
        competition.competitive = true;
        competition.competitorCount = estimateCompetitorCount(attackChain);
        
        // Flash loan attacks are highly competitive
        if (attackChain.type === 'flash_loan_price_manipulation') {
            competition.blockable = true; // Can be front-run
            competition.firstMoverAdvantage = 0.6; // First mover gets majority
            competition.mevExposure = 'high';
            competition.recommendations.push('Use private mempool or Flashbots RPC');
            competition.recommendations.push('Consider atomic bundle execution');
        }
        
        // Arbitrage is extremely competitive
        if (attackChain.linkage?.type === 'capital_provision' || 
            attackChain.steps.some(s => s.bugClass === 'arbitrage')) {
            competition.competitorCount += 5; // Many arbitrage bots
            competition.firstMoverAdvantage = 0.3; // Very competitive
            competition.mevExposure = 'high';
            competition.recommendations.push('Must be faster than specialized searchers');
        }
    }
    
    // Reentrancy is less competitive (requires specific setup)
    if (attackChain.type === 'reentrancy_drain') {
        competition.competitive = false;
        competition.firstMoverAdvantage = 0.9; // Likely exclusive if prepared
        competition.mevExposure = 'low';
    }
    
    // Access control often exclusive
    if (attackChain.type === 'access_control_takeover') {
        competition.competitive = false;
        competition.firstMoverAdvantage = 1.0;
        competition.mevExposure = 'none';
    }
    
    return competition;
}

function estimateCompetitorCount(attackChain) {
    // Base estimates by TVL range
    const tvl = attackChain.protocolTVL || 0;
    
    let baseCompetitors = 0;
    if (tvl > 100_000_000) baseCompetitors = 10; // >$100M TVL = many watchers
    else if (tvl > 10_000_000) baseCompetitors = 5; // >$10M TVL = some watchers
    else if (tvl > 1_000_000) baseCompetitors = 2; // >$1M TVL = few watchers
    else baseCompetitors = 0.5; // Small TVL = limited attention
    
    // Adjust for pattern novelty
    const isNovelPattern = !attackChain.historicalMatches || attackChain.historicalMatches.length === 0;
    if (isNovelPattern) baseCompetitors *= 0.3; // Fewer competitors for novel bugs
    
    // Adjust for protocol age
    const protocolAgeDays = attackChain.protocolAgeDays || 365;
    if (protocolAgeDays < 30) baseCompetitors *= 0.5; // New protocol = fewer watchers
    if (protocolAgeDays > 365) baseCompetitors *= 1.5; // Old protocol = battle-tested but watched
    
    return Math.round(baseCompetitors);
}
```

### Algorithm 5: Simulate Defender Response

```javascript
function simulateDefenderResponse(attackChain) {
    const response = {
        detectable: true,
        detectionMethod: null,
        detectionProbability: 0.5,
        timeToDetectMs: null,
        timeToRespondMs: null,
        timeToPatchMs: null,
        responseCapability: 'manual', // manual | automated | none
        activeMonitoring: false,
        canFreeze: false,
        canPause: false,
        severity: 'medium' // low | medium | high | critical
    };
    
    // Determine detection method based on attack type
    switch (attackChain.type) {
        case 'flash_loan_price_manipulation':
            response.detectionMethod = 'price_oracle_monitoring';
            response.detectionProbability = 0.7; // Good monitoring tools exist
            response.timeToDetectMs = 30000; // 30 seconds to notice price deviation
            response.timeToRespondMs = 300000; // 5 minutes to respond
            response.timeToPatchMs = Infinity; // Can't patch mid-attack
            response.activeMonitoring = true; // Most protocols monitor oracles
            response.severity = 'critical'; // Large losses possible
            break;
            
        case 'reentrancy_drain':
            response.detectionMethod = 'balance_monitoring';
            response.detectionProbability = 0.4; // Harder to detect mid-execution
            response.timeToDetectMs = 60000; // 1 minute (after tx completes)
            response.timeToRespondMs = 1800000; // 30 minutes
            response.timeToPatchMs = 3600000 * 24; // 1 day to deploy patch
            response.canPause = true; // Most protocols have pause functionality
            response.severity = 'critical';
            break;
            
        case 'access_control_takeover':
            response.detectionMethod = 'governance_monitoring';
            response.detectionProbability = 0.3; // May look legitimate initially
            response.timeToDetectMs = 3600000; // 1 hour
            response.timeToRespondMs = 7200000; // 2 hours
            response.timeToPatchMs = 3600000 * 48; // 2 days
            response.activeMonitoring = false; // Governance moves slower
            response.severity = 'critical';
            break;
            
        default:
            response.detectionProbability = 0.5;
            response.timeToDetectMs = 3600000;
            response.timeToRespondMs = 7200000;
            response.timeToPatchMs = 86400000 * 7; // 1 week
    }
    
    // Check for protocol-specific defenses
    if (attackChain.protocolFeatures?.includes('circuit_breaker')) {
        response.canPause = true;
        response.timeToRespondMs = Math.min(response.timeToRespondMs, 60000); // 1 minute with circuit breaker
    }
    
    if (attackChain.protocolFeatures?.includes('real_time_monitoring')) {
        response.activeMonitoring = true;
        response.detectionProbability += 0.2;
    }
    
    if (attackChain.protocolFeatures?.includes('timelock')) {
        response.timeToPatchMs = Math.max(response.timeToPatchMs, 86400000 * 2); // Timelock delays patches
    }
    
    return response;
}
```

### Algorithm 6: Identify Missed Attacks (Creative Discovery)

```javascript
function identifyMissedAttacks(gatedChains, context, attackerProfiles) {
    const missedAttacks = [];
    
    // Strategy 1: Think about what attackers see that we don't
    const blindSpots = analyzeBlindSpots(gatedChains, context);
    
    // Strategy 2: Consider combination attacks not in templates
    const novelCombinations = findNovelCombinations(gatedChains, context);
    
    // Strategy 3: Look for protocol-specific unique features
    const protocolSpecific = findProtocolSpecificAttacks(context);
    
    // Strategy 4: Consider temporal/governance attacks
    const temporalAttacks = findTemporalAttacks(context);
    
    // Strategy 5: Check for human/social engineering vectors
    const socialVectors = findSocialEngineeringVectors(context);
    
    missedAttacks.push(
        ...blindSpots,
        ...novelCombinations,
        ...protocolSpecific,
        ...temporalAttacks,
        ...socialVectors
    );
    
    // Score and rank missed attacks by attacker appeal
    return rankMissedAttacks(missedAttacks, attackerProfiles);
}

function analyzeBlindSpots(gatedChains, context) {
    const blindSpots = [];
    
    // Blind Spot 1: We focus on code bugs, attackers focus on value
    const valueCentricAttacks = [];
    if (context.protocolTVL > 10_000_000 && gatedChains.length < 3) {
        // High TVL but few chains found - might be missing something
        valueCentricAttacks.push({
            hypothesisType: 'value_centric_blind_spot',
            description: 'High TVL protocol with few identified attack chains - consider economic attacks that don\'t require code bugs',
            suggestedInvestigation: [
                'Analyze tokenomics for design flaws (inflation attacks, peg breaks)',
                'Check for LP incentive gaming possibilities',
                'Look for oracle design weaknesses not yet triggered',
                'Consider governance centralization risks'
            ],
            attackerAppeal: 'high',
            evidence: `TVL: $${context.protocolTVL}, Chains found: ${gatedChains.length}`
        });
    }
    
    // Blind Spot 2: We assume normal operation, attackers create abnormal conditions
    const abnormalConditionAttacks = [];
    const stressConditions = ['extreme_gas_prices', 'block_congestion', 'oracle_failure', 'anchor_price_deviation'];
    for (const condition of stressConditions) {
        const resilience = checkProtocolResilience(context, condition);
        if (resilience.score < 0.5) {
            abnormalConditionAttacks.push({
                hypothesisType: 'stress_condition_exploitation',
                description: `Protocol may behave unexpectedly under ${condition.replace(/_/g, ' ')}`,
                suggestedInvestigation: [`Test protocol behavior when ${condition.replace(/_/g, ' ')}`],
                attackerAppeal: resilience.exploitability,
                evidence: `Resilience score: ${resilience.score}`
            });
        }
    }
    
    return [...valueCentricAttacks, ...abnormalConditionAttacks];
}

function findNovelCombinations(gatedChains, context) {
    const novelCombinations = [];
    
    // Get all patterns currently used in chains
    const usedPatterns = new Set(gatedChains.flatMap(c => c.steps.map(s => s.patternSlug)));
    
    // Find unused patterns that could combine
    const availablePatterns = getAvailablePatterns(context); // From pattern matcher
    const unusedPatterns = availablePatterns.filter(p => !usedPatterns.has(p.slug));
    
    // Try combining unused patterns with each other
    for (let i = 0; i < unusedPatterns.length; i++) {
        for (let j = 0; j < unusedPatterns.length; j++) {
            if (i === j) continue;
            
            const linkage = analyzePotentialLinkage(unusedPatterns[i], unusedPatterns[j], context);
            
            if (linkage.strength >= 0.4 && linkage.strength < 0.5) { // Below threshold but interesting
                novelCombinations.push({
                    hypothesisType: 'novel_pattern_combination',
                    description: `Potential novel chain: ${unusedPatterns[i].slug} → ${unusedPatterns[j].slug}`,
                    linkageType: linkage.type,
                    linkageStrength: linkage.strength,
                    whyMissed: 'Linkage strength below standard threshold but may be viable',
                    suggestedInvestigation: [
                        'Manually verify if preconditions can be satisfied',
                        'Check if historical precedent exists for similar combinations',
                        'Assess whether this represents a truly novel attack class'
                    ],
                    attackerAppeal: linkage.strength > 0.45 ? 'medium' : 'low',
                    patterns: [unusedPatterns[i].slug, unusedPatterns[j].slug]
                });
            }
        }
    }
    
    return novelCombinations;
}

function findProtocolSpecificAttacks(context) {
    const protocolSpecific = [];
    
    // Check for unique protocol features that could be attacked
    if (context.protocolFeatures) {
        const riskyFeatures = {
            'custom_amm': 'Custom AMM implementations often have edge cases in price calculation',
            'rebasing_token': 'Rebasing mechanics can desync with internal accounting',
            'wrapped_variant': 'Wrap/unwrap operations may have precision issues',
            'governance_token': 'Governance tokens enable voting attacks',
            'cross_chain_bridge': 'Bridges are high-value targets with complex verification',
            'liquidation_engine': 'Custom liquidation logic frequently has edge cases',
            'interest_rate_model': 'Interest rate models may have pathological behaviors',
            'fee_switch': 'Fee mechanisms can be gamed for profit extraction'
        };
        
        for (const [feature, riskDescription] of Object.entries(riskyFeatures)) {
            if (context.protocolFeatures.includes(feature)) {
                // Check if we already have chains targeting this feature
                const hasExistingChain = false; // Would need to check actual chains
                
                if (!hasExistingChain) {
                    protocolSpecific.push({
                        hypothesisType: 'protocol_feature_attack',
                        description: `${feature}: ${riskDescription}`,
                        feature,
                        suggestedInvestigation: [
                            `Deep-dive into ${feature} implementation`,
                            'Compare with known vulnerabilities in similar implementations',
                            'Model edge cases with extreme inputs'
                        ],
                        attackerAppeal: ['cross_chain_bridge', 'governance_token'].includes(feature) ? 'high' : 'medium'
                    });
                }
            }
        }
    }
    
    return protocolSpecific;
}

function findTemporalAttacks(context) {
    const temporalAttacks = [];
    
    // Check for time-based vulnerabilities
    if (context.governanceConfig) {
        const { timelockDelay, votingPeriod, executionDelay, quorum } = context.governanceConfig;
        
        // Long timelocks with low participation = governance attack surface
        if (timelockDelay > 86400 * 2 && quorum < 0.3) { // >2 day timelock, <30% quorum
            temporalAttacks.push({
                hypothesisType: 'governance_temporal_attack',
                description: 'Long timelock with low quorum creates extended vulnerability window',
                windowDetails: {
                    timelockDelayHours: timelockDelay / 3600,
                    votingPeriodHours: votingPeriod / 3600,
                    attackWindow: 'From proposal passage through timelock expiry'
                },
                suggestedInvestigation: [
                    'Calculate minimum capital needed for governance takeover',
                    'Identify delegates who could be swayed',
                    'Check for proposal approval racing conditions'
                ],
                attackerAppeal: 'medium-high'
            });
        }
    }
    
    // Check for scheduled events that create windows
    if (context.upcomingEvents) {
        for (const event of context.upcomingEvents) {
            if (event.type === 'upgrade' || event.type === 'parameter_change') {
                temporalAttacks.push({
                    hypothesisType: 'scheduled_event_exploitation',
                    description: `Upcoming ${event.type} at ${event.scheduledTime} may create attack window`,
                    event,
                    suggestedInvestigation: [
                        'Analyze proposed changes for new attack surfaces',
                        'Check if old version has known vulnerabilities expiring soon',
                        'Monitor for last-minute proposal modifications'
                    ],
                    attackerAppeal: 'medium'
                });
            }
        }
    }
    
    return temporalAttacks;
}

function findSocialEngineeringVectors(context) {
    const socialVectors = [];
    
    // Check for social attack surfaces
    const socialIndicators = [
        { indicator: 'admin_multisig', vector: 'Multisig member compromise or social engineering', appeal: 'high' },
        { indicator: 'team_controls_governance', vector: 'Team-dominated governance enables insider threats', appeal: 'medium' },
        { indicator: 'public_communication_channels', vector: 'Impersonation in Discord/Twitter for phishing', appeal: 'medium' },
        { indicator: 'bug_bounty_program', vector: 'White hat turned rogue (knows vulnerabilities)', appeal: 'low-medium' },
        { indicator: 'external_auditor', vector: 'Auditor credential impersonation', appeal: 'low' }
    ];
    
    for (const { indicator, vector, appeal } of socialIndicators) {
        if (context.socialSurface?.includes(indicator)) {
            socialVectors.push({
                hypothesisType: 'social_engineering_vector',
                description: vector,
                indicator,
                suggestedInvestigation: [
                    'Verify team/multisig member identity practices',
                    'Check communication channel security',
                    'Review bug bounty terms for potential abuse'
                ],
                attackerAppeal: appeal,
                requiresOffChainAction: true
            });
        }
    }
    
    return socialVectors;
}
```

### Algorithm 7: Generate Attacker Recommendation

```javascript
function generateAttackerRecommendation(attackChain, realityCheckResults) {
    const failedChecks = realityCheckResults.filter(r => !r.passed);
    const passedChecks = realityCheckResults.filter(r => r.passed);
    
    if (failedChecks.length === 0) {
        return {
            action: 'ESCALATE_TO_CONFIRMED',
            rationale: 'All reality checks passed. Attack is economically viable, feasible, and timely.',
            priority: calculatePriority(attackChain),
            recommendedNextStep: 'Send to Verifier agent for final validation'
        };
    }
    
    // Analyze which checks failed and provide guidance
    const blockingIssues = failedChecks.map(f => ({
        check: f.name,
        issue: f.reason,
        severity: getBlockingSeverity(f.name),
        possibleMitigation: getPossibleMitigation(f.name, attackChain)
    }));
    
    // Determine overall recommendation
    const criticalFailures = blockingIssues.filter(b => b.severity === 'critical');
    
    if (criticalFailures.length > 0) {
        return {
            action: 'DOWNGRADE_TO_LEAD',
            rationale: `Critical failures: ${criticalFailures.map(b => b.check).join(', ')}. Attack is theoretically possible but practically unlikely.`,
            blockingIssues,
            saveForFutureAnalysis: true,
            reason: 'May become viable if protocol changes or market conditions shift'
        };
    }
    
    return {
        action: 'KEEP_AS_PROBABLE',
        rationale: `Some concerns (${failedChecks.map(f => f.name).join(', ')}) but attack remains plausible.`,
        blockingIssues,
        additionalResearchNeeded: blockingIssues.filter(b => b.severity !== 'low').map(b => b.possibleMitigation),
        monitorForChanges: true
    };
}

function getBlockingSeverity(checkName) {
    const severityMap = {
        'Economic Viability': 'critical', // Must be profitable
        'Resource Feasibility': 'high', // Must be executable
        'Execution Window': 'critical', // Must be timely
        'Competitive Landscape': 'low', // Competition doesn't block, just reduces profit
        'Defender Response': 'medium' // Affects success probability
    };
    return severityMap[checkName] || 'medium';
}

function getPossibleMitigation(checkName, attackChain) {
    const mitigations = {
        'Economic Viability': 'Wait for TVL growth or find higher-value extraction path',
        'Resource Feasibility': 'Consider if lower-capital variant exists or if capital could be pooled',
        'Execution Window': 'Monitor for window opening; document trigger conditions',
        'Competitive Landscape': 'Use private mempool/Flashbots; accept reduced profit share',
        'Defender Response': 'Account for response time in execution plan; target faster extraction'
    };
    return mitigations[checkName] || 'Further investigation needed';
}

function calculatePriority(attackChain) {
    // Priority based on multiple factors
    const factors = {
        extractedValue: Math.log10(attackChain.extractedValueEstimate.likely || 1000) / 7, // 0-1 normalized
        feasibility: attackChain.feasibility.technicalFeasibility === 'high' ? 1 :
                      attackChain.feasibility.technicalFeasibility === 'medium' ? 0.7 : 0.4,
        urgency: attackChain.executionWindow?.expired ? 0 : 
                 attackChain.executionWindow?.type === 'race_condition' ? 0.9 : 0.5,
        novelty: attackChain.historicalMatches?.length === 0 ? 0.8 : 0.5 // Novel = higher priority
    };
    
    const weightedScore = (
        factors.extractedValue * 0.3 +
        factors.feasibility * 0.25 +
        factors.urgency * 0.25 +
        factors.novelty * 0.2
    );
    
    if (weightedScore > 0.8) return 'P0 - Critical';
    if (weightedScore > 0.6) return 'P1 - High';
    if (weightedScore > 0.4) return 'P2 - Medium';
    return 'P3 - Low';
}
```

---

## Output Format

### Enhanced Attack Chain Object (with mindset analysis)

```javascript
{
    // ... Original chain fields from Phase 2 ...
    
    // NEW: Attacker Mindset Analysis
    attackerMindset: {
        // Per-profile analysis
        profileAnalysis: [
            {
                profile: 'economic_opportunist',
                wouldAttack: true,
                ev: { /* calculateAttackerEV result */ },
                resourceGap: null | { /* What they lack */ },
                timingFit: 'good' | 'acceptable' | 'poor'
            }
            // ... for each profile
        ],
        
        // Most likely attacker type
        mostLikelyAttacker: 'economic_opportunist',
        attackerConfidence: 0.85, // How confident we are in this assessment
        
        // Aggregated viability
        overallViability: 'VIABLE' | 'MARGINAL' | 'NOT_VIABLE',
        profilesWouldAttack: ['economic_opportunist', 'script_kiddie'],
        profilesWouldNotAttack: ['strategic_insider'] // ROI too low for them
    },
    
    // NEW: Reality Check Results
    realityCheck: {
        canConfirm: true | false,
        maxAllowedStatus: 'CONFIRMED' | 'PROBABLE',
        checkedAt: '2026-08-06T...',
        results: [/* 5 reality check results */],
        blockedBy: [],
        recommendation: { /* generateAttackerRecommendation result */ }
    },
    
    // NEW: Competitive Analysis
    competition: {
        isCompetitive: true,
        estimatedCompetitors: 3,
        mevExposure: 'high',
        firstMoverAdvantage: 0.6,
        recommendations: ['Use private mempool']
    },
    
    // NEW: Defender Simulation
    defenderResponse: {
        detectionProbability: '70%',
        timeToRespond: '5 minutes',
        canPause: true,
        severity: 'critical'
    },
    
    // NEW: Missed Attack Hypotheses (if any found)
    missedAttacks: [
        {
            hypothesisType: 'protocol_feature_attack',
            description: '...',
            attackerAppeal: 'medium',
            suggestedInvestigation: [...]
        }
    ]
}
```

---

## Integration with Pipeline

### Where This Plugin Fits

```
PHASE 4 PIPELINE:
                    
    ┌──────────────────┐
    │ Attack Chain     │ ← Phase 2 output (gated chains)
    │ Composer Output  │
    └────────┬─────────┘
             │ attackChains[] (passed Phase 2 gate)
             ▼
    ┌────────────────────────┐
    │ Attacker Mindset       │ ← This plugin (applies attacker psychology)
    │ Simulator              │
    └────────┬───────────────┘
             │ enhancedChains[] (with mindset analysis)
             ▼
    ┌────────────────────────┐
    │ Reality Check Gate     │ ← Built into this plugin (mandatory)
    │ Validation             │
    └────────┬───────────────┘
             │ confirmedChains[] (only passing chains)
             ▼
    ┌────────────────────────┐
    │ Final Prioritization   │ ← Rank by attacker appeal
    │ & Output               │
    └────────┬───────────────┘
             │
             ▼
    OUTPUT: Ranked findings ready for report
```

### Interaction with Verifier Agent

After mindset simulation, enhanced chains are sent to Verifier:

```javascript
const verifierPayload = {
    phase: 4,
    subPhase: "attacker_mindset_simulation",
    input: {
        chainCount: enhancedChains.length,
        confirmedCount: enhancedChains.filter(c => c.realityCheck.canConfirm).length,
        averageEV: calculateAverageEV(enhancedChains)
    },
    output: {
        enhancedChains: enhancedChains.map(c => ({
            id: c.id,
            archetype: c.archetype,
            realityCheck: c.realityCheck,
            mostLikelyAttacker: c.attackerMindset.mostLikelyAttacker,
            overallViability: c.attackerMindset.overallViability,
            priority: c.priority,
            missedAttacksFound: c.missedAttacks?.length || 0
        })),
        missedAttackHypotheses: collectAllMissedAttacks(enhancedChains)
    },
    request: "Validate attacker mindset analysis for realism and completeness"
};
```

---

## Quality Checks (Self-Validation)

```javascript
function runMindsetQualityChecks(enhancedChains) {
    const issues = [];
    
    for (const chain of enhancedChains) {
        // Check 1: Every chain must have mindset analysis
        if (!chain.attackerMindset) {
            issues.push({ severity: 'error', chainId: chain.id, message: 'Missing attacker mindset analysis' });
        }
        
        // Check 2: Reality check must be present
        if (!chain.realityCheck) {
            issues.push({ severity: 'error', chainId: chain.id, message: 'Missing reality check results' });
        }
        
        // Check 3: At least one attacker profile must show positive EV
        const positiveEVProfiles = chain.attackerMindset?.profileAnalysis?.filter(p => p.wouldAttack) || [];
        if (positiveEVProfiles.length === 0 && chain.realityCheck?.canConfirm === true) {
            issues.push({ 
                severity: 'warning', 
                chainId: chain.id, 
                message: 'Chain confirmed but no attacker profile shows positive EV' 
            });
        }
        
        // Check 4: Competition analysis for competitive chain types
        const competitiveTypes = ['flash_loan_price_manipulation', 'arbitrage'];
        if (competitiveTypes.includes(chain.type) && !chain.competition) {
            issues.push({ severity: 'warning', chainId: chain.id, message: 'Competitive chain type missing competition analysis' });
        }
        
        // Check 5: Defender response must be present
        if (!chain.defenderResponse) {
            issues.push({ severity: 'error', chainId: chain.id, message: 'Missing defender response simulation' });
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

## Files This Plugin Consumes

| File | Purpose |
|------|---------|
| `plugins/attack-chain-composer.md` | Input: Gated attack chains |
| `Exploits-class-library/attack-chain-templates.json` | Historical data for baseline comparisons |
| `Exploits-class-library/attacker-profiles.json` | Attacker archetype definitions (NEW) |
| Trackator JSON files (all phases) | Context for resource/defender analysis |

## Files This Plugin Produces

| File | Content |
|------|---------|
| `output/enhanced-attack-chains.json` | Chains with full mindset analysis |
| `output/attacker-mindset-report.md` | Human-readable mindset analysis report |
| `output/missed-attack-hypotheses.json` | Potential attacks pattern matching missed |
| `output/reality-check-results.json` | Gate pass/fail for each chain |

---

## Anti-Patterns (Don't Do These)

❌ **Assume all vulnerabilities will be exploited** — Not every bug is worth attacking  
❌ **Ignore economic realities** — $100 loss isn't worth $10K development effort  
❌ **Treat all attackers the same** — Script kiddies ≠ strategic insiders  
❌ **Overlook competition** — Real attackers consider other searchers  
❌ **Assume perfect execution** — Attacks fail due to gas, timing, errors  
❌ **Ignore defender capabilities** — Protocols can pause, freeze, upgrade  
❌ **Only confirm code bugs** — Economic/design flaws are also exploitable  

✅ **Score by risk-adjusted EV** — This is how real attackers decide  
✅ **Apply appropriate attacker profile** — Match threat model to likely adversary  
✅ **Consider the competitive landscape** — MEV, front-running, other searchers  
✅ **Simulate defender response** — Protocols aren't sitting ducks  
✅ **Generate missed attack hypotheses** — Think beyond pattern matching  
✅ **Keep confirmation bar high** — CONFIRMED means "real attacker would do this"

---

## Return Format

After completing mindset simulation, return:

```
DONE: {N} attack chains analyzed with attacker mindset.
{M} chains PASSED Reality Check (upgraded to CONFIRMED).
{K} chains DOWNGRADED (economically or practically unviable).
{J} missed attack hypotheses generated.
Top target: {CHAIN_ID} ({archetype}), most likely attacker: {PROFILE}, ~${EV} risk-adjusted EV.
Priority ranking: P0={n} P1={n} P2={n} P3={n}.
Quality check: {valid/warnings_count warnings}.
Key insight: {single most important finding from attacker perspective}
```
