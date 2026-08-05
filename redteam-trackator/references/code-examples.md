# Redteam-Trackator Code Examples Reference

> **Source**: `SKILL.md` (original version)
> **Purpose**: Complete, working code blocks extracted from redteam-trackator skill documentation
> **Organization**: By pipeline phase

---

## NOTE: Phase 3 Bug Fix

> **IMPORTANT**: Duplicate gating condition was fixed - see `phase-3-creative-attack.md` for details.
> The original code had a redundant check that could block valid findings. The fix ensures that:
> 1. Only ONE gating check is performed per hypothesis
> 2. The check uses the LATEST evidence calibration data
> 3. Both `traceConclusion.survives` === true AND `evidenceCalibration.finalVerdict` !== 'false-positive' are required (AND logic — both conditions must be satisfied)

---

# Phase 0: INGESTION Functions

## validateTrackatorOutput()

**Location**: Phase 0, Step 0.1  
**Purpose**: Validates required Trackator output files exist and have correct structure

```javascript
/**
 * Phase 0: Validate Trackator Output
 * Source: SKILL.md Phase 0 - Step 0.1
 * 
 * Validates that required Trackator files exist and contain valid data structure.
 * Throws error if any required file is missing or malformed.
 */
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

## buildHypothesisList() + calculatePriorityScore()

**Location**: Phase 0, Step 0.2  
**Purpose**: Extracts alerts from Trackator and ranks them by priority score

```javascript
/**
 * Phase 0: Build Priority-Ranked Hypothesis List
 * Source: SKILL.md Phase 0 - Step 0.2
 * 
 * Extracts all alerts from Trackator enrich data and creates priority-ranked
 * hypothesis objects for downstream analysis.
 */
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

/**
 * Calculates priority score for an alert based on severity, condition type,
 * and source data quality.
 * 
 * Scoring weights:
 * - Severity: critical=30, high=20, medium=10
 * - Condition type: pattern=20, presence/absence=15, threshold=10
 * - Source: runtime=15, tier1=10
 */
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

## extractProtocolContext()

**Location**: Phase 0, Step 0.3  
**Purpose**: Builds context object for downstream phases

```javascript
/**
 * Phase 0: Extract Protocol Context
 * Source: SKILL.md Phase 0 - Step 0.3
 * 
 * Builds comprehensive context object containing protocol metadata,
 * threat model data, and enhanced Trackator v2.0 data.
 */
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

## extractEnhancedContext()

**Location**: Phase 0, Step 0.4 (v2.0 NEW)  
**Purpose**: Loads optional enhanced Trackator analysis data files

```javascript
/**
 * Phase 0: Extract Enhanced Trackator Data (v2.0 NEW)
 * Source: SKILL.md Phase 0 - Step 0.4
 * 
 * Loads optional enhanced Trackator output files:
 * - trackator-storage.json (Storage Dependency Analyzer)
 * - trackator-coupling.json (State Coupling Detector)
 * - trackator-sync.json (Sync Analyzer)
 * - trackator-evidence.json (Evidence Validator)
 * 
 * Falls back gracefully if files don't exist (v1.0 compatibility mode).
 */
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

---

# Phase 1: INTENT FILTERING Functions

## intentFilter() - Intended Behavior Plugin Decision Logic

**Location**: Phase 1, Intended Behavior Plugin  
**Purpose**: Determines if alert points at intentional design rather than bug

```javascript
/**
 * Phase 1: Intent Filter (Intended Behavior Plugin)
 * Source: SKILL.md Phase 1 - Intended Behavior Plugin
 * 
 * Decision logic for filtering false positives by comparing against:
 * 1. Known trust assumptions
 * 2. Component responsibility definitions
 * 3. Operational error patterns
 * 4. Exploitable design choices (keep even if "intended")
 * 
 * Returns verdict: keep | downgrade_to_info | discard | keep_with_note
 */
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

## Operational Error Detection Pattern

**Location**: Phase 1, Intent Filter Check 3  
**Purpose**: Identifies operational errors (trusted role using authorized functions)

```javascript
/**
 * Phase 1: Operational Error Detection
 * Source: SKILL.md Phase 1 - Intent Filter Check 3
 * 
 * Detects scenarios where trusted roles (admin, keeper, governance, oracle)
 * are using their authorized functions correctly - these are NOT bugs.
 * 
 * Operational errors to detect:
 * - Admin sets high fee rate (authorized config change)
 * - Admin sets oracle to dead address (operational failure, not vuln)
 * - Keeper doesn't call liquidate (human oversight)
 * - Governance passes proposal to drain funds (governance working as designed)
 */

// Helper: Check if alert represents operational error
function isOperationalError(alert, context) {
    // Check if function has trusted role modifier
    const funcModifiers = alert.functionModifiers || [];
    const hasTrustedRoleModifier = funcModifiers.some(m => 
        ['onlyRole', 'onlyOwner', 'onlyGovernance', 'onlyKeeper'].includes(m)
    );
    
    // Check if action is within authorized scope
    const isAuthorizedAction = alert.category === 'config_change' ||
                               alert.category === 'admin_action' ||
                               alert.category === 'governance_action';
    
    return hasTrustedRoleModifier && isAuthorizedAction;
}
```

## Component Responsibility Check

**Location**: Phase 1, Intent Filter Check 2  
**Purpose**: Checks if component's documented responsibility explains the alert

```javascript
/**
 * Phase 1: Component Responsibility Check
 * Source: SKILL.md Phase 1 - Intent Filter Check 2
 * 
 * Checks if the alert can be explained by the component's documented
 * responsibility and interface specifications.
 */

// Helper: Find component responsible for the alerted field
function findComponentForField(alert, components) {
    const targetField = alert.targetField || alert.variable;
    if (!targetField || !components) return null;
    
    return components.find(comp => 
        comp.variables?.includes(targetField) ||
        comp.interfaces?.some(iface => 
            iface.fields?.includes(targetField) ||
            iface.functions?.includes(alert.functionName)
        )
    );
}

// Helper: Determine if behavior matches component design
function isWorkingAsDesigned(alert, component) {
    // Check if alert pattern is in component's expected behaviors
    const expectedBehaviors = component.expectedBehaviors || [];
    return expectedBehaviors.some(b => b.pattern === alert.pattern);
}
```

---

# Phase 2: PATTERN MATCHING Functions

## patternMatch() - Pattern Matching Algorithm

**Location**: Phase 2, Pattern Matcher Plugin  
**Purpose**: Matches alerts against historical exploit patterns from Exploits-class-library

```javascript
/**
 * Phase 2: Pattern Matching Algorithm
 * Source: SKILL.md Phase 2 - Pattern Matcher Plugin
 * 
 * Cross-references surviving hypotheses against historical exploit pattern cards
 * from Exploits-class-library to find matches and assess reachability.
 * 
 * Match scoring factors (base):
 * - Factor 1: Bug class match (30%) - reentrancy ↔ CEI violation
 * - Factor 2: Protocol type match (25%)
 * - Factor 3: Detection heuristic match (25%)
 * - Factor 4: Severity alignment (10%)
 * - Factor 5: Prerequisite satisfaction (10%)
 * 
 * v2.0 Additional factors (6-9):
 * - Factor 6: Storage Dependency Alignment (+10% bonus)
 * - Factor 7: State Coupling Signal (+10% bonus)
 * - Factor 8: Synchronization Risk (+10% bonus)
 * - Factor 9: Evidence Validator Pre-Classification (adjusts confidence)
 */
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

/**
 * Calculate pattern match score using weighted factors.
 * Maximum base score: 1.0
 * With v2.0 bonuses: up to 1.35 (capped at 1.0)
 */
function calculatePatternMatch(alert, pattern) {
    let score = 0;
    
    // Factor 1: Bug class match (weight: 30%)
    if (alert.category === pattern.primary_bug_class) {
        score += 0.30;
    } else if (isRelatedBugClass(alert.category, pattern.primary_bug_class)) {
        score += 0.15;  // Partial match
    }
    
    // Factor 2: Protocol type match (weight: 25%)
    if (pattern.protocol_types?.includes(context.protocolType)) {
        score += 0.25;
    }
    
    // Factor 3: Detection heuristic match (weight: 25%)
    const heuristicMatch = checkDetectionHeuristic(alert, pattern.detection_checklist);
    score += 0.25 * heuristicMatch;
    
    // Factor 4: Severity alignment (weight: 10%)
    const severityAlignment = alignSeverity(alert.severity, pattern.historical_severity);
    score += 0.10 * severityAlignment;
    
    // Factor 5: Prerequisite satisfaction (weight: 10%)
    const prereqSatisfaction = checkPrerequisites(alert, pattern.prerequisites, context);
    score += 0.10 * prereqSatisfaction;
    
    // ═══════════════════════════════════════════════════
    // v2.0 BONUS FACTORS (requires enhanced Trackator data)
    // ═══════════════════════════════════════════════════
    
    // Factor 6: Storage Dependency Alignment (+10% bonus)
    if (context.storage) {
        score += 0.10 * checkStorageAlignment(alert, pattern, context.storage);
    }
    
    // Factor 7: State Coupling Signal (+10% bonus)
    if (context.coupling) {
        score += 0.10 * checkCouplingSignal(alert, pattern, context.coupling);
    }
    
    // Factor 8: Synchronization Risk (+10% bonus)
    if (context.sync) {
        score += 0.10 * checkSyncRisk(alert, pattern, context.sync);
    }
    
    // Factor 9: Pre-classification adjustment
    if (context.evidence) {
        const preClass = checkPreClassification(alert, context.evidence);
        if (preClass.class === 'false-positive') score *= 0.5;  // Discount
        if (preClass.class === 'confirmedVulnerability') score *= 1.1;  // Boost
    }
    
    // Cap at 1.0
    return Math.min(score, 1.0);
}
```

## reachabilityCheck() - Reachability Check Function (BLOCK GATE #1)

**Location**: Phase 2, Reachability Check Plugin  
**Purpose**: Verifies if matched pattern is actually reachable by attacker (BLOCK GATE, not kill gate)

```javascript
/**
 * Phase 2: Reachability Check (BLOCK GATE #1)
 * Source: SKILL.md Phase 2 - Reachability Check Plugin
 * 
 * IMPORTANT: This is a BLOCK GATE, not kill gate!
 * - Block gates SAVE findings for PoC validation
 * - Kill gates DELETE findings forever
 * 
 * Verdict states:
 * - 'dead': Proven unreachable (all preconditions unsatisfied, no unknowns)
 * - 'confirmed_pattern': All preconditions satisfied
 * - 'probable': Most preconditions satisfied, some unknowns
 * - 'lead': More unknowns than satisfied, but still interesting
 * 
 * Block gate logic: saveForPoC=true when there are unknowns
 */
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

---

# Phase 3: CREATIVE ATTACK Functions (THE BIGGEST)

## reverseEngineer() + traceFlowBackwards() - Reverse Engineering Plugin

**Location**: Phase 3, Reverse Engineering Plugin  
**Purpose**: Follow Trackator value flows BACKWARDS to find manipulation points

```javascript
/**
 * Phase 3: Reverse Engineering Plugin
 * Source: SKILL.md Phase 3 - Reverse Engineering Plugin
 * 
 * Follows Trackator value flows BACKWARDS to find manipulation points.
 * Starts from assets at risk and traces backwards through money flows
 * to identify where attacker can inject malicious inputs or state changes.
 * 
 * Manipulation point types:
 * - 'input': Attacker can influence function input directly
 * - 'state': Attacker can manipulate state variable before it's read
 * - 'timing': Front-running or sandwich attack possible
 */
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

/**
 * Traces a money flow backwards to find manipulation points.
 * Analyzes each step for:
 * - External inputs attacker can control
 * - State dependencies that can be manipulated
 * - Timing dependencies enabling front-running
 */
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

## assumptionBreaker() + breakCriticalDesyncRisks() - Assumption Breaker Plugin

**Location**: Phase 3, Assumption Breaker Plugin  
**Purpose**: Systematically tests each Trackator trust assumption for exploitation potential

```javascript
/**
 * Phase 3: Assumption Breaker Plugin
 * Source: SKILL.md Phase 3 - Assumption Breaker Plugin
 * 
 * Systematically tests each Trackator trust assumption to see if breaking it
 * leads to exploitation. CRITICAL RULE: Only test assumptions that can be
 * broken by EXTERNAL attackers, not by trusted roles being malicious.
 * 
 * v2.0 ENHANCED: Now leverages Sync Analyzer's assumptionDependencyGraph
 * and criticalDesyncRisks for precision targeting.
 * 
 * Allowed categories to test:
 * - oracle: External market force
 * - external-contract: May have bugs, may be upgradeable
 * - price-feed: MEV/front-runnable
 * 
 * Disallowed categories:
 * - governance: Trusted role
 * - admin key compromise: Operational security
 * - keeper misbehavior: Trusted role
 */
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

/**
 * v2.0 NEW: Break critical desynchronization risks from Sync Analyzer
 * Source: SKILL.md Phase 3 - Assumption Breaker Plugin (v2.0 enhancement)
 * 
 * Targets three types of critical desync risks:
 * - stale-price: Exploit price staleness window
 * - missing-verifier: Exploit unverified assumptions
 * - race-window: Exploit timing-based race conditions
 */
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

/**
 * Break oracle assumption with specific attack vectors
 */
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

## buildExecutionTrace() + drawConclusion() - Full Execution Trace Structure/Builder

**Location**: Phase 3, MANDATORY Full Execution Trace  
**Purpose**: Builds complete A→B→C→end execution trace BEFORE escalating to Verifier

```javascript
/**
 * Phase 3: MANDATORY Full Execution Trace Builder
 * Source: SKILL.md Phase 3 - Full Execution Trace
 * 
 * ★ MANDATORY: Before escalating ANY creative hypothesis to Verifier,
 * Hacker MUST complete full execution trace A → B → C → end of execution.
 * 
 * The trace builder:
 * 1. Starting from entry function, follows ALL internal calls
 * 2. Records modifiers, external calls, state reads/writes
 * 3. Detects cycles and notes them
 * 4. Has safety limit of 100 steps to prevent infinite traces
 * 5. Produces final state analysis and survival conclusion
 * 
 * Key fields recorded per step:
 * - function name and contract
 * - access modifiers (onlyRole, nonReentrant, etc.)
 * - whether external call exists (reentrancy vector)
 * - CEI pattern compliance
 * - state variables read/written
 * - internal calls made
 */
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

/**
 * Draws conclusion about whether hypothesis survives full trace analysis.
 * Checks for:
 * 1. Reentrancy possibility (external calls before state updates)
 * 2. Presence of guards (nonReentrant, etc.)
 * 3. Overall survivability assessment
 */
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

## stateCouplingAnalysis() - State Coupling Analysis Functions (~500 lines)

**Location**: Phase 3, State Coupling Analysis Plugin (v2.0 NEW → v2.1 ENHANCED)  
**Purpose**: Uses Trackator's State Coupling Detector data to find coupling-based attack vectors

```javascript
/**
 * Phase 3: State Coupling Analysis (v2.0 NEW → v2.1 ENHANCED)
 * Source: SKILL.md Phase 3 - State Coupling Analysis Plugin
 * 
 * Uses Trackator's State Coupling Detector data to find coupling-based
 * attack vectors that don't appear in individual function analysis.
 * 
 * v2.1 ENHANCEMENT (Fix A Integration): Now consumes ALL output fields from
 * enhanced state-coupling-detector.ts including:
 * - functionDependencyMatrix with couplingClusters[], statistics
 * - hiddenCouplings[] with 13 coupling types (not just transient)
 * - invariantFunctionMap with violationPaths[], protectionGaps[]
 * - variableClassification[] for targeted variable attacks
 * - topStateIntersections[] with full participant analysis
 * - hiddenAssumptions[] with exploitability-based prioritization
 * - criticalFindings[] as priority queue (quick access array)
 * 
 * Philosophy: "Two functions that share state are safer than they look—until
 * you realize an attacker can call both in one transaction."
 * 
 * Attack Patterns Identified:
 * 1. Strong Coupling + Permissionless Entry (with cluster support)
 * 2. Hidden Couplings (all 13 types)
 * 3. Invariant Violation Paths (pre-computed)
 * 4. Protection Gap Exploitation
 * 5. Hidden Assumption Exploitation
 * 6. Variable Classification Targeting (sensitive vars)
 */
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
    // ATTACK PATTERNS 3-6: Invariant Violation Paths, Protection Gaps,
    //                      Hidden Assumptions, Variable Classification
    // ═══════════════════════════════════════════════════════════════
    // (See full implementation in SKILL.md for complete code)
    // These follow similar patterns to above with appropriate data structures
    
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

## intelligentPluginRouter() + batchRouteCouplingAttacks() - Intelligent Plugin Router Logic

**Location**: Phase 3, Intelligent Plugin Router (v2.1 NEW)  
**Purpose**: Routes hypotheses to most effective analysis plugin based on evidence type and criticality

```javascript
/**
 * Phase 3: Intelligent Plugin Router (v2.1 NEW)
 * Source: SKILL.md Phase 3 - Intelligent Plugin Router
 * 
 * Routes hypotheses to the most effective analysis plugin based on
 * Trackator evidence type and criticality. Uses criticalFindings[]
 * as priority queue and routes based on source phase.
 * 
 * Routing Matrix (evidence-type → plugin mapping):
 * 1. coupling-critical-findings → fork_tester (highest priority)
 * 2. coupling_cluster_exploitation → assumption_breaker
 * 3. protection_gap_exploitation → pattern_matcher (skip intent filter)
 * 4. invariant_violation_path → execution_tracer
 * 5. hidden_assumption_exploitation → assumption_breaker
 * 6. sensitive_variable_targeting → reverse_engineering
 * 7. hidden_coupling_* → specialized handler by subtype
 * 8. Standard routing for other types
 */
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
        routingDecision.primaryPlugin = 'assumption_breaker';
        routingDecision.secondaryPlugins = ['reverse_engineering', 'coupling_analyzer'];
        routingDecision.routingRationale = 'Coupling cluster requires multi-function assumption breaking';
        routingDecision.priority = (hypothesis.priorityBoost || 0) + 70;
        routingDecision.estimatedValue = 'high';
        
        console.log(`🟠 ROUTE: ${hypothesis.id} → Assumption Breaker (cluster attack)`);
        return routingDecision;
    }
    
    // 3. Protection gap exploits → Intent Filter bypass (already validated as gap)
    if (attackType === 'protection_gap_exploitation') {
        routingDecision.primaryPlugin = 'pattern_matcher';
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
        routingDecision.primaryPlugin = 'execution_tracer';
        routingDecision.secondaryPlugins = ['evidence_validator'];
        routingDecision.routingRationale = 'Pre-computed violation path - execute and validate';
        routingDecision.priority = (hypothesis.priorityBoost || 0) + 75;
        routingDecision.estimatedValue = hypothesis.trackatorEvidence?.feasibility === 'trivial' ? 'critical' : 'high';
        
        console.log(`🟡 ROUTE: ${hypothesis.id} → Execution Tracer (violation path)`);
        return routingDecision;
    }
    
    // 5. Hidden assumption exploits → Assumption Breaker (primary use case)
    if (attackType === 'hidden_assumption_exploitation') {
        routingDecision.primaryPlugin = 'assumption_breaker';
        routingDecision.secondaryPlugins = ['reverse_engineering'];
        routingDecision.routingRationale = 'Hidden assumption - primary target for assumption breaker plugin';
        routingDecision.priority = (hypothesis.priorityBoost || 0) + 65;
        routingDecision.estimatedValue = hypothesis.trackatorEvidence?.exploitability === 'trivial' ? 'high' : 'medium';
        
        console.log(`🟡 ROUTE: ${hypothesis.id} → Assumption Breaker (assumption exploit)`);
        return routingDecision;
    }
    
    // 6. Sensitive variable targeting → Reverse Engineering (follow the money)
    if (attackType === 'sensitive_variable_targeting') {
        routingDecision.primaryPlugin = 'reverse_engineering';
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
            routingDecision.primaryPlugin = 'pattern_matcher';
            routingDecision.secondaryPlugins = ['reachability_checker', 'fork_tester'];
            routingDecision.routingRationale = `High-risk ${couplingType} - match against historical proxy exploits`;
            routingDecision.priority = (hypothesis.priorityBoost || 0) + 85;
            routingDecision.estimatedValue = 'critical';
        } else {
            routingDecision.primaryPlugin = 'reachability_checker';
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

/**
 * v2.1: Batch router for processing all coupling attacks at once
 */
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

## calibrateEvidenceWithTrackator() - Evidence Calibration System

**Location**: Phase 3/4, Evidence Calibration System (v2.0 → v2.1 ENHANCED)  
**Purpose**: Consumes Evidence Validator outputs (Fix D) for court-ready confidence scoring

```javascript
/**
 * Phase 3/4: Multi-Dimensional Evidence Calibration System (v2.0 → v2.1 ENHANCED)
 * Source: SKILL.md Phase 4 - Evidence Calibration System
 * 
 * Consumes Evidence Validator outputs (Fix D) for court-ready confidence scoring.
 * 
 * v2.1 ENHANCEMENT (Fix D Integration): Now consumes ALL output fields from
 * enhanced evidence-validator.ts:
 * - classificationRegistry with full 6-class system
 * - reachabilityAnalysis[] with execution paths, cross-contract prerequisites
 * - disproofEngine with 11 disproof strategies and confidence scores
 * - confidenceAssessments[] with multi-dimensional score breakdown
 * - proofRequirements[] with 9-criteria checklist for ReachableBug
 * - finalVerdict[] with RecommendedAction enum alignment
 * 
 * Calibration Parts:
 * PART 1: 6-Class Classification (proven-property, potential-bug, reachable-bug,
 *          false-positive, by-design, insufficient-evidence)
 * PART 2: Reachability Analysis (full path + cross-contract prereqs)
 * PART 3: Disproof Analysis (strategy-by-strategy confidence)
 * PART 4: Multi-Dimensional Confidence (overall, evidence, reachability, impact, FP risk)
 * PART 5: Proof Requirements (9-criteria checklist)
 * PART 6: Final Verdict & Recommended Action
 */
function calibrateEvidenceWithTrackator(finding, context) {
    if (!context.evidence) {
        console.log('⚠️ No evidence data available - using basic classification');
        return basicClassification(finding);
    }
    
    const calibration = {
        findingId: finding.id,
        
        // PART 1: 6-Class Classification (from Fix D)
        classification: null,
        classificationConfidence: 0,
        criteriaMet: [],
        criteriaFailed: [],
        
        // PART 2: Reachability Analysis (from Fix D)
        reachability: null,
        executionPath: null,
        crossContractPrereqs: [],
        blockingRequirement: null,
        
        // PART 3: Disproof Analysis (from Fix D)
        disproofResult: null,
        disproofConfidence: 0,
        disproofStrategiesAttempted: [],
        
        // PART 4: Multi-Dimensional Confidence (from Fix D)
        confidenceBreakdown: {
            overall: 0,
            evidenceStrength: 0,
            reachabilityConfidence: 0,
            impactConfidence: 0,
            falsePositiveRisk: 0
        },
        
        // PART 5: Proof Requirements (9-criteria from Fix D)
        proofRequirements: {
            met: 0,
            total: 9,
            requirements: [],
            status: 'not-proven'
        },
        
        // PART 6: Final Verdict & Action (from Fix D)
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
        const matchingEntry = classificationRegistry.entries.find(e => 
            e.findingId === finding.id || 
            e.title === finding.title ||
            e.originalFindingId === finding.trackatorEvidence?.originalFindingId
        );
        
        if (matchingEntry) {
            calibration.classification = matchingEntry.classification;
            calibration.classificationConfidence = matchingEntry.confidence;
            calibration.criteriaMet = matchingEntry.supportingEvidence?.map(e => e.itemId) || [];
            calibration.criteriaFailed = matchingEntry.blockingEvidence?.map(e => e.itemId) || [];
            
            console.log(`  📋 Classification: ${calibration.classification} (${calibration.classificationConfidence}%)`);
        } else {
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
            calibration.executionPath = matchingPath.callChain;
            
            calibration.crossContractPrereqs = (matchingPath.crossContractPrereqs || []).map(ccp => ({
                targetContract: ccp.targetContract,
                requiredState: ccp.requiredState,
                dependencyType: ccp.dependencyType,
                canBeSatisfied: ccp.canBeSatisfied
            }));
            
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
            calibration.disproofResult = matchingDisproof.newClassification;
            calibration.disproofConfidence = matchingDisproof.confidence;
            
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
            calibration.confidenceBreakdown = {
                overall: matchingAssessment.overallConfidence,
                evidenceStrength: matchingAssessment.evidenceStrength,
                reachabilityConfidence: matchingAssessment.reachabilityConfidence,
                impactConfidence: matchingAssessment.impactConfidence,
                falsePositiveRisk: matchingAssessment.falsePositiveRisk
            };
            
            calibration.remainingUnknowns = (matchingAssessment.remainingUnknowns || []).map(u => ({
                factor: u.factor,
                whyUnknown: u.whyUnknown,
                impactIfWrong: u.impactIfWrong,
                suggestedInvestigation: u.suggestedInvestigation
            }));
            
            console.log(`  📊 Confidence: ${calibration.confidenceBreakdown.overall}%`);
            console.log(`     Evidence: ${calibration.confidenceBreakdown.evidenceStrength}%, Reachability: ${calibration.confidenceBreakdown.reachabilityConfidence}%`);
            console.log(`     Impact: ${calibration.confidenceBreakdown.impactConfidence}%, FP Risk: ${calibration.confidenceBreakdown.falsePositiveRisk}%`);
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
                status: matchingProofReq.overallStatus,
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
            calibration.finalVerdict = matchingVerdict.finalVerdict;
            calibration.recommendedAction = matchingVerdict.recommendedAction;
            
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

/**
 * v2.1: Local classification fallback when no Trackator entry matches
 */
function classifyFindingV21(finding, context) {
    const classMapping = {
        'confirmed-vulnerability': { class: 'reachable-bug', minConfidence: 85 },
        'potential-vulnerability': { class: 'potential-bug', minConfidence: 60 },
        'false-positive': { class: 'false-positive', minConfidence: 0 },
        'by-design': { class: 'by-design', minConfidence: 0 },
        'informational': { class: 'proven-property', minConfidence: 30 },
        'cannot-determine': { class: 'insufficient-evidence', minConfidence: 0 }
    };
    
    let score = 50;  // Base uncertainty
    
    if (finding.trackatorEvidence?.matrixEntry) score += 15;
    if (finding.prerequisiteChain?.length >= 4) score += 10;
    if (finding.estimatedDifficulty === 'easy') score += 10;
    if (finding.trackatorEvidence?.source === 'criticalFindings[]') score += 15;
    
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

/**
 * v2.1: Derive verdict when Trackator doesn't provide one
 */
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

/**
 * v2.1: Derive recommended action from verdict
 */
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

---

# Phase 4: FUZZING Functions

## generateFizzProperties() + mapInvariantToFizzProperty() - Fuzz Property Generation

**Location**: Phase 4, Fuzz Property Generation  
**Purpose**: Maps Trackator invariants to Fizz/Echidna/Medusa properties

```javascript
/**
 * Phase 4: Generate Fuzz Properties from Trackator Invariants
 * Source: SKILL.md Phase 4 - Generating Fuzz Properties from Trackator Invariants
 * 
 * Maps Trackator invariants to Fizz properties for Echidna/Medusa testing.
 * Also adds adversarial profit-maximizing properties from Fizz skill.
 * 
 * Category Mapping:
 * - accounting → HIGH_LEVEL
 * - bounds → VARIABLE_TRANSITION
 * - oracle → HIGH_LEVEL
 * - permission → STATE_TRANSITION
 */
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

/**
 * Generate adversarial (attack-oriented) properties from Fizz
 * Source: SKILL.md Phase 4 - Adversarial Properties
 * 
 * These properties test for economic security:
 * - No free profit extraction
 * - Flash loan resistance
 * - Withdrawal liveness
 * - First depositor protection
 */
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

## realismCheck() - Realism Check Verdict Function (BLOCK GATE #3)

**Location**: Phase 4, Realism Check Plugin  
**Purpose**: Filters out fuzz findings that aren't reachable on real mainnet state

```javascript
/**
 * Phase 4: Realism Check (BLOCK GATE #3)
 * Source: SKILL.md Phase 4 - Realism Check Plugin
 * 
 * Filters out fuzz findings that aren't reachable on real mainnet state.
 * This is a BLOCK GATE - saves questionable findings for manual review
 * instead of discarding them.
 * 
 * Checks performed:
 * 1. Does finding require unrealistic state?
 * 2. Does finding require trusted role action?
 * 3. Is there enough capital/liquidity?
 * 
 * Returns verdict: realistic | unrealistic | operational_error | impractical
 */
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

## disproofEngine() + searchForGuardCode() - Disproof Engine Implementation

**Location**: Phase 4, Disproof Engine Plugin (v2.0 NEW)  
**Purpose**: Attempts to DISPROVE fuzz findings before accepting them as vulnerabilities

```javascript
/**
 * Phase 4: Disproof Engine (v2.0 NEW)
 * Source: SKILL.md Phase 4 - Disproof Engine Plugin
 * 
 * Attempts to DISPROVE fuzz findings before accepting them as vulnerabilities.
 * This is the opposite of typical vulnerability research—instead of proving
 * bugs exist, we try to prove they DON'T.
 * 
 * Philosophy: "A finding that survives disproof attempts is stronger than
 * one that was never challenged."
 * 
 * Disproof Attempt Strategies:
 * 1. Guard Code Search - Look for require/assert/check patterns
 * 2. Semantic Analysis - Does pattern actually lead to loss?
 * 3. Historical Pattern Cross-Check - Has similar pattern been disproved?
 * 4. Invariant Consistency Check - Do protecting invariants prevent exploitation?
 * 
 * Results: DISPROVED | NOT_DISPROVED | CANNOT_DETERMINE
 */
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

/**
 * Search for guard code that might prevent exploitation
 */
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

---

# Phase 5: FORK TESTING Functions

## FORK_CONFIG - Fork Test Infrastructure Setup

**Location**: Phase 5, Fork Testing Infrastructure  
**Purpose**: Configuration for Foundry fork testing

```javascript
/**
 * Phase 5: Fork Testing Infrastructure Configuration
 * Source: SKILL.md Phase 5 - Fork Testing Infrastructure
 * 
 * Configuration for Foundry fork testing against real mainnet state.
 */
const FORK_CONFIG = {
    rpcUrl: process.env.MAINNET_RPC_URL || 'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
    blockNumber: process.env.FORK_BLOCK_NUMBER || 'latest',
    maxIterations: MAX_FORK_ITERATIONS || 10,
    timeoutMs: 300000  // 5 minutes max per iteration
};
```

## smokeForkTest() - Smoke Fork Test Execution

**Location**: Phase 5, Step 5.1  
**Purpose**: Verifies basic functionality works on forked state

```javascript
/**
 * Phase 5: Smoke Fork Test
 * Source: SKILL.md Phase 5 - Step 5.1
 * 
 * Verifies basic functionality works on forked mainnet state before
 * running expensive deep fork tests.
 */
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

## deepForkTestWithIteration() - Deep Fork Testing Iteration Loop

**Location**: Phase 5, Step 5.2  
**Purpose**: Main iteration loop for fork testing - THIS IS THE HEART OF PHASE 5

```javascript
/**
 * Phase 5: Deep Fork Testing with Iteration (THE HEART OF PHASE 5)
 * Source: SKILL.md Phase 5 - Step 5.2
 * 
 * The hacker runs exploit attempts on forked mainnet, observes Trackator
 * visualization of results, and ITERATES until success or max iterations.
 * 
 * Flow per iteration:
 * 1. Build exploit attempt based on hypothesis + learnings
 * 2. Run on forked mainnet
 * 3. Feed result into Trackator for analysis (visualization)
 * 4. Hacker analyzes visualization output
 * 5. Decide: iterate or conclude?
 * 6. Generate modifications for next attempt (if iterating)
 * 
 * Termination conditions:
 * - Success: meaningful exploit confirmed
 * - Dead end: no more modifications possible
 * - Max iterations reached
 */
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

## analyzeVisualization() - Hacker Visualization Analysis Helpers

**Location**: Phase 5, Hacker Visualization Analysis  
**Purpose**: How hacker interprets Trackator output from fork test

```javascript
/**
 * Phase 5: Hacker Visualization Analysis
 * Source: SKILL.md Phase 5 - Hacker Visualization Analysis
 * 
 * How hacker interprets Trackator output from fork test results.
 * Analyzes four key areas:
 * 1. State Diff Analysis - Did attacker profit? Did protocol lose funds?
 * 2. Alert Analysis - Any unexpected alerts (new attack vectors)?
 * 3. Oracle Impact - Price deviation analysis
 * 4. Invariant Violations - Which invariants were broken?
 */
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

## generateModifications() - Modification Generation Logic

**Location**: Phase 5, Modification Generation  
**Purpose**: How hacker generates modifications for next iteration attempt

```javascript
/**
 * Phase 5: Modification Generation (How Hacker Iterates)
 * Source: SKILL.md Phase 5 - Modification Generation
 * 
 * Generates modification suggestions based on what went wrong in
 * the previous fork test iteration.
 * 
 * Modification types:
 * - fix_revert: Address specific revert reason
 * - increase_manipulation: Increase flash loan size / price impact
 * - scale_position: Increase position size for meaningful profit
 * - add_precondition: Add missing preliminary transactions
 * - pivot_attack: Switch to newly discovered attack vector
 */
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

---

# Phase 6: REPORTING Functions

## generateReport() - Report Generation Code

**Location**: Phase 6, Report Generation  
**Purpose**: Generates comprehensive report of all confirmed and probable findings

```javascript
/**
 * Phase 6: Report Generation
 * Source: SKILL.md Phase 6 - Report Generation Code
 * 
 * Generates comprehensive report of all confirmed and probable findings.
 * Outputs both Markdown (human-readable) and JSON (machine-readable).
 */
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

## renderReportToMarkdown() - Render Report to Markdown

**Location**: Phase 6, Report Rendering  
**Purpose**: Converts report object to formatted markdown string

```javascript
/**
 * Phase 6: Render Report to Markdown
 * Source: SKILL.md Phase 6 - Report Structure (template)
 * 
 * Converts report data structure to formatted markdown following
 * the official report template structure.
 * 
 * Report sections:
 * - Executive Summary (metrics table)
 * - Critical Findings (detailed vulnerability reports)
 * - Probable Findings (with caveats)
 * - Leads for Manual Review (brief descriptions)
 * - Appendix A: Discarded Hypotheses Summary
 * - Appendix B: Trackator Context
 * - Appendix C: Trackator Multi-Phase Evidence (v2.0)
 * - Appendix D: Confidence Scoring & Classification (v2.0)
 * - Appendix E: Methodology Notes
 * - Appendix F: Raw Data Index
 */
function renderReportToMarkdown(report) {
    // Implementation follows template structure from SKILL.md
    // See Phase 6 Report Structure for full template
    
    let md = `# Redteam-Trackator Security Assessment Report\n\n`;
    md += `**Protocol:** ${report.metadata.protocol}\n`;
    md += `**Assessment Date:** ${report.metadata.date}\n`;
    md += `**Version:** ${report.metadata.version}\n\n---\n\n`;
    
    // Executive Summary
    md += `## Executive Summary\n\n`;
    md += `| Metric | Value |\n|--------|-------|\n`;
    md += `| Total Hypotheses Generated | ${report.executiveSummary.totalHypotheses} |\n`;
    md += `| Confirmed Vulnerabilities | ${report.executiveSummary.confirmedCount} |\n`;
    md += `| Probable Findings | ${report.executiveSummary.probableCount} |\n`;
    md += `| Leads for Manual Review | ${report.executiveSummary.leadsCount} |\n`;
    md += `| False Positives Discarded | ${report.executiveSummary.discardedCount} |\n`;
    md += `| True Positive Rate (Est.) | ${report.executiveSummary.truePositiveRate}% |\n\n---\n\n`;
    
    // Findings sections would follow...
    // (Full implementation in actual report generator)
    
    return md;
}
```

---

# UTILITY FUNCTIONS

## calculateConfidence() - Confidence Score Calculation (Full Version)

**Location**: Utility Functions Section  
**Purpose**: Calculates composite confidence score for each confirmed/probable finding

```javascript
/**
 * Confidence Score Calculation (Full Version)
 * Source: SKILL.md - Confidence Score Calculation
 * 
 * Each confirmed/probable finding receives a composite confidence score
 * based on five weighted factors:
 * 
 * Weights:
 * - patternMatch: 0.20 (How well does it match historical exploit?)
 * - traceComplete: 0.20 (Was full execution trace completed?)
 * - fuzzValidation: 0.15 (Did fuzz testing reproduce it?)
 * - forkSuccess: 0.35 (Did it work on forked mainnet?) - MOST IMPORTANT
 * - economicFeasibility: 0.10 (Is it profitable in practice?)
 * 
 * Tier mapping:
 * - >= 0.7: CONFIRMED
 * - >= 0.4: PROBABLE
 * - >= 0.2: LEAD
 * - < 0.2: DISCARDED
 */
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

## Error Handling Patterns

**Location**: Error Handling & Edge Cases Section  
**Purpose**: Graceful degradation patterns for missing/failed dependencies

```javascript
/**
 * Error Handling Patterns
 * Source: SKILL.md - Error Handling & Edge Cases
 * 
 * Graceful degradation patterns for when optional dependencies
 * are missing or fail. The system should continue operating in
 * degraded mode rather than failing completely.
 */

// Pattern 1: Missing Trackator Enrich Data
if (!trackatorEnrichData) {
    console.warn('⚠️ No enrich data available - running in degraded mode');
    // Fall back to basic static analysis only
    // Skip phases that require enrich data (1, 3 partially)
}

// Pattern 2: No Exploits Library Available
if (!existsSync(EXPLOITS_LIBRARY_PATH)) {
    console.warn('⚠️ No exploits library - skipping pattern matching');
    // Proceed with creative attack phase only
}

// Pattern 3: Fizz Skill Not Available
if (!checkFizzAvailable()) {
    console.warn('⚠️ Fizz skill not available - skipping fuzz phase');
    // Continue with fork testing only
}

// Pattern 4: Fork RPC Issues
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

# QUICK REFERENCE INDEX

## Code Blocks by Phase

| Phase | Function Name | Lines (approx.) | Purpose |
|-------|--------------|-----------------|---------|
| 0 | `validateTrackatorOutput()` | 22 | Validate Trackator files |
| 0 | `buildHypothesisList()` | 22 | Build hypothesis list |
| 0 | `calculatePriorityScore()` | 18 | Priority scoring |
| 0 | `extractProtocolContext()` | 17 | Build context object |
| 0 | `extractEnhancedContext()` | 53 | Load v2.0 enhanced data |
| 1 | `intentFilter()` | 34 | Intent filtering decision |
| 1 | `isOperationalError()` | 14 | Op error detection |
| 1 | `findComponentForField()` | 12 | Component lookup |
| 2 | `patternMatch()` | 27 | Pattern matching algorithm |
| 2 | `calculatePatternMatch()` | 55 | Match scoring (9 factors) |
| 2 | `reachabilityCheck()` | 46 | Block gate #1 |
| 3 | `reverseEngineer()` | 33 | Reverse engineering |
| 3 | `traceFlowBackwards()` | 32 | Backward tracing |
| 3 | `assumptionBreaker()` | 24 | Assumption breaking |
| 3 | `breakCriticalDesyncRisks()` | 68 | Desync risk exploitation |
| 3 | `breakOracleAssumption()` | 28 | Oracle attacks |
| 3 | `buildExecutionTrace()` | 67 | Full trace builder |
| 3 | `drawConclusion()` | 28 | Trace conclusion |
| 3 | `stateCouplingAnalysis()` | ~200 | Coupling analysis (partial) |
| 3 | `intelligentPluginRouter()` | 120 | Plugin routing |
| 3 | `batchRouteCouplingAttacks()` | 58 | Batch routing |
| 3 | `calibrateEvidenceWithTrackator()` | ~230 | Evidence calibration |
| 3 | `classifyFindingV21()` | 23 | Local classification |
| 3 | `deriveVerdict()` | 16 | Verdict derivation |
| 4 | `generateFizzProperties()` | 11 | Fuzz property generation |
| 4 | `mapInvariantToFizzProperty()` | 14 | Invariant mapping |
| 4 | `generateAdversarialProperties()` | 38 | Adversarial properties |
| 4 | `realismCheck()` | 28 | Block gate #2 |
| 4 | `disproofEngine()` | 92 | Disproof engine |
| 4 | `searchForGuardCode()` | 24 | Guard code search |
| 5 | `FORK_CONFIG` | 6 | Fork configuration |
| 5 | `smokeForkTest()` | 22 | Smoke test |
| 5 | `deepForkTestWithIteration()` | 82 | Deep fork iteration |
| 5 | `analyzeVisualization()` | 66 | Visualization analysis |
| 5 | `generateModifications()` | 55 | Modification generation |
| 6 | `generateReport()` | 48 | Report generation |
| 6 | `renderReportToMarkdown()` | 40 | Markdown rendering |
| Util | `calculateConfidence()` | 36 | Confidence calculation |
| Util | Error Patterns | ~30 | Error handling |

---

*End of Code Examples Reference*
