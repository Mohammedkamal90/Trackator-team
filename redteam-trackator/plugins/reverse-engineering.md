# Plugin: Reverse Engineering Plugin

**Phase**: 3 (Creative Attack)
**Purpose**: Follow Trackator value flows BACKWARDS to find manipulation points that pattern matching missed
**Type**: Generation plugin (creates NEW hypotheses from value flow analysis)

---

## Overview

This plugin enables the Hacker agent to think like an attacker by **tracing value flows backwards** from assets at risk to find input/state/timing manipulation points. It finds **novel vulnerabilities** that don't match historical patterns.

**v2.0 ENHANCED**: Now leverages **Storage Dependency Analyzer** data for weaponized attack surface mapping.

## Philosophy

> *"Start from 'what can we steal?' and work backwards to 'how do we steal it?'"*

Unlike Pattern Matcher (which matches known bugs), this plugin finds **unknown unknowns** — attack surfaces that emerge from the specific protocol's architecture.

---

## Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Assets at risk | `context.assetsAtRisk` | What's worth stealing |
| Money flows | `context.moneyFlows` | How value moves through protocol |
| Entry points | `context.entryPoints` | Where attacker can interact |
| State variables | `initData.contracts[].stateVariables` | What can be manipulated |
| Call graph | `initData.callGraph` | How functions connect |

---

## Algorithm

### Step 1: Identify High-Value Targets

```javascript
function identifyHighValueTargets(context) {
    // Sort assets by type and estimated value
    const targets = context.assetsAtRisk
        .map(asset => ({
            ...asset,
            // Estimate value based on type
            valueTier: estimateValueTier(asset),
            // Find flows involving this asset
            flows: context.moneyFlows.filter(f => 
                f.involvesAsset(asset.name) || 
                f.steps?.some(s => s.asset === asset.name)
            )
        }))
        .sort((a, b) => VALUE_TIER_ORDER.indexOf(a.valueTier) - VALUE_TIER_ORDER.indexOf(b.valueTier));
    
    return targets;
}

const VALUE_TIER_ORDER = ['critical', 'high', 'medium', 'low'];

function estimateValueTier(asset) {
    // ERC20 balances in core contracts = critical
    if (asset.type === 'erc20' && isCoreContract(asset.location)) return 'critical';
    
    // LP tokens / share tokens = high
    if (asset.type === 'lp' || asset.type === 'share') return 'high';
    
    // Governance tokens = medium (unless large balance)
    if (asset.type === 'governance') return 'medium';
    
    // Rewards/points = low individually but might compound
    return 'low';
}
```

### Step 2: Trace Money Flows Backwards

```javascript
function traceFlowBackwards(moneyFlow, context) {
    const manipulationPoints = [];
    
    // Walk through flow steps in REVERSE order
    for (let i = moneyFlow.steps.length - 1; i >= 0; i--) {
        const step = moneyFlow.steps[i];
        
        // Check each step for manipulability
        const point = analyzeStepForManipulation(step, i, context);
        if (point) {
            manipulationPoints.push(point);
        }
    }
    
    return manipulationPoints;
}

function analyzeStepForManipulation(step, stepIndex, context) {
    const analyses = [
        checkInputManipulability(step, context),
        checkStateDependency(step, context),
        checkTimingAttack(step, context),
        checkCallbackVulnerability(step, context),
        checkAccessControl(step, context)
    ];
    
    // Return first viable manipulation point found
    return analyses.find(a => a.isManipulable);
}
```

### Step 3: Manipulation Type Analyzers

#### 3A: Input Manipulation Check

```javascript
function checkInputManipulability(step, context) {
    // Can attacker control this step's inputs?
    
    if (!step.hasExternalInput) {
        return { isManipulable: false };
    }
    
    // Find the function
    const func = findFunction(step.function, context.contracts);
    if (!func) {
        return { isManipulable: false };
    }
    
    // Check parameters for attacker-controlled types
    const attackerControlledParams = func.parameters?.filter(p => {
        return p.type === 'address' || 
               p.type === 'contract' ||
               p.type === 'uint256' && !p.hasRangeCheck;
    }) || [];
    
    if (attackerControlledParams.length === 0) {
        return { isManipulable: false };
    }
    
    // Verify entry accessibility
    const entryPoint = context.entryPoints?.find(e => 
        e.name === func.name && e.contract === func.contractName
    );
    
    if (!entryPoint || entryPoint.access === 'internal') {
        return { isManipulable: false };
    }
    
    return {
        isManipulable: true,
        type: 'input',
        function: step.function,
        contract: func.contractName,
        manipulatedParams: attackerControlledParams.map(p => p.name),
        entryAccess: entryPoint.access,
        description: `Attacker can supply ${attackerControlledParams.map(p => p.name).join(', ')} to ${func.name}()`,
        trackatorEvidence: {
            fieldsUsed: ['functions[].parameters[]', 'entryPoints[].access'],
            functionName: func.name
        }
    };
}
```

#### 3B: State Dependency Check

```javascript
function checkStateDependency(step, context) {
    // Does this step depend on state that can be manipulated?
    
    if (!step.stateDependency) {
        return { isManipulable: false };
    }
    
    const stateVar = step.stateDependency;
    
    // Find where this state is written
    const writers = findStateWriters(stateVar, context.contracts);
    
    if (writers.length === 0) {
        return { isManipulable: false };  // Constant or immutable
    }
    
    // Check if any writer is accessible to attacker
    const vulnerableWriters = writers.filter(writer => {
        const writerFunc = findFunction(writer.function, context.contracts);
        if (!writerFunc) return false;
        
        const entryPoint = context.entryPoints?.find(e =>
            e.name === writerFunc.name && e.contract === writerFunc.contractName
        );
        
        return entryPoint && entryPoint.access !== 'internal';
    });
    
    if (vulnerableWriters.length === 0) {
        return { isManipulable: false };
    }
    
    return {
        isManipulable: true,
        type: 'state',
        targetVariable: stateVar,
        vulnerableWriters: vulnerableWriters.map(w => ({
            function: w.function,
            contract: w.contract,
            how: w.howWritten  // direct assignment, increment, etc.
        })),
        description: `${stateVar} can be manipulated via ${vulnerableWriters[0].function}(), affecting ${step.function}() outcome`,
        trackatorEvidence: {
            fieldsUsed: ['functions[].stateVariablesWritten[]', 'stateVariables[]'],
            variableName: stateVar
        }
    };
}
```

#### 3C: Timing Attack Check

```javascript
function checkTimingAttack(step, context) {
    // Is this step vulnerable to front-running/sandwich attacks?
    
    if (!step.hasTimingDependency) {
        return { isManipulable: false };
    }
    
    // Check if function reads price/oracle/block-dependent values
    const func = findFunction(step.function, context.contracts);
    if (!func) {
        return { isManipulable: false };
    }
    
    const timingIndicators = [
        func.stateVariablesRead?.some(v => 
            v.toLowerCase().includes('price') ||
            v.toLowerCase().includes('oracle') ||
            v.toLowerCase().includes('block')
        ),
        func.body?.hasExternalCall,  // Might read from DEX
        step.requiresSameBlock      // Explicit timing requirement
    ];
    
    if (!timingIndicators.some(Boolean)) {
        return { isManipulable: false };
    }
    
    return {
        isManipulable: true,
        type: 'timing',
        function: step.function,
        attackVectors: [],
        description: `${step.function}() has timing dependency - vulnerable to MEV/front-running`,
        trackatorEvidence: {
            fieldsUsed: ['functions[].stateVariablesRead[]', 'functions[].body.hasExternalCall'],
            indicators: timingIndicators
        }
    };
}
```

#### 3D: Callback Vulnerability Check

```javascript
function checkCallbackVulnerability(step, context) {
    // Does this step involve external calls to attacker-controlled addresses?
    
    const func = findFunction(step.function, context.contracts);
    if (!func || !func.body?.hasExternalCall) {
        return { isManipulable: false };
    }
    
    // CEI violation + external call = potential reentrancy/callback attack
    const ceiViolated = func.body.ceiPattern === 'violated';
    const hasNoReentrancyGuard = !func.modifiers?.some(m =>
        m.toLowerCase().includes('reentrancy') ||
        m.toLowerCase().includes('mutex')
    );
    
    if (!(ceiViolated || hasNoReentrancyGuard)) {
        return { isManipulable: false };
    }
    
    // Check if call target could be attacker-controlled
    const hasAttackerTarget = func.parameters?.some(p =>
        p.type === 'address'
    ) || func.calls?.some(c =>
        c.includes('msg.sender') || c.includes('.call')
    );
    
    return {
        isManipulable: true,
        type: 'callback',
        function: step.function,
        contract: func.contractName,
        ceiPattern: func.body.ceiPattern,
        hasGuard: !hasNoReentrancyGuard,
        attackerControlledTarget: hasAttackerTarget,
        description: ceiViolated 
            ? `CEI violation in ${func.name}() - state updated after external call`
            : `Missing reentrancy guard on ${func.name}() with external calls`,
        trackatorEvidence: {
            fieldsUsed: ['functions[].body.ceiPattern', 'functions[].body.hasExternalCall', 'functions[].modifiers[]'],
            ceiPattern: func.body.ceiPattern
        }
    };
}
```

#### 3E: Access Control Check

```javascript
function checkAccessControl(step, context) {
    // Does this step have missing or bypassable access control?
    
    const func = findFunction(step.function, context.contracts);
    if (!func) {
        return { isManipulable: false };
    }
    
    // Check for access control modifiers
    const hasAuthModifier = func.modifiers?.some(m =>
        m.includes('only') || 
        m.includes('require') ||
        m.includes('auth')
    );
    
    if (hasAuthModifier) {
        // Has auth modifier - check if it's bypassable
        // This would require deeper analysis of modifier logic
        return { isManipulable: false };  // Assume correct for now
    }
    
    // No auth modifier on state-changing function
    const changesState = func.stateVariablesWritten?.length > 0;
    const transfersValue = func.body?.hasTransfer;
    
    if (!changesState && !transfersValue) {
        return { isManipulable: false };  // View/pure function, no need for auth
    }
    
    return {
        isManipulable: true,
        type: 'access_control',
        function: step.function,
        contract: func.contractName,
        changesState,
        transfersValue,
        description: `Missing access control on ${func.name}() which ${changesState ? 'modifies state' : 'transfers value'}`,
        severity: transfersValue ? 'critical' : 'high',
        trackatorEvidence: {
            fieldsUsed: ['functions[].modifiers[]', 'functions[].stateVariablesWritten[]', 'functions[].body.hasTransfer'],
            missingModifier: true
        }
    };
}
```

### Step 4: Generate Creative Hypotheses

```javascript
function generateCreativeHypotheses(manipulationPoints, context) {
    return manipulationPoints.map((point, index) => ({
        id: `CREATIVE_${String(index + 1).padStart(2, '0')}`,
        type: 'reverse_engineering',
        
        // Target info
        targetAsset: point.targetAsset || point.asset || 'general_protocol_value',
        targetType: point.type,  // input, state, timing, callback, access_control
        
        // Entry point
        entryPoint: point.function,
        entryContract: point.contract,
        entryAccess: point.entryAccess || 'needs_analysis',
        
        // Attack concept
        attackIdea: buildAttackIdea(point, context),
        manipulationPoint: point.description,
        
        // Prerequisites
        prerequisiteChain: extractPrerequisites(point, context),
        
        // Confidence (lower than pattern matches - these are novel)
        estimatedDifficulty: estimateDifficulty(point),
        status: 'HYPOTHESIS',  // Needs execution trace
        
        // Evidence
        trackatorEvidence: point.trackatorEvidence,
        
        createdAt: new Date().toISOString()
    }));
}

function buildAttackIdea(point, context) {
    switch (point.type) {
        case 'input':
            return `Supply crafted ${point.manipulatedParams.join(', ')} to ${point.entryPoint}() to manipulate ${point.targetAsset}`;
        
        case 'state':
            return `Manipulate ${point.targetVariable} via ${point.vulnerableWriters[0].function}() before calling dependent function`;
        
        case 'timing':
            return `Front-run or sandwich ${point.function}() to exploit timing-dependent logic`;
        
        case 'callback':
            return point.ceiPattern === 'violated'
                ? `Exploit CEI violation in ${point.function}() via reentrancy during callback`
                : `Inject malicious callback into ${point.function}() external call`;
        
        case 'access_control':
            return `Call unauthorized ${point.function}() to ${point.changesState ? 'modify state' : 'drain funds'} without authentication`;
        
        default:
            return `Unknown manipulation type at ${point.function}`;
    }
}

function estimateDifficulty(point) {
    // Base difficulty on manipulation type
    const baseDifficulty = {
        'input': 'easy',
        'state': 'medium',
        'timing': 'hard',
        'callback': 'medium',
        'access_control': 'easy'
    };
    
    let difficulty = baseDifficulty[point.type] || 'medium';
    
    // Adjust based on additional factors
    if (point.entryAccess === 'anyone') {
        // Keep as-is or downgrade difficulty
    } else if (point.entryAccess === 'role-based') {
        difficulty = upgradeDifficulty(difficulty);  // Need role somehow
    }
    
    return difficulty;
}
```

---

## Output Format

```javascript
{
    plugin: 'reverse-engineering',
    runTimestamp: ISODateString,
    
    summary: {
        totalTargetsAnalyzed: number,
        totalManipulationPointsFound: number,
        byType: {
            input: number,
            state: number,
            timing: number,
            callback: number,
            access_control: number
        },
        bySeverity: {
            critical: number,
            high: number,
            medium: number
        }
    },
    
    hypotheses: [
        // Array of creative hypothesis objects (see Step 4)
    ],
    
    highValueTargets: [
        {
            asset: string,
            location: string,
            valueTier: string,
            flowsAffected: number,
            manipulationPoints: number
        }
    ]
}
```

---

## Integration Notes

### Relationship with Other Plugins

| Plugin | Interaction |
|--------|-------------|
| Pattern Matcher | Complementary: PM finds known bugs, RE finds novel ones |
| Assumption Breaker | RE finds code-level issues, AB finds assumption-level issues |
| Reachability | All RE hypotheses must pass reachability BLOCK GATE |

### When to Use

- **Always run in Phase 3** alongside Assumption Breaker
- Run BEFORE assumption breaking (find code issues first)
- Feed results into execution trace builder

### What This Plugin Misses

- Very complex multi-transaction attacks (use Assumption Breaker)
- Protocol-economic attacks like LP manipulation (need domain knowledge)
- Social engineering / governance attacks (out of scope / trusted role)

---

## v2.0 ENHANCED: Trackator Multi-Phase Integration

### Phase 1: Storage Dependency Integration (`context.storage`)

The plugin now has **weaponized intelligence** about where value lives and who can touch it:

**Enhanced Attack Surface Discovery:**

```javascript
// v2.0: Start from VALUE-BEARING variables (holds user funds!)
function findHighValueTargets_v2(context) {
    const targets = [];

    if (!context.storage?.valueBearingVariables) {
        // Fall back to legacy method
        return identifyHighValueTargets(context);  // Original algorithm
    }

    console.log('🎯 v2.0: Using Storage Dependency data for target discovery');

    for (const vbv of context.storage.valueBearingVariables) {
        const writers = context.storage.variableWriters.get(vbv.variable) || [];
        const target = {
            asset: vbv.variable,
            type: vbv.type,           // 'erc20-balance', 'collateral', 'lp-shares'
            location: vbv.location,
            valueTier: 'critical',     // These hold user funds!

            // WHO can write to this?
            writers: writers,

            permissionlessWriters: writers.filter(w =>
                w.accessControlLevel === 'none' ||
                w.accessControlLevel === 'permissionless'
            ),

            // Is it contended? (race condition target)
            isContended: context.storage.contentedVariables?.some(
                cv => cv.variable === vbv.variable && cv.writerCount >= 2
            )
        };

        targets.push(target);

        // IMMEDIATE attack vector if permissionless writer exists
        if (target.permissionlessWriters.length > 0) {
            console.log(`💀 CRITICAL: ${target.asset} has ${target.permissionlessWriters.length} permissionless writers!`);
        }
    }

    return targets.sort((a, b) => {
        // Value-bearing + contended + permissionless = highest priority
        let scoreA = 0, scoreB = 0;

        for (const t of [a, b]) {
            let score = 0;
            if (t.type === 'erc20-balance') score += 30;
            else if (t.type === 'collateral') score += 25;
            else if (t.type === 'lp-shares') score += 20;
            else if (t.type === 'governance') score += 10;
            if (t.isContended) score += 15;  // Race conditions are valuable!
            if (t.permissionlessWriters.length > 0) score += 25;  // Permissionless = exploitable!

            if (t === a) scoreA = score; else scoreB = score;
        }

        return scoreB - scoreA;
    });
}
```

**Enhanced State Manipulation Detection:**

```javascript
// v2.0: Check writer access control BEFORE tracing flow backwards
function checkStateManipulability_v2(stateVar, context) {

    // NEW: Use storage dependency data for precise writer analysis
    if (context.storage?.variableWriters?.has(stateVar)) {
        const writers = context.storage.variableWriters.get(stateVar);

        for (const writer of writers) {
            // Permissionless writer = immediately exploitable
            if (writer.accessControlLevel === 'none' ||
                writer.accessControlLevel === 'permissionless') {
                return {
                    isManipulable: true,
                    type: 'state',
                    targetVariable: stateVar,
                    vulnerableWriter: writer.function,
                    riskLevel: 'critical',  // Can directly modify user funds!
                    description: `${stateVar} can be modified by permissionless ${writer.function}()`,
                    trackatorEvidence: {
                        fieldsUsed: ['storage.variableWriters', 'storage.valueBearingVariables'],
                        writerAccessControl: writer.accessControlLevel,
                        isValueBearing: context.storage.valueBearingVariables?.some(
                            v => v.variable === stateVar
                        )
                    }
                };
            }

            // Role-based but CEI violated = potential issue
            if (writer.ceiPatternMatch && writer.accessControlLevel === 'role-based') {
                return {
                    isManipulable: true,
                    type: 'state',
                    targetVariable: stateVar,
                    vulnerableWriter: writer.function,
                    riskLevel: 'medium',  // Need role, but CEI violation
                    description: `${stateVar} writable by ${writer.function}() with CEI violation`
                };
            }
        }

        // No writers found = constant/immutable
        return { isManipulable: false };
    }

    // Fall back to original analysis
    return checkStateManipulability(stateVar, context);  // Original function
}
```

**Shared-State Matrix for Entry Prioritization:**

```javascript
// v2.0: Use shared-state matrix to prioritize entry points
function prioritizeEntryPoints_v2(context) {
    if (!context.storage?.sharedStateMatrix) {
        return context.entryPoints;  // Return original
    }

    // Score each entry point by risk (value-bearing + permissionless)
    return context.entryPoints.map(ep => ({
        ...ep,
        enhancedRisk: context.storage.sharedStateMatrix
            .filter(s => s.entryPoint === ep.name)
            .reduce((score, s) => score + (s.hasValueBearing ? 15 : 0) + (s.riskScore || 0), 0)
    })).sort((a, b) => b.enhancedRisk - a.enhancedRisk);
}
```

### Phase 2: State Coupling Integration (`context.coupling`)

When Trackator's **State Coupling Detector** data is available, the plugin can identify **atomicity violations** and **cross-function state manipulation**:

```javascript
// v2.0: Find atomicity violations using function dependency matrix
findAtomicityViolations(context) {
    if (!context.coupling?.functionDependencyMatrix) {
        return [];  // No coupling data available
    }

    const violations = [];
    const matrix = context.coupling.functionDependencyMatrix;

    // Find STRONG coupling pairs where attacker can call functions separately
    for (const [pairKey, coupling] of Object.entries(matrix)) {
        if (coupling.strength === 'STRONG' || coupling.strength > 0.7) {
            const [funcA, funcB] = pairKey.split('->');

            // Check if both functions are accessible to attacker
            const funcAAccessible = this.isFunctionAccessible(funcA, context);
            const funcBAccessible = this.isFunctionAccessible(funcB, context);

            if (funcAAccessible && funcBAccessible) {
                violations.push({
                    type: 'atomicity_violation',
                    functionPair: [funcA, funcB],
                    couplingStrength: coupling.strength,
                    sharedVariables: coupling.sharedVariables || [],
                    attackScenario: `Call ${funcA} then ${funcB} separately to exploit intermediate state`,
                    invariantRisk: this.checkInvariantImpact(funcA, funcB, context),
                    trackatorEvidence: {
                        fieldsUsed: ['coupling.functionDependencyMatrix'],
                        couplingType: coupling.couplingType,
                        hiddenAssumption: coupling.hiddenAssumption
                    }
                });
            }
        }
    }

    return violations;
}

// v2.0: Exploit hidden couplings (transient/conditional/timestamp-dependent)
findHiddenCouplingExploits(context) {
    if (!context.coupling?.hiddenCouplings) {
        return [];
    }

    return context.coupling.hiddenCouplings
        .filter(coupling => {
            // Only exploitable if attacker can trigger both sides
            return this.isFunctionAccessible(coupling.functionA, context) &&
                   this.isFunctionAccessible(coupling.functionB, context);
        })
        .map(coupling => ({
            type: 'hidden_coupling',
            couplingType: coupling.couplingType,  // 'transient' | 'conditional' | 'timestamp-dependent'
            functions: [coupling.functionA, coupling.functionB],
            strength: coupling.strength,
            sharedVariables: coupling.sharedVariables,
            exploitationPotential:
                coupling.couplingType === 'timestamp-dependent' ? 'HIGH - MEV/front-run viable' :
                coupling.couplingType === 'transient' ? 'MEDIUM - race condition possible' :
                'LOW - specific conditions required',
            attackIdea: this.generateCouplingAttack(coupling, context)
        }));
}

// v2.0: Check if breaking invariant affects dependent functions
checkInvariantImpact(funcA, funcB, context) {
    if (!context.coupling?.invariantFunctionMap) {
        return 'unknown';
    }

    const { establishes, dependsOn, canViolate } = context.coupling.invariantFunctionMap;
    const impactedInvariants = [];

    // Does funcA establish invariants that funcB depends on?
    for (const [invId, establishers] of Object.entries(establishes || {})) {
        if (establishers.includes(funcA) && (dependsOn[invId] || []).includes(funcB)) {
            impactedInvariants.push(invId);
        }
    }

    // Can funcA violate invariants that funcB assumes hold?
    for (const [invId, violators] of Object.entries(canViolate || {})) {
        if (violators.includes(funcA) && (dependsOn[invId] || []).includes(funcB)) {
            impactedInvariants.push({ invariant: invId, risk: 'violation_possible' });
        }
    }

    return impactedInvariants.length > 0 ? { impactedInvariants, risk: 'HIGH' } : 'LOW';
}
```

### Phase 3: Sync Analyzer Integration (`context.sync`)

When Trackator's **Sync Analyzer** data is available, the plugin can identify **timing attacks**, **stale data exploitation**, and **race windows**:

```javascript
// v2.0: Find stale data exploits using desynchronization analysis
findStaleDataExploits(context) {
    if (!context.sync?.desynchronizationAnalysis) {
        return [];
    }

    const { staleDataDetections, driftAnalysis, missingVerifiers, raceWindows } =
        context.sync.desynchronizationAnalysis;

    const exploits = [];

    // Stale price/oracle data
    for (const stale of (staleDataDetections || [])) {
        exploits.push({
            type: 'stale_data_exploit',
            variable: stale.variable,
            validWindow: stale.validWindow,
            expiryCondition: stale.expiryCondition,
            attackScenario: `Manipulate ${stale.variable} within valid window before expiry`,
            prerequisiteChain: [
                `Attacker can influence ${stale.variable}`,
                `Valid window (${stale.validWindow}ms) provides exploitation time`,
                `Consumer function reads stale value before refresh`
            ],
            estimatedDifficulty: stale.validWindow > 30000 ? 'easy' : 'medium',
            trackatorEvidence: {
                fieldsUsed: ['sync.desynchronizationAnalysis.staleDataDetections']
            }
        });
    }

    // Missing verifiers = unverified assumptions
    for (const missing of (missingVerifiers || [])) {
        exploits.push({
            type: 'unverified_assumption',
            assumptionId: missing.assumptionId,
            consumerFunctions: missing.consumerFunctions,
            attackScenario: `Exploit unverified assumption ${missing.assumptionId} in ${missing.consumerFunctions.join(', ')}`,
            riskLevel: 'HIGH',
            trackatorEvidence: {
                fieldsUsed: ['sync.desynchronizationAnalysis.missingVerifiers']
            }
        });
    }

    // Race windows
    for (const race of (raceWindows || [])) {
        exploits.push({
            type: 'race_window_exploitation',
            windowMs: race.windowMs,
            exploitPrerequisite: race.exploitPrerequisite,
            feasibility: race.windowMs > 12000 ? 'easy' : race.windowMs > 3000 ? 'medium' : 'hard',
            attackScenario: `Execute attack within ${race.windowMs}ms race window`
        });
    }

    return exploits;
}

// v2.0: Use critical desync risks for high-priority targeting
prioritizeByDesyncRisk(context) {
    if (!context.sync?.criticalDesyncRisks) {
        return [];  // No sync data
    }

    return context.sync.criticalDesyncRisks
        .filter(risk => risk.severity === 'critical' || risk.severity === 'high')
        .map(risk => ({
            priorityTarget: true,
            riskType: risk.riskType,
            severity: risk.severity,
            impact: risk.impact,
            attackScenario: risk.attackScenario,
            producerFunction: risk.producerFunction,
            consumerFunction: risk.consumerFunction,
            staleWindowMs: risk.staleWindowMs,
            exploitationFeasibility:
                risk.staleWindowMs > 60000 ? 'very_high' :
                risk.staleWindowMs > 10000 ? 'high' : 'medium',
            trackatorEvidence: {
                fieldsUsed: ['sync.criticalDesyncRisks']
            }
        }));
}

// v2.0: Build attack chains using assumption dependency graph
buildSyncAttackChains(context) {
    if (!context.sync?.assumptionDependencyGraph) {
        return [];
    }

    const { producers, consumers, verifiers } = context.sync.assumptionDependencyGraph;
    const chains = [];

    // Find assumptions produced but never verified
    for (const prod of (producers || [])) {
        const hasVerifier = (verifiers || []).some(v => v.assumptionId === prod.assumptionId);

        if (!hasVerifier) {
            // This assumption is produced but NEVER verified = potential exploit
            const assumptionConsumers = (consumers || [])
                .filter(c => c.assumptionId === prod.assumptionId);

            chains.push({
                type: 'unverified_assumption_chain',
                assumptionId: prod.assumptionId,
                producerFunction: prod.function,
                stalenessWindow: prod.stalenessWindow,
                consumerFunctions: assumptionConsumers.map(c => c.function),
                validationGaps: assumptionConsumers.map(c => c.validationGap),
                attackChain: [
                    `1. Trigger ${prod.function} to produce assumption ${prod.assumptionId}`,
                    `2. Wait within staleness window (${prod.stalenessWindow}ms)`,
                    `3. Call consumer function(s) before assumption is re-verified`,
                    `4. Consumer operates on stale/invalid assumption`
                ],
                exploitability: this.assessExploitability(prod, assumptionConsumers)
            });
        }
    }

    return chains;
}
```

### Enhanced Output Format (v2.0)

When any enhanced data is available, hypotheses include additional evidence:

```javascript
{
    // ... original fields ...

    // v2.0: Enhanced evidence fields
    storageEvidence: {
        valueBearingTarget: boolean,
        permissionlessWriterExists: boolean,
        contendedVariable: boolean,
        sharedStateRiskScore: number
    },
    couplingVectors: [{
        functionPair: [string, string],
        couplingType: string,
        atomicityViolation: boolean,
        invariantImpact: string
    }],
    syncVulnerabilities: [{
        riskType: 'stale-price' | 'stale-approval' | 'state-drift' | 'missing-verifier' | 'race-window',
        severity: string,
        staleWindowMs: number,
        attackScenario: string
    }],
    trackatorPhasesUsed: ['storage', 'coupling', 'sync']  // Which phases contributed
}
```

---

## Example Output

### Input Context
```
Assets at Risk:
- _balances (ERC20) in StakingRewards [CRITICAL]
- _totalSupply (shares) in Vault [HIGH]

Money Flows:
- Deposit: stake() → _balances[user] += amount
- Reward: getReward() → earned() calculation → transfer
```

### Generated Hypotheses

```javascript
{
    id: "CREATIVE_01",
    type: "reverse_engineering",
    targetType: "state",
    targetAsset: "_balances (rewards)",
    entryPoint: "notifyRewardAmount",
    manipulationPoint: "rewardPerTokenStored can be manipulated before stake()",
    attackIdea: "Call notifyRewardAmount() with inflated amount before staking to spike rewardPerTokenStored, then claim inflated rewards",
    prerequisiteChain: [
        "notifyRewardAmount() accessible to attacker OR manipulable",
        "rewardPerTokenStorage update visible to earned() calculation",
        "No checkpoint/rebase that would dilute the inflation"
    ],
    estimatedDifficulty: "medium",
    status: "HYPOTHESIS"
}

{
    id: "CREATIVE_02", 
    type: "reverse_engineering",
    targetType: "callback",
    targetAsset: "_balances (user)",
    entryPoint: "transferInRewards",
    manipulationPoint: "CEI violation: external call before state update",
    attackIdea: "Reenter during reward transfer to claim rewards multiple times before balance updates",
    prerequisiteChain: [
        "transferInRewards() performs external ERC20 transfer",
        "Balance update happens AFTER transfer (CEI violated)",
        "No nonReentrant guard on function",
        "Attacker can influence callback target"
    ],
    estimatedDifficulty: "medium",
    status: "HYPOTHESIS"
}
```

---

## Anti-Patterns (Avoid These)

❌ "This function looks complex" (without identifying specific manipulation point)
❌ "Value flow exists" (without tracing backwards to attacker-controlled input)
❌ "Similar to X exploit" (that's Pattern Matcher's job)
❌ Assuming admin/malicious insider scenarios

✅ Clear manipulation point with specific function/variable
✅ Concrete prerequisite chain from Trackator data
✅ Novel attack idea not covered by historical patterns
✅ Realistic attacker capabilities only
