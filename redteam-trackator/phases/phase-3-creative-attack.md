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




### Plugin: Root Cause Hypothesizer (NEW - v2.2 Upgrade)

**Purpose**: Perform **multi-layer causal analysis** on attack chains and creative hypotheses to identify WHY vulnerabilities exist at code, design, and fundamental levels — not just WHAT they are.

**Phase**: 3c (Creative Attack Enhancement)

**Core Philosophy**: *"Finding the bug tells you what's broken. Finding the root cause tells you why it can break again."*

**Key Files**:
- Plugin spec: `plugins/root-cause-hypothesizer.md`
- Catalog: `Exploits-class-library/root-cause-catalog.json`
- Source data: `Exploits-class-library/exploit-pattern-cards/*.md` (Root Cause + "What Audit Missed" sections)

**What It Does**:

1. **4-Layer Causal Analysis** for every hypothesis/chain:
   - **Layer 1 (Surface)**: Exploit pattern, attack steps (from Phase 2)
   - **Layer 2 (Code)**: Exact flaw location, mechanism, missing mitigation
   - **Layer 3 (Design)**: Violated assumptions, missing invariants, design gaps
   - **Layer 4 (Fundamental)**: Enabling factors, systemic issues, recurrence probability

2. **Integrates "What Audit Missed"** from historical exploit cards to predict blind spots

3. **Generates remediation guidance** at multiple levels (immediate → code → design → fundamental)

**The 4 Analysis Layers**:

```
LAYER 1: SURFACE (What)           → "Attacker does X, then Y, then Z"
LAYER 2: CODE (Where Exactly)      → "Function F at line L missing guard G"  
LAYER 3: DESIGN (Why Written This) → "Developer assumed P, but P doesn't hold under C"
LAYER 4: FUNDAMENTAL (Why Allowed) → "Complexity hazard / integration risk / economic misalignment"
```

**Root Cause Classification Taxonomy** (from `root-cause-catalog.json`):

| Category | Examples | Frequency |
|----------|----------|-----------|
| **Ordering Flaws** | CEI violation, state update order | 34% of exploits |
| **Access Control Flaws** | Missing auth, auth bypass | 36% of exploits |
| **Validation Flaws** | Missing input validation, oracle trust | 33% of exploits |
| **Logic Errors** | Incorrect calculation, race condition | 19% of exploits |

**Design Gap Types**:
- Single Point of Failure
- Missing Defense in Depth
- Trust Boundary Violation
- State Model Incorrectness
- Economic Misalignment

**Audit Blind Spot Integration**:

Leverages historical "What Audit Missed" sections from 65+ exploit cards:

| Blind Spot | Frequency | Example |
|------------|-----------|---------|
| Parameter Trust | 28% | Attacker-supplied address assumed trusted |
| Modifier Scope | 22% | nonReentrant on entry but not callback path |
| Oracle Assumptions | 18% | Spot price assumed = fair price |
| Integration Gaps | 15% | Cross-contract behavior assumed standard |

**Output Enhancement**:

Every hypothesis from Phase 3 now includes `rootCauseAnalysis`:

```javascript
hypothesis.rootCauseAnalysis = {
    code: { primaryFlaw: { type, location, mechanism } },
    design: { violatedAssumptions[], missingInvariants[], designGap },
    fundamental: { enablingFactor, systemicIssue, recurrenceProbability },
    auditBlindSpots: [{ category, description, specificCheck }],
    remediation: { immediate[], code[], design[], fundamental[] }
};
```

See `plugins/root-cause-hypothesizer.md` for complete algorithm specification.

### Phase 3 Output (v2.2 ENHANCED)

```javascript
hypothesis.status = 'TESTED';
hypothesis.creativeFindings = [/* reverse engineering results */];
hypothesis.assumptionBreaks = [/* assumption breaker results */];
hypothesis.couplingAttacks = [/* v2.1: ENHANCED state coupling analysis results */];
hypothesis.desyncAttacks = [/* v2.0: sync analyzer attack results */];
hypothesis.executionTrace = { /* full trace object */ };
hypothesis.traceConclusion = { survives: boolean, reason: string };

// ═══════════════════════════════════════════════════════════════
// v2.2 NEW: Root Cause Analysis (from Root Cause Hypothesizer)
// ═══════════════════════════════════════════════════════════════
hypothesis.rootCauseAnalysis = {
    // Layer 2: Code-Level (exact flaw location)
    code: {
        primaryFlaw: {
            type: 'ORACLE_TRUST_ASSUMPTION_VIOLATION' | 'CEI_VIOLATION' | 'MISSING_ACCESS_CONTROL' | ...,
            name: string,
            description: string,
            location: { contract: string, function: string, lineRange: [number, number] },
            mechanism: string  // HOW the flaw enables exploitation
        },
        secondaryFlaws: [...],
        missingMitigation: { type: string, recommendation: string, urgency: 'critical' | 'high' | 'medium' }
    },
    
    // Layer 3: Design-Level (why code was written this way)
    design: {
        violatedAssumptions: [{
            type: 'ORACLE_HONESTY' | 'TX_ATOMICITY' | 'CALLER_BENIGNANCE' | ...,
            text: string,
            violatedBy: string,
            severity: 'critical' | 'high' | 'medium',
            whyUnverified: string
        }],
        missingInvariants: [{ invariant: string, status: 'violatable', how: string }],
        designGap: {
            type: 'SINGLE_POINT_OF_FAILURE' | 'MISSING_DEFENSE_IN_DEPTH' | 'TRUST_BOUNDARY_VIOLATION' | ...,
            name: string,
            description: string
        }
    },
    
    // Layer 4: Fundamental (systemic enabling factor)
    fundamental: {
        enablingFactor: {
            type: 'INHERITANCE_COMPOSITION' | 'PROXY_UPGRADE_PATTERN' | 'CROSS_PROTOCOL_INTEGRATION' | ...,
            name: string,
            description: string
        },
        systemicIssue: { class: string, description: string },
        recurrenceProbability: 'high' | 'medium' | 'low',
        protocolClassIndicator: string
    },
    
    // Cross-cutting: What would a typical audit miss?
    auditBlindSpots: [{
        category: 'PARAMETER_TRUST' | 'MODIFIER_SCOPE' | 'ORACLE_ASSUMPTIONS' | ...,
        description: string,
        specificCheck: string,
        relevance: 'critical' | 'high' | 'medium'
    }],
    
    // Remediation guidance (root cause aligned, not just symptom patch)
    remediation: {
        immediate: string[],      // Stop the bleeding NOW
        code: string[],           // Fix the specific code flaw
        design: string[],         // Fix the design gap
        fundamental: string[]     // Prevent class of bugs
    },
    
    // Summary metrics
    summary: {
        totalLayersAnalyzed: 4,
        rootCauseConfidence: 'high' | 'medium' | 'low',
        fixComplexity: 'easy' | 'medium' | 'hard',
        regressionRisk: 'low' | 'medium' | 'high',
        priorityScore: number  // 0-1 composite severity/importance
    }
};

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

