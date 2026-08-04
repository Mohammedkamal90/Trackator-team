"use strict";
// ============================================================
// TRACKATOR Phase 2 Enhancement - State Coupling Detector
// Implements Prompt 2 requirements:
// - Function × Function Dependency Matrix (via shared storage)
// - Hidden State Couplings Detection
// - Invariant → Function Mapping (establishes/depends/violates)
// - Storage Variable Classification
// - Top N Highest-Value State Intersections
// - Hidden Assumptions Across Execution Paths
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeStateCouplings = analyzeStateCouplings;
exports.exportStateCouplingResult = exportStateCouplingResult;
exports.generateStateCouplingMarkdown = generateStateCouplingMarkdown;
exports.generateWeaponizedAttacks = generateWeaponizedAttacks;
exports.getCriticalAttacks = getCriticalAttacks;
exports.getQuickWinAttacks = getQuickWinAttacks;
exports.exportWeaponizedResults = exportWeaponizedResults;
/**
 * Main entry point for State Coupling Analysis
 * Implements comprehensive Prompt 2 requirements
 */
function analyzeStateCouplings(options) {
    const { contracts, functionRegistry, callEdges = [], invariants = [], verbose = false } = options;
    if (verbose)
        console.log('[StateCouplingAnalyzer] Starting comprehensive state coupling analysis...');
    // Step 1: Build Function Dependency Matrix
    const functionDependencyMatrix = buildFunctionDependencyMatrix(contracts, functionRegistry, callEdges, verbose);
    // Step 2: Detect Hidden Couplings
    const hiddenCouplings = detectHiddenCouplings(contracts, functionRegistry, callEdges, verbose);
    // Step 3: Build Invariant → Function Mapping
    const invariantFunctionMap = buildInvariantFunctionMapping(contracts, functionRegistry, invariants, verbose);
    // Step 4: Classify Variables
    const variableClassification = classifyVariables(contracts, functionRegistry, invariants, verbose);
    // Step 5: Compute Top N Intersections
    const topStateIntersections = computeTopIntersections(functionDependencyMatrix, variableClassification, contracts, 20, // Top 20 as per prompt requirement
    verbose);
    // Step 6: Identify Hidden Assumptions
    const hiddenAssumptions = identifyHiddenAssumptions(contracts, functionRegistry, invariants, callEdges, verbose);
    // Step 7: Compile critical findings
    const criticalFindings = compileCriticalFindings(functionDependencyMatrix, hiddenCouplings, invariantFunctionMap, variableClassification, topStateIntersections, hiddenAssumptions, verbose);
    return {
        timestamp: new Date().toISOString(),
        functionDependencyMatrix,
        hiddenCouplings,
        invariantFunctionMap,
        variableClassification,
        topStateIntersections,
        hiddenAssumptions,
        criticalFindings
    };
}
// ============================================================
// STEP 1: FUNCTION DEPENDENCY MATRIX BUILDER
// ============================================================
function buildFunctionDependencyMatrix(contracts, functionRegistry, callEdges = [], verbose = false) {
    if (verbose)
        console.log('[StateCouplingAnalyzer] Building function dependency matrix...');
    const functions = [];
    const dependencies = new Map();
    // Build function list with their state access info
    for (const contract of contracts) {
        for (const func of contract.functions) {
            const registeredFunc = findRegFunc(functionRegistry, contract.name, func.name);
            functions.push({
                id: `${contract.name}.${func.name}`,
                contract: contract.name,
                name: func.name,
                signature: `${contract.name}.${func.name}`,
                visibility: func.visibility,
                accessControl: registeredFunc?.accessControl.level || inferAccessControl(func),
                isPermissionless: isPermFunc(func, registeredFunc),
                stateVariablesRead: func.stateVariablesRead || [],
                stateVariablesWritten: func.stateVariablesWritten || [],
                inDegree: 0,
                outDegree: 0,
                couplingScore: 0,
                riskLevel: 'safe'
            });
        }
    }
    // Build dependency matrix based on shared state variables
    for (let i = 0; i < functions.length; i++) {
        const funcA = functions[i];
        for (let j = 0; j < functions.length; j++) {
            if (i === j)
                continue;
            const funcB = functions[j];
            const depKey = `${funcA.id}→${funcB.id}`;
            // Check for write-read dependency (A writes what B reads)
            const writtenByA_readByB = funcA.stateVariablesWritten.filter(v => funcB.stateVariablesRead.includes(v));
            // Check for read-write dependency (A reads what B writes)  
            const readByA_writtenByB = funcA.stateVariablesRead.filter(v => funcB.stateVariablesWritten.includes(v));
            // Check for write-write dependency (both write same var)
            const bothWrite = funcA.stateVariablesWritten.filter(v => funcB.stateVariablesWritten.includes(v));
            // Determine dependency type and strength
            let depType = 'shared-state';
            let sharedVars = [];
            if (writtenByA_readByB.length > 0) {
                depType = 'write-read';
                sharedVars = writtenByA_readByB;
            }
            else if (readByA_writtenByB.length > 0) {
                depType = 'read-write';
                sharedVars = readByA_writtenByB;
            }
            else if (bothWrite.length > 0) {
                depType = 'write-write';
                sharedVars = bothWrite;
            }
            if (sharedVars.length > 0) {
                const isCrossContract = funcA.contract !== funcB.contract;
                // Calculate coupling strength
                const strength = calculateCouplingStrength(sharedVars, funcA, funcB, isCrossContract);
                // Determine risk factors
                const riskFactors = assessDependencyRisk(depType, sharedVars, funcA, funcB, isCrossContract);
                // Check if there's also a direct call relationship
                const hasDirectCall = callEdges.some(e => e.from.contract === funcA.contract &&
                    e.from.function === funcA.name &&
                    e.to.contract === funcB.contract &&
                    e.to.function === funcB.name);
                dependencies.set(depKey, {
                    sourceFunction: funcA.id,
                    targetFunction: funcB.id,
                    dependencyType: depType,
                    sharedVariables: sharedVars,
                    couplingStrength: strength,
                    isDirect: hasDirectCall,
                    isCrossContract,
                    description: generateDependencyDescription(depType, funcA, funcB, sharedVars),
                    riskFactors
                });
                // Update degrees
                funcA.outDegree++;
                funcB.inDegree++;
            }
        }
    }
    // Calculate coupling scores and risk levels
    for (const func of functions) {
        func.couplingScore = calculateFunctionCouplingScore(func, dependencies);
        func.riskLevel = assessFunctionRiskLevel(func);
    }
    // Find coupling clusters
    const couplingClusters = findCouplingClusters(functions, dependencies);
    // Compute statistics
    const stats = computeMatrixStatistics(functions, dependencies);
    if (verbose) {
        console.log(`[StateCouplingAnalyzer] Matrix built: ${functions.length} functions, ${dependencies.size} dependencies`);
    }
    return {
        functions,
        dependencies,
        statistics: stats,
        couplingClusters
    };
}
function calculateCouplingStrength(sharedVars, funcA, funcB, isCrossContract) {
    let strength = 0;
    // Base strength from number of shared variables
    strength += Math.min(sharedVars.length * 15, 45);
    // Value-bearing variables increase strength
    const valueBearingCount = sharedVars.filter(v => /balance|supply|debt|collateral|reserve|liquidity|funds/i.test(v)).length;
    strength += valueBearingCount * 10;
    // Permissionless functions increase risk
    if (funcA.isPermissionless)
        strength += 10;
    if (funcB.isPermissionless)
        strength += 10;
    // Cross-contract adds complexity
    if (isCrossContract)
        strength += 15;
    // Write-read is more significant than read-write
    // (already captured in base calculation)
    return Math.min(strength, 100);
}
function assessDependencyRisk(depType, sharedVars, funcA, funcB, isCrossContract) {
    const risks = [];
    // Type-based risks
    switch (depType) {
        case 'write-read':
            risks.push('stale-read-risk');
            if (funcA.isPermissionless)
                risks.push('permissionless-writer');
            break;
        case 'write-write':
            risks.push('race-condition-risk');
            risks.push('ordering-dependency');
            break;
        case 'read-write':
            risks.push('time-of-check-time-of-use');
            break;
    }
    // Variable-based risks
    for (const v of sharedVars) {
        if (/balance|supply|debt/i.test(v))
            risks.push('value-bearing-variable');
        if (/price|oracle|rate/i.test(v))
            risks.push('price-dependency');
        if (/owner|admin|role/i.test(v))
            risks.push('authorization-variable');
    }
    // Structural risks
    if (isCrossContract)
        risks.push('cross-contract-dependency');
    if (funcA.isPermissionless && funcB.isPermissionless) {
        risks.push('double-permissionless');
    }
    return risks;
}
function generateDependencyDescription(depType, funcA, funcB, sharedVars) {
    const varList = sharedVars.length <= 3
        ? sharedVars.join(', ')
        : `${sharedVars.slice(0, 3).join(', ...')} +${sharedVars.length - 3} more`;
    switch (depType) {
        case 'write-read':
            return `${funcA.name} writes [${varList}] which ${funcB.name} subsequently reads`;
        case 'read-write':
            return `${funcA.name} reads [${varList}] which ${funcB.name} subsequently modifies`;
        case 'write-write':
            return `Both ${funcA.name} and ${funcB.name} write to [${varList}] - potential conflict`;
        default:
            return `${funcA.name} and ${funcB.name} share state via [${varList}]`;
    }
}
function calculateFunctionCouplingScore(func, dependencies) {
    let score = 0;
    // Count outgoing dependencies
    for (const [key, dep] of dependencies) {
        if (key.startsWith(func.id + '→')) {
            score += dep.couplingStrength * 0.3;
        }
        if (key.endsWith('→' + func.id)) {
            score += dep.couplingStrength * 0.7; // Incoming deps are more concerning
        }
    }
    // Normalize to 0-100
    return Math.min(Math.round(score), 100);
}
function assessFunctionRiskLevel(func) {
    if (func.couplingScore >= 80 && func.isPermissionless)
        return 'critical';
    if (func.couplingScore >= 70 || (func.couplingScore >= 50 && func.isPermissionless))
        return 'high';
    if (func.couplingScore >= 40)
        return 'medium';
    if (func.couplingScore >= 20)
        return 'low';
    return 'safe';
}
function findCouplingClusters(functions, dependencies) {
    const clusters = [];
    const visited = new Set();
    let clusterId = 0;
    for (const func of functions) {
        if (visited.has(func.id))
            continue;
        // BFS to find all strongly connected functions
        const clusterFunctions = [];
        const clusterVars = new Set();
        const queue = [func.id];
        while (queue.length > 0) {
            const current = queue.shift();
            if (visited.has(current))
                continue;
            visited.add(current);
            clusterFunctions.push(current);
            // Find all functions with strong coupling to current
            for (const [key, dep] of dependencies) {
                if ((key.startsWith(current + '→') || key.endsWith('→' + current)) &&
                    dep.couplingStrength >= 40) {
                    const other = key.startsWith(current + '→')
                        ? dep.targetFunction
                        : dep.sourceFunction;
                    if (!visited.has(other)) {
                        queue.push(other);
                    }
                    // Collect shared variables
                    dep.sharedVariables.forEach(v => clusterVars.add(v));
                }
            }
        }
        // Only create cluster if multiple functions involved
        if (clusterFunctions.length >= 2) {
            const clusterFuncs = clusterFunctions.map(id => functions.find(f => f.id === id)).filter(Boolean);
            const avgCoupling = clusterFuncs.reduce((sum, f) => sum + f.couplingScore, 0) / clusterFuncs.length;
            const hasPerm = clusterFuncs.some(f => f.isPermissionless);
            clusters.push({
                clusterId: `CLUSTER_${++clusterId}`,
                functions: clusterFunctions,
                sharedVariables: Array.from(clusterVars),
                cohesionScore: Math.round(avgCoupling),
                riskLevel: avgCoupling >= 70 ? (hasPerm ? 'critical' : 'high') :
                    avgCoupling >= 50 ? 'medium' : 'low',
                description: `${clusterFunctions.length} functions tightly coupled through ${clusterVars.size} shared variables`
            });
        }
    }
    // Sort by risk
    clusters.sort((a, b) => {
        const order = { critical: 4, high: 3, medium: 2, low: 1 };
        return order[b.riskLevel] - order[a.riskLevel];
    });
    return clusters;
}
function computeMatrixStatistics(functions, dependencies) {
    let maxInDegree = 0;
    let maxOutDegree = 0;
    let stronglyCoupled = 0;
    let crossContract = 0;
    let cyclic = 0;
    for (const func of functions) {
        maxInDegree = Math.max(maxInDegree, func.inDegree);
        maxOutDegree = Math.max(maxOutDegree, func.outDegree);
    }
    for (const [, dep] of dependencies) {
        if (dep.sharedVariables.length > 3)
            stronglyCoupled++;
        if (dep.isCrossContract)
            crossContract++;
        // Simple cycle detection (A→B and B→A)
        const reverseKey = `${dep.targetFunction}→${dep.sourceFunction}`;
        if (dependencies.has(reverseKey))
            cyclic++;
    }
    // Cyclic pairs counted twice, so divide
    cyclic = Math.floor(cyclic / 2);
    return {
        totalFunctions: functions.length,
        totalDependencies: dependencies.size,
        averageDependenciesPerFunction: dependencies.size / Math.max(functions.length, 1),
        maxInDegree,
        maxOutDegree,
        stronglyCoupledPairs: stronglyCoupled,
        crossContractDependencies: crossContract,
        cyclicDependencies: cyclic
    };
}
// ============================================================
// STEP 2: HIDDEN COUPLING DETECTOR
// ============================================================
function detectHiddenCouplings(contracts, functionRegistry, callEdges = [], verbose = false) {
    if (verbose)
        console.log('[StateCouplingAnalyzer] Detecting hidden couplings...');
    const couplings = [];
    const byCategory = new Map();
    let couplingId = 0;
    // 1. Detect inheritance storage overlap
    for (const contract of contracts) {
        if (contract.inherited && contract.inherited.length > 0) {
            for (const parentName of contract.inherited) {
                const parent = contracts.find(c => c.name === parentName);
                if (parent) {
                    // Check for overlapping state variable patterns
                    const childVars = contract.stateVariables.map(v => v.name.toLowerCase());
                    const parentVars = parent.stateVariables.map(v => v.name.toLowerCase());
                    // Look for shadowing or similar names
                    for (const childVar of contract.stateVariables) {
                        const matchingParent = parent.stateVariables.find(pv => pv.name.toLowerCase() === childVar.name.toLowerCase() ||
                            childVar.name.toLowerCase().includes(pv.name.toLowerCase()) ||
                            pv.name.toLowerCase().includes(childVar.name.toLowerCase()));
                        if (matchingParent) {
                            const coupling = {
                                id: `HC_${++couplingId}`,
                                type: 'inheritance-storage-overlap',
                                severity: 'high',
                                source: { contract: contract.name },
                                target: { contract: parentName, variable: matchingParent.name },
                                mechanism: 'Child contract may shadow or overlap parent storage',
                                sharedState: [childVar.name, matchingParent.name],
                                description: `Variable ${childVar.name} in ${contract.name} may overlap with ${matchingParent.name} in parent ${parentName}`,
                                recommendation: 'Ensure explicit slot assignments or rename to avoid ambiguity',
                                detectionConfidence: 'likely'
                            };
                            couplings.push(coupling);
                            categorizeCoupling(byCategory, coupling);
                        }
                    }
                }
            }
        }
    }
    // 2. Detect delegatecall context leaks
    for (const edge of callEdges) {
        if (edge.type === 'delegatecall') {
            const coupling = {
                id: `HC_${++couplingId}`,
                type: 'delegatecall-context-leak',
                severity: 'critical',
                source: { contract: edge.from.contract, function: edge.from.function },
                target: { contract: edge.to.contract, function: edge.to.function },
                mechanism: 'Delegatecall exposes full storage context to target',
                description: `${edge.from.function} uses delegatecall to ${edge.to.function}, giving target full storage access`,
                exploitationScenario: 'Malicious delegatecall target can read/write all storage variables',
                recommendation: 'Ensure delegatecall target is immutable, verified, and trusted',
                detectionConfidence: 'certain'
            };
            couplings.push(coupling);
            categorizeCoupling(byCategory, coupling);
        }
    }
    // 3. Detect cross-contract assumed state
    for (const contract of contracts) {
        for (const func of contract.functions) {
            // Look for patterns where function reads state then calls external
            const readsLocalThenCallsExternal = (func.stateVariablesRead?.length > 0) &&
                (func.body?.hasExternalCall);
            if (readsLocalThenCallsExternal) {
                // Find the external calls
                const externalCalls = func.calls?.filter(call => {
                    const dotIndex = call.lastIndexOf('.');
                    if (dotIndex > 0) {
                        const potentialContract = call.substring(0, dotIndex);
                        return !contracts.some(c => c.name === potentialContract);
                    }
                    return false;
                }) || [];
                for (const extCall of externalCalls) {
                    const coupling = {
                        id: `HC_${++couplingId}`,
                        type: 'cross-contract-assumed-state',
                        severity: 'medium',
                        source: { contract: contract.name, function: func.name },
                        target: { contract: extCall.split('.')[0] || 'external' },
                        mechanism: 'Local state read before external call creates assumption window',
                        sharedState: func.stateVariablesRead,
                        description: `${func.name} reads local state [${func.stateVariablesRead?.join(', ')}] before calling external ${extCall}`,
                        exploitationScenario: 'External call can execute while holding stale local state assumptions',
                        recommendation: 'Consider CEI pattern or reentrancy guards',
                        detectionConfidence: 'possible'
                    };
                    couplings.push(coupling);
                    categorizeCoupling(byCategory, coupling);
                }
            }
        }
    }
    // 4. Detect callback state dependence
    for (const contract of contracts) {
        for (const func of contract.functions) {
            // Look for callback patterns
            const hasCallbackPattern = /callback|onReceive|handle|_hook/i.test(func.name) ||
                func.calls?.some(c => /callback|receive|hook/i.test(c));
            if (hasCallbackPattern && func.stateVariablesRead?.length > 0) {
                const coupling = {
                    id: `HC_${++couplingId}`,
                    type: 'callback-state-dependence',
                    severity: 'high',
                    source: { contract: contract.name, function: func.name },
                    target: { contract: 'external', function: 'caller' },
                    mechanism: 'Callback/hook function depends on caller-managed state',
                    sharedState: func.stateVariablesRead,
                    description: `${func.name} appears to be a callback that reads state assuming pre-callback consistency`,
                    exploitationScenario: 'Caller can manipulate state before callback executes, violating assumptions',
                    recommendation: 'Re-validate all state invariants at start of callback execution',
                    detectionConfidence: 'likely'
                };
                couplings.push(coupling);
                categorizeCoupling(byCategory, coupling);
            }
        }
    }
    // 5. Detect multi-contract consistency requirements
    const stateVarsByContract = new Map();
    for (const contract of contracts) {
        const vars = new Set(contract.stateVariables.map(v => v.name));
        stateVarsByContract.set(contract.name, vars);
    }
    // Look for similar variable names across contracts (potential sync requirement)
    const contractNames = Array.from(stateVarsByContract.keys());
    for (let i = 0; i < contractNames.length; i++) {
        for (let j = i + 1; j < contractNames.length; j++) {
            const contractA = contractNames[i];
            const contractB = contractNames[j];
            const varsA = stateVarsByContract.get(contractA);
            const varsB = stateVarsByContract.get(contractB);
            const commonPatterns = Array.from(varsA).filter(va => Array.from(varsB).some(vb => va.toLowerCase() === vb.toLowerCase() ||
                (va.includes('totalSupply') && vb.includes('totalSupply')) ||
                (va.includes('balance') && vb.includes('balance'))));
            if (commonPatterns.length > 0) {
                const coupling = {
                    id: `HC_${++couplingId}`,
                    type: 'multi-contract-consistency',
                    severity: commonPatterns.some(p => /supply|balance|debt/i.test(p)) ? 'high' : 'medium',
                    source: { contract: contractA },
                    target: { contract: contractB },
                    mechanism: 'Multiple contracts appear to track related state',
                    sharedState: commonPatterns,
                    description: `${contractA} and ${contractB} both have variables: [${commonPatterns.join(', ')}]`,
                    exploitationScenario: 'Desynchronization between contracts can lead to inconsistent state',
                    recommendation: 'Implement explicit synchronization or single-source-of-truth pattern',
                    detectionConfidence: 'possible'
                };
                couplings.push(coupling);
                categorizeCoupling(byCategory, coupling);
            }
        }
    }
    // Compute summary
    const byType = {};
    for (const c of couplings) {
        byType[c.type] = (byType[c.type] || 0) + 1;
    }
    const mostAffected = couplings.reduce((max, c) => {
        const count = couplings.filter(cc => cc.source.contract === c.source.contract).length;
        const maxCount = couplings.filter(cc => cc.source.contract === max.source.contract).length;
        return count > maxCount ? c : max;
    }, couplings[0] || { source: { contract: 'none' } });
    const summary = {
        totalHiddenCouplings: couplings.length,
        criticalCount: couplings.filter(c => c.severity === 'critical').length,
        highCount: couplings.filter(c => c.severity === 'high').length,
        byType,
        mostAffectedContract: mostAffected.source.contract
    };
    if (verbose) {
        console.log(`[StateCouplingAnalyzer] Found ${couplings.length} hidden couplings (${summary.criticalCount} critical, ${summary.highCount} high)`);
    }
    return { couplings, summary, byCategory };
}
function categorizeCoupling(byCategory, coupling) {
    const existing = byCategory.get(coupling.type) || [];
    existing.push(coupling);
    byCategory.set(coupling.type, existing);
}
// ============================================================
// STEP 3: INVARIANT FUNCTION MAPPER
// ============================================================
function buildInvariantFunctionMapping(contracts, functionRegistry, invariants = [], verbose = false) {
    if (verbose)
        console.log('[StateCouplingAnalyzer] Building invariant-function mapping...');
    const mappings = [];
    const violationPaths = [];
    const protectionGaps = [];
    // Process each invariant
    for (const inv of invariants) {
        const entry = {
            invariantId: inv.id,
            invariantCategory: inv.category,
            expression: inv.expression,
            establishers: [],
            dependers: [],
            modifiers: [],
            potentialViolators: [],
            completeness: 'unknown'
        };
        // Find functions related to this invariant's state variables
        for (const contract of contracts) {
            for (const func of contract.functions) {
                const funcWrites = func.stateVariablesWritten || [];
                const funcReads = func.stateVariablesRead || [];
                const registeredFunc = findRegFunc(functionRegistry, contract.name, func.name);
                // Check if function touches invariant's variables
                const writesInvVar = inv.relatedStateVars?.some(v => funcWrites.includes(v));
                const readsInvVar = inv.relatedStateVars?.some(v => funcReads.includes(v));
                if (!writesInvVar && !readsInvVar)
                    continue;
                const funcRole = {
                    functionId: `${contract.name}.${func.name}`,
                    role: 'depender', // Default
                    mechanism: '',
                    confidence: 'inferred',
                    lineLocation: func.lineStart
                };
                // Determine role
                if (writesInvVar && readsInvVar) {
                    // Function both establishes and checks - likely an establisher
                    funcRole.role = 'establisher';
                    funcRole.mechanism = `Writes and reads invariant variables [${inv.relatedStateVars?.filter(v => funcWrites.includes(v)).join(', ')}]`;
                    entry.establishers.push(funcRole);
                }
                else if (writesInvVar) {
                    // Could be modifier or violator depending on pattern
                    const isSafePattern = /update|sync|adjust|reconcile|settle|deposit|withdraw/i.test(func.name);
                    if (isSafePattern) {
                        funcRole.role = 'modifier';
                        funcRole.mechanism = `Modifies invariant state in controlled manner`;
                        entry.modifiers.push(funcRole);
                    }
                    else {
                        funcRole.role = 'potential-violator';
                        funcRole.mechanism = `Modifies invariant variables without clear maintenance pattern`;
                        entry.potentialViolators.push(funcRole);
                    }
                }
                else if (readsInvVar) {
                    funcRole.role = 'depender';
                    funcRole.mechanism = `Relies on invariant being correctly maintained`;
                    entry.dependers.push(funcRole);
                }
                // Check for permissionless access to invariant variables
                if (isPermFunc(func, registeredFunc) && writesInvVar) {
                    // This is a protection gap if not already flagged
                    if (funcRole.role !== 'potential-violator') {
                        entry.potentialViolators.push({
                            ...funcRole,
                            role: 'potential-violator',
                            mechanism: 'Permissionless function can modify invariant state'
                        });
                    }
                }
            }
        }
        // Determine completeness
        if (entry.establishers.length > 0 && entry.modifiers.length > 0) {
            entry.completeness = 'complete';
        }
        else if (entry.establishers.length > 0 || entry.modifiers.length > 0) {
            entry.completeness = 'partial';
        }
        mappings.push(entry);
        // Generate violation paths for potential violators
        for (const violator of entry.potentialViolators) {
            const path = generateViolationPath(inv, violator, contracts);
            if (path)
                violationPaths.push(path);
        }
        // Detect protection gaps
        if (entry.potentialViolators.length > 0 && entry.establishers.length === 0) {
            protectionGaps.push({
                gapId: `PG_${inv.id}`,
                invariantId: inv.id,
                missingProtection: 'No establisher functions found for this invariant',
                affectedFunctions: entry.potentialViolators.map(v => v.functionId),
                recommendedFix: 'Add validation/maintenance logic or restrict write access to invariant variables',
                severity: inv.severity === 'critical' ? 'critical' : 'high'
            });
        }
    }
    if (verbose) {
        console.log(`[StateCouplingAnalyzer] Mapped ${mappings.length} invariants, found ${violationPaths.length} violation paths, ${protectionGaps.length} protection gaps`);
    }
    return { mappings, violationPaths, protectionGaps };
}
function generateViolationPath(inv, violator, contracts) {
    const [contractName, funcName] = violator.functionId.split('.');
    const func = findFunc(contracts, contractName, funcName);
    if (!func)
        return null;
    const steps = [];
    let stepNum = 0;
    // Step 1: Entry
    steps.push({
        stepOrder: ++stepNum,
        function: violator.functionId,
        action: 'check',
        assumptionMade: 'Access control passed (or bypassed)',
        couldFail: false
    });
    // Step 2: Read existing state
    const reads = func.stateVariablesRead || [];
    for (const varName of reads.slice(0, 3)) { // Limit to first 3
        if (inv.relatedStateVars?.includes(varName)) {
            steps.push({
                stepOrder: ++stepNum,
                function: violator.functionId,
                action: 'read',
                variable: varName,
                assumptionMade: `${varName} contains valid/expected value`,
                couldFail: true,
                failureMode: `${varName} may have been corrupted by prior call`
            });
        }
    }
    // Step 3: External call (if present)
    if (func.body?.hasExternalCall) {
        steps.push({
            stepOrder: ++stepNum,
            function: violator.functionId,
            action: 'external-call',
            assumptionMade: 'External call will not modify protocol state unexpectedly',
            couldFail: true,
            failureMode: 'Reentrancy or callback manipulation'
        });
    }
    // Step 4: Write new state
    const writes = func.stateVariablesWritten || [];
    for (const varName of writes.slice(0, 3)) {
        if (inv.relatedStateVars?.includes(varName)) {
            steps.push({
                stepOrder: ++stepNum,
                function: violator.functionId,
                action: 'write',
                variable: varName,
                assumptionMade: 'New value maintains invariant',
                couldFail: true,
                failureMode: `Invariant ${inv.id} violated by incorrect calculation`
            });
        }
    }
    // Assess feasibility
    const feasibility = assessViolationFeasibility(func, violator);
    return {
        pathId: `VP_${inv.id}_${funcName}`,
        invariantId: inv.id,
        entryFunction: violator.functionId,
        executionSteps: steps,
        prerequisiteState: [
            'Attacker has permission to call function (or it is permissionless)',
            'Required state prerequisites exist',
            ...(func.body?.hasExternalCall ? ['External call target is malicious/cooperative'] : [])
        ],
        impactIfViolated: inv.template || `Invariant ${inv.id} violated`,
        feasibility
    };
}
function assessViolationFeasibility(_func, violator) {
    if (violator.confidence === 'certain')
        return 'easy';
    if (violator.confidence === 'likely')
        return 'moderate';
    return 'difficult';
}
// ============================================================
// STEP 4: VARIABLE CLASSIFIER
// ============================================================
function classifyVariables(contracts, functionRegistry, invariants = [], verbose = false) {
    if (verbose)
        console.log('[StateCouplingAnalyzer] Classifying variables...');
    const classifications = [];
    const byCategory = new Map();
    let criticalCount = 0;
    let mostSensitive = '';
    let mostWidelyUsed = '';
    let maxUsage = 0;
    for (const contract of contracts) {
        for (const stateVar of contract.stateVariables) {
            // Skip constants and immutables
            if (stateVar.visibility === 'constant' || stateVar.visibility === 'immutable')
                continue;
            const primaryCategory = classifyVariablePrimary(stateVar);
            const secondaryCategories = classifyVariableSecondary(stateVar);
            const sensitivity = assessVariableSensitivity(stateVar, primaryCategory);
            const integrityReq = determineIntegrityRequirement(primaryCategory);
            // Find related invariants
            const relatedInvariants = invariants.filter(inv => inv.relatedStateVars?.includes(stateVar.name)).map(inv => inv.id);
            // Find writer and reader functions
            const writers = [];
            const readers = [];
            for (const func of contract.functions) {
                if (func.stateVariablesWritten?.includes(stateVar.name)) {
                    writers.push(`${contract.name}.${func.name}`);
                }
                if (func.stateVariablesRead?.includes(stateVar.name)) {
                    readers.push(`${contract.name}.${func.name}`);
                }
            }
            // Determine cross-contract impacts
            const crossContractImpact = findCrossContractImpacts(stateVar.name, contract.name, contracts);
            const classified = {
                variableName: stateVar.name,
                contract: contract.name,
                type: stateVar.type,
                primaryCategory,
                secondaryCategories,
                securitySensitivity: sensitivity,
                integrityRequirement: integrityReq,
                classificationRationale: generateClassificationRationale(stateVar, primaryCategory),
                relatedInvariants,
                writerFunctions: writers,
                readerFunctions: readers,
                crossContractImpact
            };
            classifications.push(classified);
            // Categorize
            const existing = byCategory.get(primaryCategory) || [];
            existing.push(classified);
            byCategory.set(primaryCategory, existing);
            // Track statistics
            if (sensitivity === 'critical') {
                criticalCount++;
                mostSensitive = `${contract.name}.${stateVar.name}`;
            }
            const totalUsage = writers.length + readers.length;
            if (totalUsage > maxUsage) {
                maxUsage = totalUsage;
                mostWidelyUsed = `${contract.name}.${stateVar.name}`;
            }
        }
    }
    const byPrimaryCategory = {};
    for (const [cat, vars] of byCategory) {
        byPrimaryCategory[cat] = vars.length;
    }
    const summary = {
        totalClassified: classifications.length,
        criticalSensitivityCount: criticalCount,
        byPrimaryCategory,
        mostSensitiveVariable: mostSensitive,
        mostWidelyUsedVariable: mostWidelyUsed
    };
    if (verbose) {
        console.log(`[StateCouplingAnalyzer] Classified ${classifications.length} variables (${criticalCount} critical sensitivity)`);
    }
    return { classifications, summary, byCategory };
}
function classifyVariablePrimary(stateVar) {
    const name = stateVar.name.toLowerCase();
    const type = stateVar.type.toLowerCase();
    // Accounting variables
    if (/balance|totalSupply|totalDebt|totalBorrow|totalDeposit|supply|debt/i.test(name)) {
        return 'accounting';
    }
    // Authorization variables
    if (/owner|admin|role|permission|hasRole|isOwner|pauser/i.test(name)) {
        return 'authorization';
    }
    // Pricing variables
    if (/price|oracle|rate|exchange|twap|spotPrice/i.test(name)) {
        return 'pricing';
    }
    // Liquidity variables
    if (/pool|reserve|liquidity|availableLiquidity|idle/i.test(name)) {
        return 'liquidity';
    }
    // Solvency variables
    if (/healthFactor|collateralRatio|ltv|loanToValue|margin|solvency/i.test(name)) {
        return 'solvency';
    }
    // Settlement variables
    if (/pending|settled|executed|queued|unlock|vesting| cliff/i.test(name)) {
        return 'settlement';
    }
    // Configuration variables
    if (/fee|ratio|percentage|threshold|limit|factor|config|param/i.test(name)) {
        return 'configuration';
    }
    // Ownership variables
    if (/ownerOf|tokenId|nft|tokenOwner/i.test(name)) {
        return 'ownership';
    }
    // Timestamp variables
    if (/timestamp|lastUpdate|startTime|endTime|deadline|epoch/i.test(name)) {
        return 'timestamp';
    }
    // Flag variables
    if (/paused|locked|active|enabled|initialized|entered/i.test(name) &&
        (type.includes('bool') || name.startsWith('is') || name.startsWith('has'))) {
        return 'flag';
    }
    // Caching variables
    if (/cached|last|snapshot|checkpoint/i.test(name)) {
        return 'caching';
    }
    // Indexing variables
    if (/index|count|nonce|cursor|position/i.test(name)) {
        return 'indexing';
    }
    return 'unknown';
}
function classifyVariableSecondary(stateVar) {
    const secondary = [];
    const name = stateVar.name.toLowerCase();
    // Many variables have secondary characteristics
    if (/mapping.*address.*uint/i.test(stateVar.type) || /balance/i.test(name)) {
        if (!secondary.includes('accounting'))
            secondary.push('accounting');
    }
    if (/address.*owner/i.test(name) || /address.*admin/i.test(name)) {
        if (!secondary.includes('authorization'))
            secondary.push('authorization');
    }
    return secondary;
}
function assessVariableSensitivity(stateVar, category) {
    const sensitiveCategories = ['accounting', 'authorization', 'pricing', 'solvency', 'liquidity'];
    if (sensitiveCategories.includes(category)) {
        // Extra sensitive if directly holds value
        if (/balance|supply|debt|collateral|reserve/i.test(stateVar.name)) {
            return 'critical';
        }
        return 'high';
    }
    if (['settlement', 'configuration', 'ownership'].includes(category)) {
        return 'medium';
    }
    return 'low';
}
function determineIntegrityRequirement(category) {
    switch (category) {
        case 'accounting': return 'exact';
        case 'authorization': return 'exact';
        case 'pricing': return 'bounded';
        case 'solvency': return 'bounded';
        case 'liquidity': return 'exact';
        case 'settlement': return 'atomic'; // Fix type
        case 'configuration': return 'eventual';
        case 'timestamp': return 'monotonic'; // Fix type
        default: return 'eventual';
    }
}
function generateClassificationRationale(stateVar, category) {
    const rationales = {
        'accounting': `Variable tracks fund/token quantities requiring conservation invariant`,
        'authorization': `Variable controls access permissions affecting all secured operations`,
        'pricing': `Variable influences valuation affecting economic decisions`,
        'liquidity': `Variable represents available funds for withdrawals/operations`,
        'solvency': `Variable determines account health and liquidation eligibility`,
        'settlement': `Variable tracks pending operations requiring atomic completion`,
        'configuration': `Variable sets protocol parameters affecting system behavior`,
        'indexing': `Variable enables efficient data structure traversal`,
        'caching': `Variable stores computed values for gas optimization`,
        'metadata': `Variable stores informational data without direct security impact`,
        'ownership': `Variable tracks asset/NFT ownership rights`,
        'timestamp': `Variable records time for ordering/expiry logic`,
        'flag': `Variable indicates binary state conditions`,
        'unknown': `Could not automatically determine variable purpose`
    };
    return rationales[category] || rationales['unknown'];
}
function findCrossContractImpacts(varName, contractName, contracts) {
    const impacts = [];
    for (const contract of contracts) {
        if (contract.name === contractName)
            continue;
        // Check if other contract references this variable's data
        for (const func of contract.functions) {
            const callsTarget = func.calls?.some(call => call.includes(contractName) || call.includes('.'));
            if (callsTarget) {
                // This function might depend on the variable
                const existingImpact = impacts.find(i => i.targetContract === contract.name);
                if (!existingImpact) {
                    impacts.push({
                        targetContract: contract.name,
                        impactType: 'assumed-consistent',
                        description: `${contract.name} may assume ${varName} state from ${contractName}`
                    });
                }
            }
        }
    }
    return impacts;
}
// ============================================================
// STEP 5: TOP INTERSECTIONS COMPUTATION
// ============================================================
function computeTopIntersections(depMatrix, varClass, contracts, topN = 20, verbose = false) {
    if (verbose)
        console.log(`[StateCouplingAnalyzer] Computing top ${topN} state intersections...`);
    const candidateIntersections = [];
    let intersectionId = 0;
    // Analyze high-value variable interactions
    const criticalVars = varClass.classifications.filter(v => v.securitySensitivity === 'critical' || v.securitySensitivity === 'high');
    // For each critical variable, find its intersection points
    for (const critVar of criticalVars) {
        // Find all functions that touch this variable
        const participants = [];
        for (const func of depMatrix.functions) {
            if (func.contract !== critVar.contract)
                continue;
            const writes = func.stateVariablesWritten.includes(critVar.variableName);
            const reads = func.stateVariablesRead.includes(critVar.variableName);
            if (writes || reads) {
                participants.push({
                    functionId: func.id,
                    role: writes && reads ? 'both' : writes ? 'writer' : 'reader',
                    accessControl: func.accessControl,
                    isPermissionless: func.isPermissionless,
                    interactionType: 'direct'
                });
            }
        }
        if (participants.length < 2)
            continue; // Need at least 2 participants for intersection
        // Determine intersection type
        const intType = determineIntersectionType(critVar.primaryCategory, participants);
        // Calculate risk score
        const riskScore = calculateIntersectionRisk(critVar, participants);
        // Estimate exploitation complexity
        const exploitComplexity = estimateExploitationComplexity(participants, riskScore);
        // Generate findings
        const specificFindings = generateIntersectionFindings(critVar, participants);
        // Generate recommendations
        const recommendations = generateIntersectionRecommendations(critVar, participants, riskScore);
        candidateIntersections.push({
            rank: 0, // Will be assigned after sorting
            variables: [critVar.variableName],
            contracts: [critVar.contract],
            functions: participants,
            intersectionType: intType,
            riskScore,
            valueAtRisk: estimateValueAtRisk(critVar),
            exploitationComplexity: exploitComplexity,
            description: `${critVar.variableName} (${critVar.primaryCategory}) intersected by ${participants.length} functions`,
            specificFindings,
            recommendations
        });
    }
    // Also analyze multi-variable coupling clusters
    for (const cluster of depMatrix.couplingClusters) {
        if (cluster.sharedVariables.length < 2)
            continue;
        // Filter to high-risk clusters
        const clusterParticipants = cluster.functions.map(fid => {
            const func = depMatrix.functions.find(f => f.id === fid);
            return func ? {
                functionId: fid,
                role: 'both',
                accessControl: func.accessControl,
                isPermissionless: func.isPermissionless,
                interactionType: 'indirect-via-call'
            } : null;
        }).filter(Boolean);
        const clusterRisk = cluster.cohesionScore * (cluster.riskLevel === 'critical' ? 1.5 : cluster.riskLevel === 'high' ? 1.2 : 1);
        candidateIntersections.push({
            rank: 0,
            variables: cluster.sharedVariables,
            contracts: [...new Set(cluster.functions.map(f => f.split('.')[0]))],
            functions: clusterParticipants,
            intersectionType: 'cross-contract-sync',
            riskScore: Math.min(Math.round(clusterRisk), 100),
            valueAtRisk: 'Multiple variables - cumulative risk',
            exploitationComplexity: cluster.riskLevel === 'critical' ? 'easy' : 'moderate',
            description: `Tightly coupled cluster: ${cluster.description}`,
            specificFindings: [
                `${cluster.functions.length} functions form tight coupling cluster`,
                `Cohesion score: ${cluster.cohesionScore}/100`,
                `Shared variables: ${cluster.sharedVariables.join(', ')}`
            ],
            recommendations: [
                'Consider decoupling these functions',
                'Introduce intermediate abstraction layer',
                'Add explicit synchronization mechanisms'
            ]
        });
    }
    // Sort by risk score and assign ranks
    candidateIntersections.sort((a, b) => b.riskScore - a.riskScore);
    const topIntersections = candidateIntersections.slice(0, topN);
    topIntersections.forEach((intersection, idx) => {
        intersection.rank = idx + 1;
    });
    if (verbose) {
        console.log(`[StateCouplingAnalyzer] Computed ${topIntersections.length} top intersections`);
    }
    return {
        intersections: topIntersections,
        rankingMethodology: 'Ranked by: risk score (variable sensitivity × participant count × permissionless access × coupling strength)',
        generatedAt: new Date().toISOString()
    };
}
function determineIntersectionType(varCategory, _participants) {
    switch (varCategory) {
        case 'accounting': return 'accounting-consistency';
        case 'authorization': return 'access-control-propagation';
        case 'pricing': return 'oracle-dependency';
        case 'liquidity': return 'liquidity-solvency';
        case 'solvency': return 'liquidity-solvency';
        case 'settlement': return 'settlement-atomicity';
        default: return 'cross-contract-sync';
    }
}
function calculateIntersectionRisk(varInfo, participants) {
    let risk = 0;
    // Base risk from variable sensitivity
    switch (varInfo.securitySensitivity) {
        case 'critical':
            risk += 40;
            break;
        case 'high':
            risk += 30;
            break;
        case 'medium':
            risk += 20;
            break;
        case 'low':
            risk += 10;
            break;
    }
    // Participant count risk
    risk += Math.min(participants.length * 5, 25);
    // Permissionless participant risk
    const permCount = participants.filter(p => p.isPermissionless).length;
    risk += permCount * 15;
    // Writer count risk (more writers = more contention)
    const writerCount = participants.filter(p => p.role === 'writer' || p.role === 'both').length;
    risk += writerCount * 8;
    // Related invariant risk
    risk += Math.min(varInfo.relatedInvariants.length * 5, 15);
    // Cross-contract impact risk
    risk += Math.min(varInfo.crossContractImpact.length * 5, 15);
    return Math.min(risk, 100);
}
function estimateExploitationComplexity(participants, riskScore) {
    const permWriterExists = participants.some(p => p.isPermissionless &&
        (p.role === 'writer' || p.role === 'both'));
    if (permWriterExists && riskScore >= 80)
        return 'trivial';
    if (permWriterExists && riskScore >= 60)
        return 'easy';
    if (riskScore >= 70)
        return 'moderate';
    return 'difficult';
}
function estimateValueAtRisk(varInfo) {
    const valueEstimates = {
        'accounting': 'Total protocol value (user funds)',
        'authorization': 'Full protocol control',
        'pricing': 'All price-dependent positions / Oracle-dependent valuations',
        'liquidity': 'Available withdrawal capacity',
        'solvency': 'All undercollateralized positions',
        'settlement': 'Pending transaction values',
        'configuration': 'Protocol operational integrity',
        'indexing': 'Lookup efficiency metadata',
        'caching': 'Computed/cached derived values',
        'metadata': 'Informational data only',
        'ownership': 'Asset ownership rights',
        'timestamp': 'Time-dependent state',
        'flag': 'Boolean/state flags',
        'unknown': 'Indeterminate'
    };
    return valueEstimates[varInfo.primaryCategory] || 'Unknown';
}
function generateIntersectionFindings(varInfo, participants) {
    const findings = [];
    // Permissionless writer findings
    const permWriters = participants.filter(p => p.isPermissionless &&
        (p.role === 'writer' || p.role === 'both'));
    if (permWriters.length > 0) {
        findings.push(`${permWriters.length} permissionless function(s) can modify ${varInfo.variableName}`);
    }
    // Mixed access level findings
    const accessLevels = new Set(participants.map(p => p.accessControl));
    if (accessLevels.size > 1) {
        findings.push(`Mixed access control levels: ${Array.from(accessLevels).join(', ')}`);
    }
    // Reader-after-writer findings
    const writers = participants.filter(p => p.role === 'writer' || p.role === 'both');
    const readers = participants.filter(p => p.role === 'reader' || p.role === 'both');
    if (writers.length > 0 && readers.length > 0) {
        findings.push(`${writers.length} writer(s) and ${readers.length} reader(s) create read-after-write dependency`);
    }
    // Invariant findings
    if (varInfo.relatedInvariants.length > 0) {
        findings.push(`${varInfo.relatedInvariants.length} invariant(s) depend on this variable`);
    }
    // Cross-contract findings
    if (varInfo.crossContractImpact.length > 0) {
        findings.push(`${varInfo.crossContractImpact.length} contract(s) may depend on this state`);
    }
    return findings;
}
function generateIntersectionRecommendations(varInfo, participants, riskScore) {
    const recs = [];
    if (riskScore >= 70) {
        recs.push('Immediate review recommended - high-risk intersection');
    }
    // Permissionless writer recommendations
    const permWriters = participants.filter(p => p.isPermissionless &&
        (p.role === 'writer' || p.role === 'both'));
    if (permWriters.length > 0) {
        recs.push('Consider restricting write access to authenticated callers only');
        recs.push('Implement reentrancy guards for all writers');
    }
    // Accounting-specific recommendations
    if (varInfo.primaryCategory === 'accounting') {
        recs.push('Add balance change events for audit trail');
        recs.push('Consider implementing Checks-Effects-Interactions pattern strictly');
    }
    // Authorization-specific recommendations
    if (varInfo.primaryCategory === 'authorization') {
        recs.push('Add two-step access control change process');
        recs.push('Implement timelock for sensitive permission changes');
    }
    // High writer count recommendations
    const writerCount = participants.filter(p => p.role === 'writer' || p.role === 'both').length;
    if (writerCount > 3) {
        recs.push('Consider consolidating write operations through a single modifier');
        recs.push('Document intended ordering constraints between writers');
    }
    return recs;
}
// ============================================================
// STEP 6: HIDDEN ASSUMPTION IDENTIFIER
// ============================================================
function identifyHiddenAssumptions(contracts, functionRegistry, invariants = [], callEdges = [], verbose = false) {
    if (verbose)
        console.log('[StateCouplingAnalyzer] Identifying hidden assumptions...');
    const assumptions = [];
    const byFunction = new Map();
    const byCategory = new Map();
    let assumptionId = 0;
    for (const contract of contracts) {
        for (const func of contract.functions) {
            const registeredFunc = findRegFunc(functionRegistry, contract.name, func.name);
            const funcAssumptions = [];
            // 1. No-reentrancy assumption (for functions with external calls after writes)
            if (func.body?.hasExternalCall && func.body?.ceiPattern === 'violated') {
                funcAssumptions.push(createAssumption(++assumptionId, 'No reentrant call will occur during execution', 'no-reentrancy', { contract: contract.name, function: func.name, line: func.lineStart }, [`${contract.name}.${func.name}`], [], 'Reentrant call can double-spend/double-execute', 'easy', 'trivial', 'critical', 'Implement CEI pattern or reentrancy guard'));
            }
            // 2. Token compliance assumption (for functions calling token contracts)
            const hasTokenCall = func.calls?.some(c => /transfer|transferFrom|mint|burn|approve|permit/i.test(c));
            if (hasTokenCall) {
                funcAssumptions.push(createAssumption(++assumptionId, 'Token contracts follow ERC20/721 specification exactly', 'token-compliance', { contract: contract.name, function: func.name }, [`${contract.name}.${func.name}`], [], 'Malicious token can block transfers, return false silently, or reenter', 'moderate', 'easy', 'high', 'Check return values, use SafeERC20, handle false returns'));
            }
            // 3. Oracle accuracy assumption (for functions reading prices)
            const readsPrice = func.stateVariablesRead?.some(v => /price|oracle|rate/i.test(v)) || func.calls?.some(c => /price|oracle|getRate/i.test(c));
            if (readsPrice) {
                funcAssumptions.push(createAssumption(++assumptionId, 'Oracle/data source provides accurate and manipulation-resistant prices', 'oracle-accuracy', { contract: contract.name, function: func.name }, [`${contract.name}.${func.name}`], [], 'Manipulated oracle causes incorrect valuation, bad debt, unfair liquidations', 'hard', 'moderate', 'critical', 'Use TWAP oracles, implement circuit breakers, add sanity checks'));
            }
            // 4. Atomicity assumption (for multi-variable writes)
            if ((func.stateVariablesWritten?.length || 0) >= 2) {
                funcAssumptions.push(createAssumption(++assumptionId, 'All state updates in this function execute atomically (no interleaving)', 'atomicity', { contract: contract.name, function: func.name, line: func.lineStart }, [`${contract.name}.${func.name}`], [], 'Concurrent execution could see partially-updated state', 'hard', 'difficult', func.body?.hasExternalCall ? 'high' : 'medium', 'Use mutex pattern or ensure single-entry-point execution'));
            }
            // 5. Caller intent assumption (for permissionless functions)
            if (isPermFunc(func, registeredFunc)) {
                funcAssumptions.push(createAssumption(++assumptionId, 'Caller acts in good faith within expected use cases', 'caller-intent', { contract: contract.name, function: func.name }, [`${contract.name}.${func.name}`], [], 'Adversarial caller exploits edge cases beyond intended parameters', 'impossible', 'trivial', 'medium', 'Validate all inputs rigorously, check boundary conditions'));
            }
            // 6. Timestamp monotonicity assumption
            if (func.stateVariablesRead?.some(v => /timestamp|time/i.test(v)) ||
                func.calls?.some(c => /block\.timestamp/i.test(c))) {
                funcAssumptions.push(createAssumption(++assumptionId, 'Timestamps are monotonically increasing across blocks', 'timestamp-monotonicity', { contract: contract.name, function: func.name }, [`${contract.name}.${func.name}`], [], 'Miner manipulation of timestamp within allowed range', 'easy', 'easy', 'low', 'Use wider time windows, avoid precise timestamp comparisons'));
            }
            // 7. Math correctness assumption (for complex calculations)
            if (func.complexity > 10 || /mul|div|pow|sqrt/i.test(func.name)) {
                funcAssumptions.push(createAssumption(++assumptionId, 'Mathematical operations produce correct results without overflow/underflow', 'math-correctness', { contract: contract.name, function: func.name, line: func.lineStart }, [`${contract.name}.${func.name}`], [], 'Overflow/underflow/precision loss causes incorrect calculations', 'easy', 'easy', 'high', 'Use SafeMath, check bounds, validate precision requirements'));
            }
            // Add to collections
            for (const assump of funcAssumptions) {
                assumptions.push(assump);
                const funcKey = `${contract.name}.${func.name}`;
                const existingFunc = byFunction.get(funcKey) || [];
                existingFunc.push(assump);
                byFunction.set(funcKey, existingFunc);
                const existingCat = byCategory.get(assump.category) || [];
                existingCat.push(assump);
                byCategory.set(assump.category, existingCat);
            }
        }
    }
    // Compute summary
    const byCat = {};
    for (const [, cats] of byCategory) {
        for (const cat of cats) {
            byCat[cat.category] = (byCat[cat.category] || 0) + 1;
        }
    }
    const unvalidated = assumptions.filter(a => a.validatedBy.length === 0);
    const critical = assumptions.filter(a => a.severity === 'critical');
    const mostHeavy = Array.from(byFunction.entries())
        .sort((a, b) => b[1].length - a[1].length)[0];
    const summary = {
        totalAssumptions: assumptions.length,
        criticalAssumptions: critical.length,
        unvalidatedAssumptions: unvalidated.length,
        byCategory: byCat,
        mostAssumptionHeavyFunction: mostHeavy?.[0]
    };
    if (verbose) {
        console.log(`[StateCouplingAnalyzer] Identified ${assumptions.length} hidden assumptions (${critical.length} critical, ${unvalidated.length} unvalidated)`);
    }
    return { assumptions, byFunction, byCategory, summary };
}
function createAssumption(id, assumption, category, location, heldBy, validatedBy, ifWrong, detectability, exploitability, severity, recommendation) {
    return {
        id: `HA_${id}`,
        assumption,
        category,
        location,
        heldBy,
        validatedBy,
        ifWrong,
        detectability,
        exploitability,
        severity,
        recommendation
    };
}
// ============================================================
// STEP 7: CRITICAL FINDINGS COMPILER
// ============================================================
function compileCriticalFindings(depMatrix, hiddenCoups, invMap, varClass, topIntersections, hiddenAssumps, verbose = false) {
    const findings = [];
    let findingId = 0;
    // From dependency matrix - highly coupled permissionless functions
    for (const func of depMatrix.functions) {
        if (func.isPermissionless && func.couplingScore >= 60) {
            findings.push({
                id: `CF_${++findingId}`,
                type: 'coupling',
                severity: func.riskLevel === 'critical' ? 'critical' : 'high',
                title: `Highly coupled permissionless function: ${func.id}`,
                description: `Function ${func.id} is permissionless and has coupling score ${func.couplingScore}/100 with ${func.outDegree} outgoing and ${func.inDegree} incoming dependencies`,
                location: { contract: func.contract, function: func.name },
                evidence: [
                    `Coupling score: ${func.couplingScore}/100`,
                    `Outgoing dependencies: ${func.outDegree}`,
                    `Incoming dependencies: ${func.inDegree}`,
                    `State variables written: [${func.stateVariablesWritten.join(', ')}]`,
                    `State variables read: [${func.stateVariablesRead.join(', ')}]`
                ],
                impact: 'Attacker can influence multiple state variables through single entry point',
                remediation: 'Restrict access or decouple state modifications',
                priority: func.riskLevel === 'critical' ? 'immediate' : 'short-term'
            });
        }
    }
    // From hidden couplings - critical/high severity
    for (const coup of hiddenCoups.couplings) {
        if (coup.severity === 'critical' || coup.severity === 'high') {
            findings.push({
                id: `CF_${++findingId}`,
                type: 'coupling',
                severity: coup.severity,
                title: `Hidden coupling detected: ${coup.type}`,
                description: coup.description,
                location: coup.source,
                evidence: [`Mechanism: ${coup.mechanism}`, ...(coup.exploitationScenario ? [`Scenario: ${coup.exploitationScenario}`] : [])],
                impact: coup.exploitationScenario || 'Potential state inconsistency or unauthorized access',
                remediation: coup.recommendation,
                priority: coup.severity === 'critical' ? 'immediate' : 'short-term'
            });
        }
    }
    // From invariant mapping - protection gaps
    for (const gap of invMap.protectionGaps) {
        findings.push({
            id: `CF_${++findingId}`,
            type: 'protection-gap',
            severity: gap.severity,
            title: `Invariant protection gap: ${gap.invariantId}`,
            description: gap.missingProtection,
            location: { contract: gap.affectedFunctions[0]?.split('.')[0] || 'unknown' },
            evidence: [`Affected functions: [${gap.affectedFunctions.join(', ')}]`],
            impact: 'Invariant can be violated without detection or prevention',
            remediation: gap.recommendedFix,
            priority: gap.severity === 'critical' ? 'immediate' : 'short-term'
        });
    }
    // From top intersections - top 5 highest risk
    for (const intersection of topIntersections.intersections.slice(0, 5)) {
        if (intersection.riskScore >= 70) {
            findings.push({
                id: `CF_${++findingId}`,
                type: 'classification',
                severity: intersection.riskScore >= 90 ? 'critical' : 'high',
                title: `High-risk state intersection (#${intersection.rank}): ${intersection.variables.join(', ')}`,
                description: intersection.description,
                location: { contract: intersection.contracts[0], variable: intersection.variables[0] },
                evidence: intersection.specificFindings,
                impact: intersection.valueAtRisk,
                remediation: intersection.recommendations[0] || 'Review and harden this intersection',
                priority: 'short-term'
            });
        }
    }
    // From hidden assumptions - critical ones
    for (const assump of hiddenAssumps.assumptions) {
        if (assump.severity === 'critical') {
            findings.push({
                id: `CF_${++findingId}`,
                type: 'assumption',
                severity: 'critical',
                title: `Critical hidden assumption: ${assump.assumption}`,
                description: `${assump.location.function || assump.location.contract} assumes: ${assump.assumption}`,
                location: assump.location,
                evidence: [`If wrong: ${assump.ifWrong}`, `Exploitability: ${assump.exploitability}`, `Detectability: ${assump.detectability}`],
                impact: assump.ifWrong,
                remediation: assump.recommendation,
                priority: 'immediate'
            });
        }
    }
    // Sort by severity
    findings.sort((a, b) => {
        const order = { critical: 4, high: 3, medium: 2, low: 1 };
        return order[b.severity] - order[a.severity];
    });
    if (verbose) {
        console.log(`[StateCouplingAnalyzer] Compiled ${findings.length} critical findings`);
    }
    return findings;
}
// ============================================================
// HELPER FUNCTIONS
// ============================================================
function findRegFunc(registry, contract, funcName) {
    if (!registry || !contract || !funcName)
        return undefined;
    const contractFuncs = registry.get(contract);
    return contractFuncs?.find(f => f.name === funcName || f.signature.includes(funcName));
}
function inferAccessControl(func) {
    if (func.modifiers.some(m => /onlyOwner|onlyAdmin|onlyRole/.test(m)))
        return 'admin-only';
    if (func.modifiers.length > 0)
        return 'restricted';
    if (func.visibility === 'internal' || func.visibility === 'private')
        return 'internal';
    return 'public';
}
function isPermFunc(func, registered) {
    if (registered) {
        return registered.accessControl.level === 'public' &&
            (func.visibility === 'external' || func.visibility === 'public');
    }
    const hasAccessRestriction = func.modifiers.some(m => /onlyOwner|onlyAdmin|onlyRole|require|whenNotPaused/.test(m));
    return !hasAccessRestriction &&
        (func.visibility === 'external' || func.visibility === 'public') &&
        func.stateMutability !== 'view' &&
        func.stateMutability !== 'pure';
}
function findFunc(contracts, contractName, funcName) {
    const contract = contracts.find(c => c.name === contractName);
    return contract?.functions.find(f => f.name === funcName);
}
// ============================================================
// EXPORT UTILITIES
// ============================================================
/**
 * Export state coupling analysis result to JSON-serializable format
 */
function exportStateCouplingResult(result) {
    return {
        timestamp: result.timestamp,
        functionDependencyMatrix: {
            functions: result.functionDependencyMatrix.functions,
            dependencies: Array.from(result.functionDependencyMatrix.dependencies.entries()).map(([k, v]) => ({
                key: k,
                ...v
            })),
            statistics: result.functionDependencyMatrix.statistics,
            couplingClusters: result.functionDependencyMatrix.couplingClusters
        },
        hiddenCouplings: {
            couplings: result.hiddenCouplings.couplings,
            summary: result.hiddenCouplings.summary
        },
        invariantFunctionMap: {
            mappings: result.invariantFunctionMap.mappings,
            violationPaths: result.invariantFunctionMap.violationPaths,
            protectionGaps: result.invariantFunctionMap.protectionGaps
        },
        variableClassification: {
            classifications: result.variableClassification.classifications,
            summary: result.variableClassification.summary
        },
        topStateIntersections: result.topStateIntersections,
        hiddenAssumptions: {
            assumptions: result.hiddenAssumptions.assumptions,
            summary: result.hiddenAssumptions.summary
        },
        criticalFindings: result.criticalFindings
    };
}
/**
 * Generate Markdown report for State Coupling Analysis
 */
function generateStateCouplingMarkdown(result) {
    let md = '# State Coupling Analysis Report\n\n';
    md += `**Generated:** ${result.timestamp}\n\n`;
    // Executive Summary
    md += '## Executive Summary\n\n';
    md += '| Metric | Value |\n';
    md += '|--------|-------|\n';
    md += '| Total Functions Analyzed | ' + result.functionDependencyMatrix.statistics.totalFunctions + ' |\n';
    md += '| Total Dependencies | ' + result.functionDependencyMatrix.statistics.totalDependencies + ' |\n';
    md += '| Average Dependencies/Function | ' + result.functionDependencyMatrix.statistics.averageDependenciesPerFunction.toFixed(1) + ' |\n';
    md += '| Hidden Couplings Found | ' + result.hiddenCouplings.summary.totalHiddenCouplings + ' |\n';
    md += '| Critical Couplings | ' + result.hiddenCouplings.summary.criticalCount + ' |\n';
    md += '| Protection Gaps | ' + result.invariantFunctionMap.protectionGaps.length + ' |\n';
    md += '| Critical Variables | ' + result.variableClassification.summary.criticalSensitivityCount + ' |\n';
    md += '| Critical Findings | ' + result.criticalFindings.length + ' |\n\n';
    // High-Risk Functions
    const highRiskFuncs = result.functionDependencyMatrix.functions
        .filter(f => f.riskLevel === 'critical' || f.riskLevel === 'high')
        .sort((a, b) => b.couplingScore - a.couplingScore);
    if (highRiskFuncs.length > 0) {
        md += '## High-Risk Functions\n\n';
        md += '| Function | Coupling Score | Risk | Permissionless |\n';
        md += '|---------|---------------|------|----------------|\n';
        for (const func of highRiskFuncs.slice(0, 15)) {
            md += '| `' + func.id + '` | ' + func.couplingScore + '/100 | **' + func.riskLevel.toUpperCase() + '** | ' +
                (func.isPermissionless ? '✅ Yes' : '❌ No') + ' |\n';
        }
        md += '\n';
    }
    // Hidden Couplings Summary
    if (result.hiddenCouplings.couplings.length > 0) {
        md += '## Hidden Couplings\n\n';
        for (const coup of result.hiddenCouplings.couplings.slice(0, 10)) {
            md += '### ' + coup.severity.toUpperCase() + ': ' + coup.type.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) + '\n\n';
            md += coup.description + '\n\n';
            if (coup.exploitationScenario) {
                md += '**Exploitation Scenario:** ' + coup.exploitationScenario + '\n\n';
            }
            md += '**Recommendation:** ' + coup.recommendation + '\n\n';
            md += '---\n\n';
        }
    }
    // Top State Intersections
    if (result.topStateIntersections.intersections.length > 0) {
        md += '## Top State Intersections\n\n';
        md += '| Rank | Variables | Risk | Exploitation |\n';
        md += '|------|-----------|------|-------------|\n';
        for (const inter of result.topStateIntersections.intersections.slice(0, 15)) {
            md += '| #' + inter.rank + ' | `' + inter.variables.join(', ') + '` | ' + inter.riskScore + '/100 | ' +
                inter.exploitationComplexity + ' |\n';
        }
        md += '\n';
    }
    // Critical Findings
    if (result.criticalFindings.length > 0) {
        md += '## Critical Findings\n\n';
        for (const finding of result.criticalFindings.slice(0, 10)) {
            md += '### ' + finding.severity.toUpperCase() + ': ' + finding.title + '\n\n';
            md += finding.description + '\n\n';
            md += '**Impact:** ' + finding.impact + '\n\n';
            md += '**Remediation:** ' + finding.remediation + '\n\n';
            md += '---\n\n';
        }
    }
    return md;
}
// -----------------------------------------------------------
// MAIN WEAPONIZATION FUNCTION
// -----------------------------------------------------------
/**
 * Fix A: Deep Coupling Exploitation Generator
 *
 * Transforms coupling analysis data into weaponized attack scenarios.
 * Generates:
 * 1. Atomicity violations from strongly coupled function pairs
 * 2. TOCTOU attacks from temporal/hidden couplings
 * 3. General coupling exploits from clusters
 *
 * Output optimized for RedTeam-Trackator consumption with:
 * - Pre-computed attack surfaces
 * - Ranked targets by exploitability × impact
 * - Quick attack patterns for PoC development
 */
function generateWeaponizedAttacks(couplingResult, options) {
    const verbose = options?.verbose || false;
    if (verbose)
        console.log('[WeaponizedCoupling] Generating weaponized attack scenarios...');
    const attackScenarios = [];
    const atomicityViolations = [];
    const toctouAttacks = [];
    const couplingExploits = [];
    // 1. Generate Atomicity Violations from Strongly Coupled Pairs
    const strongPairs = extractStronglyCoupledPairs(couplingResult.functionDependencyMatrix);
    for (const pair of strongPairs) {
        const violations = generateAtomicityViolations(pair, couplingResult, options?.storageWriteGraph);
        atomicityViolations.push(...violations);
        // Convert high-severity violations to full attack scenarios
        for (const viol of violations.filter(v => v.severity === 'critical' || v.severity === 'high')) {
            const attack = buildAtomicityAttack(viol, couplingResult);
            if (attack)
                attackScenarios.push(attack);
        }
    }
    // 2. Generate TOCTOU Attacks from Hidden Couplings
    for (const hidden of couplingResult.hiddenCouplings.couplings) {
        if (isTemporalCoupling(hidden)) {
            const toctou = buildTOCTOUAttack(hidden, couplingResult);
            toctouAttacks.push(toctou);
            if (toctou.severity === 'critical' || toctou.severity === 'high') {
                const attack = buildTOCTOUWeaponizedAttack(toctou, couplingResult);
                attackScenarios.push(attack);
            }
        }
    }
    // 3. Generate Coupling Exploits from Clusters
    for (const cluster of couplingResult.functionDependencyMatrix.couplingClusters) {
        if (cluster.riskLevel === 'critical' || cluster.riskLevel === 'high') {
            const exploit = buildClusterExploit(cluster, couplingResult);
            couplingExploits.push(exploit);
            const attack = buildClusterAttack(exploit, couplingResult);
            attackScenarios.push(attack);
        }
    }
    // 4. Generate Invariant Violation Chain Attacks
    for (const vPath of couplingResult.invariantFunctionMap.violationPaths) {
        if (vPath.feasibility === 'trivial' || vPath.feasibility === 'easy') {
            const attack = buildInvariantViolationAttack(vPath, couplingResult);
            attackScenarios.push(attack);
        }
    }
    // Build Redteam-optimized output
    const redteamOutput = buildRedteamOptimizedAttacks(attackScenarios, atomicityViolations, toctouAttacks, couplingExploits, couplingResult);
    // Build summary
    const summary = buildWeaponizationSummary(attackScenarios, atomicityViolations, toctouAttacks, couplingExploits);
    if (verbose) {
        console.log(`[WeaponizedCoupling] Attack generation complete:`);
        console.log(`  - Total attack scenarios: ${summary.totalAttacksGenerated}`);
        console.log(`  - Critical attacks: ${summary.criticalAttacks}`);
        console.log(`  - Atomicity violations: ${atomicityViolations.length}`);
        console.log(`  - TOCTOU attacks: ${toctouAttacks.length}`);
        console.log(`  - High-value targets identified: ${redteamOutput.rankedTargets.filter(t => t.combinedScore >= 70).length}`);
    }
    return {
        timestamp: new Date().toISOString(),
        attackScenarios,
        atomicityViolations,
        toctouAttacks,
        couplingExploits,
        summary,
        redteamOptimizedOutput: redteamOutput
    };
}
function extractStronglyCoupledPairs(matrix) {
    const pairs = [];
    const processed = new Set();
    for (const [key, relation] of matrix.dependencies.entries()) {
        if (relation.couplingStrength >= 70 && relation.sharedVariables.length >= 2) {
            const [source, target] = key.split('→');
            const pairKey = [source, target].sort().join('-');
            if (!processed.has(pairKey)) {
                processed.add(pairKey);
                const funcA = matrix.functions.find(f => f.id === source);
                const funcB = matrix.functions.find(f => f.id === target);
                if (funcA && funcB) {
                    pairs.push({ funcA, funcB, relation, sharedVariables: relation.sharedVariables });
                }
            }
        }
    }
    return pairs;
}
function generateAtomicityViolations(pair, _couplingResult, storageGraph) {
    const violations = [];
    // Check if both functions are permissionless (highest risk)
    const bothPermissionless = pair.funcA.isPermissionless && pair.funcB.isPermissionless;
    // Check if shared variables include value-bearing types
    const valueBearingVars = pair.sharedVariables.filter(v => /balance|supply|debt|collateral|reserve|fund|total|amount/i.test(v));
    // Check for read-write conflicts (A reads what B writes or vice versa)
    const isReadWriteConflict = pair.relation.dependencyType === 'read-write' ||
        pair.relation.dependencyType === 'write-read';
    // Determine severity
    let severity = 'medium';
    if (bothPermissionless && valueBearingVars.length > 0 && isReadWriteConflict) {
        severity = 'critical';
    }
    else if ((bothPermissionless || isReadWriteConflict) && valueBearingVars.length > 0) {
        severity = 'high';
    }
    else if (isReadWriteConflict || bothPermissionless) {
        severity = 'medium';
    }
    // Generate violation for each value-bearing shared variable
    for (const variable of valueBearingVars) {
        const violation = {
            violationId: `AV_${pair.funcA.id}_${pair.funcB.id}_${variable}`.replace(/[^a-zA-Z0-9_]/g, '_'),
            funcA: pair.funcA.id,
            funcB: pair.funcB.id,
            sharedVariable: variable,
            splitOperation: `Atomic operation on ${variable} split across ${pair.funcA.name} and ${pair.funcB.name}`,
            exploitationScenario: buildAtomicityScenario(pair, variable, severity),
            severity,
            hasReentrancyGuard: {
                funcA: checkReentrancyGuard(pair.funcA, storageGraph),
                funcB: checkReentrancyGuard(pair.funcB, storageGraph)
            },
            recommendedFix: buildAtomicityFixRecommendation(pair, variable)
        };
        violations.push(violation);
    }
    return violations;
}
function buildAtomicityScenario(pair, variable, severity) {
    const isReadWrite = pair.relation.dependencyType === 'read-write' ||
        pair.relation.dependencyType === 'write-read';
    if (severity === 'critical') {
        return `CRITICAL: Both ${pair.funcA.name} and ${pair.funcB.name} are permissionless and share value-bearing variable "${variable}". An attacker can call ${pair.funcA.name} to initiate an operation on ${variable}, then immediately call ${pair.funcB.name} before state consistency is checked, exploiting the atomicity gap.${isReadWrite ? ' Read-write conflict allows double-counting or state corruption.' : ''}`;
    }
    else if (severity === 'high') {
        return `HIGH: Functions ${pair.funcA.name} and ${pair.funcB.name} share sensitive variable "${variable}" without proper synchronization. Calling them in sequence can lead to inconsistent state.`;
    }
    return `MEDIUM: Potential atomicity issue between ${pair.funcA.name} and ${pair.funcB.name} on shared variable "${variable}". Review required.`;
}
function checkReentrancyGuard(func, _storageGraph) {
    // In a real implementation, this would check for mutex/reentrancy guard patterns
    // For now, use heuristic based on function name and modifiers
    const guardPatterns = /noReentrant|mutex|lock|guarded|_lock/;
    return guardPatterns.test(func.name) || guardPatterns.test(func.signature);
}
function buildAtomicityFixRecommendation(pair, variable) {
    const suggestions = [
        `Consider adding a reentrancy guard or mutex around accesses to ${variable}`,
        `Make the operations in ${pair.funcA.name} and ${pair.funcB.name} atomic using a single function call`,
        `Add consistency checks between the two functions that verify ${variable} hasn't changed`,
        `Implement a check-effects-interactions pattern properly`
    ];
    return suggestions.join('. ') + '.';
}
function buildAtomicityAttack(violation, _couplingResult) {
    if (violation.severity !== 'critical' && violation.severity !== 'high')
        return null;
    return {
        attackId: violation.violationId,
        attackType: 'atomicity-violation',
        title: `Atomicity Violation: ${violation.splitOperation}`,
        severity: violation.severity,
        targetContract: violation.funcA.split('.')[0],
        targetFunctions: [violation.funcA, violation.funcB],
        targetVariables: [violation.sharedVariable],
        entryPoint: {
            function: violation.funcA.split('.')[1],
            contract: violation.funcA.split('.')[0],
            isPermissionless: true,
            accessControl: 'public'
        },
        attackSteps: [
            {
                stepOrder: 1,
                action: 'Call first function to initiate state change',
                function: violation.funcA.split('.')[1],
                variable: violation.sharedVariable,
                manipulation: `Trigger ${violation.funcA} to begin operation on ${violation.sharedVariable}`,
                successCondition: 'Function executes successfully, state change initiated',
                failureMode: 'Function reverts due to validation'
            },
            {
                stepOrder: 2,
                action: 'Call second function before consistency check',
                function: violation.funcB.split('.')[1],
                variable: violation.sharedVariable,
                manipulation: `Immediately call ${violation.funcB} which reads/modifies ${violation.sharedVariable} in inconsistent state`,
                successCondition: 'Second function executes on stale/corrupted state',
                failureMode: 'State already updated or lock detected'
            },
            {
                stepOrder: 3,
                action: 'Extract value from inconsistent state',
                manipulation: 'Profit from the atomicity gap - double-spend, drain funds, or corrupt accounting',
                successCondition: 'Funds extracted or state corrupted to attacker advantage',
                failureMode: 'Transaction reverts or changes are minimal'
            }
        ],
        prerequisites: [
            {
                prerequisite: 'Both functions must be callable by attacker',
                category: 'access',
                satisfiable: true,
                howToAchieve: 'Both are permissionless (public)',
                difficulty: 'trivial'
            },
            {
                prerequisite: 'Timing: second call must happen before first completes',
                category: 'timing',
                satisfiable: true,
                howToAchieve: 'Use same transaction (reentrancy) or front-run in mempool',
                difficulty: 'easy'
            }
        ],
        impact: {
            potentialLoss: 'Up to total value in ' + violation.sharedVariable,
            affectedUsers: 'multiple',
            fundDrainagePossible: true,
            stateCorruptionPossible: true
        },
        trackatorEvidence: {},
        feasibility: {
            complexity: !violation.hasReentrancyGuard.funcA && !violation.hasReentrancyGuard.funcB ? 'easy' : 'moderate',
            estimatedGasCost: '< 500k gas (two function calls)',
            requiredCapital: '< $100 (gas only)',
            detectionRisk: 'medium'
        },
        mitigation: [violation.recommendedFix]
    };
}
// -----------------------------------------------------------
// TOCTOU ATTACK GENERATION
// -----------------------------------------------------------
function isTemporalCoupling(coupling) {
    const temporalTypes = [
        'timestamp-dependent',
        'callback-state-dependence',
        'multi-contract-consistency',
        'protocol-dependent'
    ];
    return temporalTypes.includes(coupling.type);
}
function buildTOCTOUAttack(coupling, _couplingResult) {
    // Determine time window characteristics
    let timeWindowExists = true;
    let triggerCondition = '';
    switch (coupling.type) {
        case 'timestamp-dependent':
            triggerCondition = 'block.timestamp changes between operations';
            break;
        case 'callback-state-dependence':
            triggerCondition = 'external callback modifies state mid-execution';
            break;
        case 'multi-contract-consistency':
            triggerCondition = 'cross-contract state drift occurs';
            break;
        default:
            timeWindowExists = false;
    }
    // Determine severity
    let severity = 'medium';
    if (coupling.severity === 'critical' || coupling.detectionConfidence === 'certain') {
        severity = 'critical';
    }
    else if (coupling.severity === 'high' || coupling.detectionConfidence === 'likely') {
        severity = 'high';
    }
    return {
        attackId: `TOCTOU_${coupling.id}`,
        sourceCoupling: coupling,
        timeWindow: {
            exists: timeWindowExists,
            triggerCondition,
            windowMs: undefined // Would be calculated from specific protocol logic
        },
        attackSequence: {
            step1: {
                action: `Manipulate state that ${coupling.target.function || 'target function'} depends on`,
                timing: 'T+0 (initial state setup)'
            },
            step2: {
                action: `Trigger ${coupling.source.function || 'source function'} with now-stale assumption`,
                timing: 'T+ε (after state changed but before detected)'
            },
            step3: coupling.mechanism.includes('callback')
                ? {
                    action: 'Execute malicious callback during execution gap',
                    timing: 'T+δ (during external call)'
                }
                : undefined
        },
        requiredConditions: [
            `Ability to call ${coupling.source.contract}.${coupling.source.function || 'source'}`,
            `State can be manipulated between check and use`,
            coupling.detectionConfidence !== 'certain' ? 'Assumption remains undetected' : 'No freshness verification exists'
        ].filter(Boolean),
        severity,
        detectionDifficulty: coupling.detectionConfidence === 'speculative' ? 'hard' :
            coupling.detectionConfidence === 'possible' ? 'moderate' : 'easy'
    };
}
function buildTOCTOUWeaponizedAttack(toctou, _couplingResult) {
    const coupling = toctou.sourceCoupling;
    return {
        attackId: `WA_${toctou.attackId}`,
        attackType: 'temporal-coupling-exploit',
        title: `TOCTOU Exploit via ${coupling.type.replace(/-/g, ' ')}`,
        severity: toctou.severity,
        targetContract: coupling.target.contract || coupling.source.contract,
        targetFunctions: [
            coupling.source.function || '',
            coupling.target.function || ''
        ].filter(Boolean),
        targetVariables: coupling.sharedState || [],
        entryPoint: {
            function: coupling.source.function || 'unknown',
            contract: coupling.source.contract,
            isPermissionless: true, // Assume for TOCTOU
            accessControl: 'public'
        },
        attackSteps: [
            {
                stepOrder: 1,
                action: 'Set up initial state that passes validation checks',
                manipulation: `Establish state conditions that ${coupling.target.function} will assume are valid`,
                successCondition: 'Initial state accepted by validation',
                failureMode: 'Validation rejects initial state'
            },
            {
                stepOrder: 2,
                action: 'Modify state between validation and usage',
                variable: coupling.sharedState?.[0],
                manipulation: `Change ${coupling.sharedState?.[0] || 'shared state'} after check but before use`,
                successCondition: 'State modification not detected',
                failureMode: 'Freshness check or re-validation catches change'
            },
            {
                stepOrder: 3,
                action: 'Trigger vulnerable function with stale state assumption',
                function: coupling.target.function,
                manipulation: `${coupling.target.function} operates on outdated state, producing incorrect result`,
                successCondition: 'Incorrect calculation benefits attacker',
                failureMode: 'Function detects inconsistency and reverts'
            }
        ],
        prerequisites: toctou.requiredConditions.map((req, i) => ({
            prerequisite: req,
            category: i === 0 ? 'access' : i === 1 ? 'state' : 'external',
            satisfiable: true,
            howToAchieve: i === 0 ? 'Direct call if permissionless' :
                i === 1 ? 'Front-run or use callback' :
                    'Manipulate external dependency',
            difficulty: 'easy'
        })),
        impact: {
            potentialLoss: 'Protocol-dependent (oracle/price exploits can be catastrophic)',
            affectedUsers: 'multiple',
            fundDrainagePossible: coupling.description.toLowerCase().includes('fund') ||
                coupling.description.toLowerCase().includes('balance'),
            stateCorruptionPossible: true
        },
        trackatorEvidence: {
            hiddenCoupling: coupling
        },
        feasibility: {
            complexity: toctou.detectionDifficulty === 'hard' ? 'easy' :
                toctou.detectionDifficulty === 'moderate' ? 'moderate' : 'difficult',
            estimatedGasCost: '< 300k gas',
            requiredCapital: '< $10,000 (may need flash loan)',
            detectionRisk: toctou.detectionDifficulty === 'hard' ? 'low' : 'medium'
        },
        mitigation: [
            coupling.recommendation,
            'Implement fresh data checks (timestamp/blocknumber validation)',
            'Use re-verification pattern: check-act-check instead of check-act'
        ],
        historicalPrecedent: coupling.type === 'callback-state-dependence' ? {
            exploitName: 'Flash Loan Oracle Manipulation',
            protocol: 'bZx Protocol / Harvest Finance',
            year: 2020,
            lossUsd: '$32M+',
            similarityDescription: 'Similar callback-state-dependency pattern exploited via flash loans'
        } : undefined
    };
}
// -----------------------------------------------------------
// CLUSTER EXPLOIT GENERATION
// -----------------------------------------------------------
function buildClusterExploit(cluster, _couplingResult) {
    // Find permissionless functions in cluster
    const permissionlessFuncs = cluster.functions.filter(f => {
        const funcInfo = f.split('.');
        return funcInfo.length === 2; // Basic format check
    });
    // Identify vulnerable variables
    const vulnerableVars = cluster.sharedVariables.filter(v => /balance|supply|collateral|debt|reserve|total|price|oracle/i.test(v));
    return {
        exploitId: `CE_${cluster.clusterId}`,
        couplingCluster: cluster,
        exploitationVector: `High-cohesion cluster (${cluster.functions.length} functions, ${cluster.sharedVariables.length} shared variables) creates complex attack surface`,
        attackSurface: {
            entryPoints: permissionlessFuncs,
            vulnerableVariables: vulnerableVars,
            missingChecks: [
                'Cross-function state consistency not enforced',
                'No cluster-level mutex or locking',
                'Individual function checks don\'t account for cluster interactions'
            ]
        },
        payloadConstruction: `Construct transaction sequence that traverses multiple functions in cluster, accumulating state modifications that individually pass checks but collectively violate invariants`,
        profitExtraction: vulnerableVars.length > 0
            ? `Extract value from ${vulnerableVars.join(', ')} through coordinated multi-function exploitation`
            : 'Protocol-level impact (DoS, governance capture)',
        estimatedValueAtRisk: cluster.riskLevel === 'critical' ? '> $1M possible' :
            cluster.riskLevel === 'high' ? '$100K - $1M possible' :
                '< $100K possible'
    };
}
function buildClusterAttack(exploit, _couplingResult) {
    return {
        attackId: `WA_${exploit.exploitId}`,
        attackType: 'state-cascade-corruption',
        title: `Cascade Corruption via ${exploit.couplingCluster.clusterId} Cluster`,
        severity: exploit.couplingCluster.riskLevel === 'critical' ? 'critical' : 'high',
        targetContract: exploit.couplingCluster.functions[0]?.split('.')[0] || 'unknown',
        targetFunctions: exploit.couplingCluster.functions,
        targetVariables: exploit.attackSurface.vulnerableVariables,
        entryPoint: {
            function: exploit.attackSurface.entryPoints[0]?.split('.')[1] || 'cluster-entry',
            contract: exploit.couplingCluster.functions[0]?.split('.')[0] || 'unknown',
            isPermissionless: true,
            accessControl: 'public'
        },
        attackSteps: [
            {
                stepOrder: 1,
                action: 'Identify cluster entry point and initial state requirements',
                manipulation: 'Map all functions in cluster and their shared variable dependencies',
                successCondition: 'Entry point accessible and initial state achievable',
                failureMode: 'Access control blocks entry or state unachievable'
            },
            {
                stepOrder: 2,
                action: 'Execute first function to modify shared state',
                manipulation: 'Change shared variable in way that passes local validation',
                successCondition: 'State modified, no revert',
                failureMode: 'Validation catches invalid state'
            },
            {
                stepOrder: 3,
                action: 'Chain into second function using modified state',
                manipulation: 'Second function sees modified state, makes different decision than expected',
                successCondition: 'Cascading effect begins',
                failureMode: 'Second function has independent check that fails'
            },
            {
                stepOrder: 4,
                action: 'Continue through cluster until invariant violated or value extracted',
                manipulation: 'Each function amplifies the state deviation',
                successCondition: 'Final state allows fund extraction or critical invariant broken',
                failureMode: 'Some function in chain has robust check that stops cascade'
            }
        ],
        prerequisites: [
            {
                prerequisite: 'Access to at least one cluster entry point',
                category: 'access',
                satisfiable: true,
                howToAchieve: 'Use permissionless function or compromise privileged one',
                difficulty: 'easy'
            },
            {
                prerequisite: 'Understanding of cluster interaction patterns',
                category: 'external',
                satisfiable: true,
                howToAchieve: 'Static analysis + testing to map state flows',
                difficulty: 'moderate'
            }
        ],
        impact: {
            potentialLoss: exploit.estimatedValueAtRisk,
            affectedUsers: 'all',
            fundDrainagePossible: exploit.attackSurface.vulnerableVariables.length > 0,
            stateCorruptionPossible: true
        },
        trackatorEvidence: {},
        feasibility: {
            complexity: 'moderate',
            estimatedGasCost: '500k - 2M gas (multi-function chain)',
            requiredCapital: '< $5,000 (may need initial position)',
            detectionRisk: 'medium'
        },
        mitigation: [
            'Add cluster-level invariants that span all functions',
            'Implement mutex/lock for critical shared variables',
            'Reduce cluster cohesion by decoupling shared state',
            'Add cross-function state validation'
        ]
    };
}
// -----------------------------------------------------------
// INVARIANT VIOLATION ATTACK GENERATION
// -----------------------------------------------------------
function buildInvariantViolationAttack(vPath, _couplingResult) {
    return {
        attackId: `WA_INV_${vPath.pathId}`,
        attackType: 'invariant-violation-chain',
        title: `Invariant Violation: ${vPath.invariantId}`,
        severity: vPath.feasibility === 'trivial' ? 'critical' : 'high',
        targetContract: vPath.entryFunction.split('.')[0],
        targetFunctions: vPath.executionSteps.map(s => s.function).filter(Boolean),
        targetVariables: vPath.executionSteps.map(s => s.variable).filter(Boolean),
        entryPoint: {
            function: vPath.entryFunction.split('.')[1],
            contract: vPath.entryFunction.split('.')[0],
            isPermissionless: true,
            accessControl: 'public'
        },
        attackSteps: vPath.executionSteps.map((step, idx) => ({
            stepOrder: idx + 1,
            action: step.action,
            function: step.function,
            variable: step.variable,
            manipulation: step.assumptionMade ? `Violate assumption: ${step.assumptionMade}` : 'Execute step',
            successCondition: step.couldFail === false ? 'Step succeeds normally' : 'Step might fail but continues',
            failureMode: step.failureMode || 'Execution stops'
        })),
        prerequisites: vPath.prerequisiteState.map(state => ({
            prerequisite: state,
            category: 'state',
            satisfiable: true,
            howToAchieve: 'Set up required state through normal protocol operations',
            difficulty: vPath.feasibility === 'trivial' ? 'trivial' : 'easy'
        })),
        impact: {
            potentialLoss: vPath.impactIfViolated,
            affectedUsers: 'multiple',
            fundDrainagePossible: vPath.impactIfViolated.toLowerCase().includes('loss') ||
                vPath.impactIfViolated.toLowerCase().includes('drain'),
            stateCorruptionPossible: true
        },
        trackatorEvidence: {
            invariantViolation: vPath
        },
        feasibility: {
            complexity: vPath.feasibility,
            estimatedGasCost: '< 400k gas',
            requiredCapital: '< $1,000',
            detectionRisk: 'medium'
        },
        mitigation: [
            'Add explicit invariant checks at critical points',
            'Use modifiers to enforce invariants automatically',
            'Implement circuit-breaker pattern for invariant violations'
        ]
    };
}
// -----------------------------------------------------------
// REDTEAM-OPTIMIZED OUTPUT BUILDER
// -----------------------------------------------------------
function buildRedteamOptimizedAttacks(attacks, atomicityViolations, toctouAttacks, _couplingExploits, _couplingResult) {
    // Build attack surface items
    const attackSurfaceItems = attacks.map(attack => ({
        targetId: attack.attackId,
        function: attack.entryPoint.function,
        contract: attack.entryPoint.contract,
        vulnerabilityType: attack.attackType,
        exploitComplexity: attack.feasibility.complexity,
        estimatedProfit: attack.impact.potentialLoss,
        priority: attack.severity === 'critical' ? 'P0-Critical' :
            attack.severity === 'high' ? 'P1-High' :
                attack.severity === 'medium' ? 'P2-Medium' : 'P3-Low',
        shouldInvestigate: attack.feasibility.complexity !== 'impossible'
    }));
    // Build ranked targets
    const rankedTargets = attackSurfaceItems
        .filter(item => item.shouldInvestigate)
        .map(item => {
        const exploitScore = item.exploitComplexity === 'trivial' ? 100 :
            item.exploitComplexity === 'easy' ? 85 :
                item.exploitComplexity === 'moderate' ? 60 :
                    item.exploitComplexity === 'difficult' ? 30 : 0;
        const impactScore = item.priority === 'P0-Critical' ? 100 :
            item.priority === 'P1-High' ? 80 :
                item.priority === 'P2-Medium' ? 50 : 25;
        return {
            rank: 0, // Will be set after sort
            target: `${item.contract}.${item.function}`,
            exploitabilityScore: exploitScore,
            impactScore: impactScore,
            combinedScore: Math.round(exploitScore * 0.6 + impactScore * 0.4), // Weight toward exploitability
            attackTypesAvailable: [item.vulnerabilityType],
            recommendedFirstAttack: item.vulnerabilityType,
            reason: `${item.vulnerabilityType}: ${item.estimatedProfit} at risk, ${item.exploitComplexity} complexity`
        };
    })
        .sort((a, b) => b.combinedScore - a.combinedScore)
        .map((t, idx) => ({ ...t, rank: idx + 1 }))
        .slice(0, 20); // Top 20 targets
    // Build quick attack patterns
    const attackPatterns = [
        {
            patternName: 'Atomicity Double-Spend',
            applicableTo: atomicityViolations.map(v => `${v.funcA}→${v.funcB}`),
            steps: [
                'Identify permissionless function pair sharing value-bearing variable',
                'Call function A to initiate state change',
                'Immediately call function B before consistency check',
                'Extract profit from inconsistent state'
            ],
            estimatedTimeToPoC: '2-4 hours',
            difficulty: 'intermediate'
        },
        {
            patternName: 'Oracle TOCTOU',
            applicableTo: toctouAttacks.filter(t => t.sourceCoupling.type === 'timestamp-dependent').map(t => t.sourceCoupling.id),
            steps: [
                'Find oracle/price dependency with stale data acceptance',
                'Set up favorable price condition',
                'Trigger price-dependent function before oracle updates',
                'Profit from price discrepancy'
            ],
            estimatedTimeToPoC: '4-8 hours',
            difficulty: 'advanced'
        },
        {
            patternName: 'Callback State Injection',
            applicableTo: toctouAttacks.filter(t => t.sourceCoupling.type === 'callback-state-dependence').map(t => t.sourceCoupling.id),
            steps: [
                'Identify external call with state dependency',
                'Prepare malicious callback contract',
                'Trigger parent function to make external call',
                'Inject state change during callback execution',
                'Parent function continues with corrupted state'
            ],
            estimatedTimeToPoC: '6-12 hours',
            difficulty: 'expert'
        },
        {
            patternName: 'Cluster Cascade',
            applicableTo: ['High-cohesion function clusters (3+ functions)'],
            steps: [
                'Map cluster functions and shared variables',
                'Identify permissionless entry point',
                'Plan state modification sequence',
                'Execute multi-function chain',
                'Amplify effect at each step'
            ],
            estimatedTimeToPoC: '8-16 hours',
            difficulty: 'expert'
        }
    ];
    // Build integration hints
    const integrationHints = [
        {
            category: 'entry-point',
            hint: 'Start with P0-Critical targets from rankedTargets array',
            trackatorField: 'redteamOptimizedOutput.rankedTargets',
            priority: 'critical'
        },
        {
            category: 'state-setup',
            hint: 'Use attackSteps[].prerequisites to determine required initial state',
            trackatorField: 'attackScenarios[].prerequisites',
            priority: 'high'
        },
        {
            category: 'trigger',
            hint: 'Build PoC following attackSteps[] sequence exactly',
            trackatorField: 'attackScenarios[].attackSteps',
            priority: 'critical'
        },
        {
            category: 'amplify',
            hint: 'For maximum impact, combine atomicity violation with reentrancy if guards missing',
            trackatorField: 'atomicityViolations[].hasReentrancyGuard',
            priority: 'high'
        },
        {
            category: 'extract',
            hint: 'Follow profitExtraction guidance from couplingExploits for value extraction',
            trackatorField: 'couplingExploits[].profitExtraction',
            priority: 'medium'
        }
    ];
    return {
        attackSurfaceSummary: attackSurfaceItems,
        rankedTargets,
        attackPatterns,
        integrationHints
    };
}
// -----------------------------------------------------------
// SUMMARY BUILDER
// -----------------------------------------------------------
function buildWeaponizationSummary(attacks, atomicityViolations, toctouAttacks, _couplingExploits) {
    const byType = {};
    for (const attack of attacks) {
        byType[attack.attackType] = (byType[attack.attackType] || 0) + 1;
    }
    const criticalCount = attacks.filter(a => a.severity === 'critical').length;
    const highCount = attacks.filter(a => a.severity === 'high').length;
    // Calculate average feasibility (invert complexity to score)
    const complexityScores = {
        trivial: 95, easy: 80, moderate: 60, difficult: 30, impossible: 0
    };
    const avgFeasibility = attacks.length > 0
        ? Math.round(attacks.reduce((sum, a) => sum + (complexityScores[a.feasibility.complexity] || 50), 0) / attacks.length)
        : 0;
    // Extract top targets
    const topTargets = attacks
        .filter(a => a.severity === 'critical')
        .map(a => `${a.targetContract}.${a.entryPoint.function}`)
        .slice(0, 5);
    return {
        totalAttacksGenerated: attacks.length,
        criticalAttacks: criticalCount,
        highSeverityAttacks: highCount,
        byAttackType: byType,
        averageFeasibilityScore: avgFeasibility,
        totalValueAtRisk: 'Protocol-dependent (see individual attack estimates)',
        topTargets
    };
}
// -----------------------------------------------------------
// EXPORT UTILITIES FOR REDTEAM INTEGRATION
// -----------------------------------------------------------
/**
 * Get only critical/P0 attacks for immediate attention
 */
function getCriticalAttacks(weaponized) {
    return weaponized.attackScenarios
        .filter(a => a.severity === 'critical')
        .sort((a, b) => b.feasibility.complexity.localeCompare(a.feasibility.complexity));
}
/**
 * Get easiest-to-exploit attacks (quick wins)
 */
function getQuickWinAttacks(weaponized) {
    const complexityOrder = {
        trivial: 5, easy: 4, moderate: 3, difficult: 2, impossible: 1
    };
    return weaponized.attackScenarios
        .filter(a => a.feasibility.complexity !== 'impossible')
        .sort((a, b) => (complexityOrder[b.feasibility.complexity] || 0) - (complexityOrder[a.feasibility.complexity] || 0))
        .slice(0, 10);
}
/**
 * Export weaponized results in JSON-complete format for Redteam consumption
 */
function exportWeaponizedResults(result) {
    return {
        timestamp: result.timestamp,
        summary: result.summary,
        redteamOptimizedOutput: result.redteamOptimizedOutput,
        attackScenarios: result.attackScenarios.map(a => ({
            attackId: a.attackId,
            attackType: a.attackType,
            title: a.title,
            severity: a.severity,
            targetContract: a.targetContract,
            targetFunctions: a.targetFunctions,
            targetVariables: a.targetVariables,
            entryPoint: a.entryPoint,
            attackSteps: a.attackSteps,
            impact: a.impact,
            feasibility: a.feasibility,
            mitigation: a.mitigation
        })),
        atomicityViolations: result.atomicityViolations,
        toctouAttacks: result.toctouAttacks.map(t => ({
            attackId: t.attackId,
            severity: t.severity,
            sourceCouplingType: t.sourceCoupling.type,
            attackSequence: t.attackSequence,
            requiredConditions: t.requiredConditions
        }))
    };
}
//# sourceMappingURL=state-coupling-detector.js.map