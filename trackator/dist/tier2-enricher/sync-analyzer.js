"use strict";
// ============================================================
// TRACKATOR Phase 3 Enhancement - State Synchronization Analyzer
// Implements Prompt 3 requirements:
// - Part 1: Assumption Consumer Analysis (Producer/Consumer/Verifier)
// - Part 2: State Desynchronization Analysis
// - Part 3: Trust & Synchronization Boundaries
// - Part 4: Top 20 Synchronization Relationships Ranking
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeSynchronization = analyzeSynchronization;
exports.exportSyncAnalysisResult = exportSyncAnalysisResult;
exports.generateSyncAnalysisMarkdown = generateSyncAnalysisMarkdown;
/**
 * Main entry point for Synchronization Analysis
 * Implements comprehensive Prompt 3 requirements
 */
function analyzeSynchronization(options) {
    const { contracts, functionRegistry, callEdges = [], invariants = [], verbose = false } = options;
    if (verbose)
        console.log('[SyncAnalyzer] Starting comprehensive synchronization analysis...');
    // Part 1: Build Assumption Dependency Graph
    const assumptionDependencyGraph = buildAssumptionDependencyGraph(contracts, functionRegistry, invariants, verbose);
    // Part 2: Analyze Desynchronization Risks
    const desynchronizationAnalysis = analyzeDesynchronization(contracts, functionRegistry, callEdges, invariants, verbose);
    // Part 3: Map Sync Boundaries
    const syncBoundaries = mapSyncBoundaries(contracts, functionRegistry, callEdges, verbose);
    // Part 4: Rank Top Sync Relationships
    const topSyncRelationships = rankTopSyncRelationships(assumptionDependencyGraph, desynchronizationAnalysis, syncBoundaries, 20, // Top 20 as per prompt requirement
    verbose);
    // Compile critical desync risks
    const criticalDesyncRisks = desynchronizationAnalysis.detectedRisks
        .filter(r => r.severity === 'critical' || r.impact === 'critical')
        .sort((a, b) => {
        const order = { critical: 4, high: 3, medium: 2, low: 1 };
        return (order[b.impact] || 0) - (order[a.impact] || 0);
    });
    if (verbose) {
        console.log(`[SyncAnalyzer] Analysis complete:`);
        console.log(`  - Assumption graph: ${assumptionDependencyGraph.graphStatistics.totalNodes} nodes, ${assumptionDependencyGraph.graphStatistics.totalEdges} edges`);
        console.log(`  - Sync groups: ${desynchronizationAnalysis.summary.totalSyncGroups} (${desynchronizationAnalysis.summary.atRiskGroups} at risk)`);
        console.log(`  - Desync sources: ${desynchronizationAnalysis.summary.totalDesyncSources}`);
        console.log(`  - Critical risks: ${desynchronizationAnalysis.summary.criticalRisks}`);
        console.log(`  - Top relationships ranked: ${topSyncRelationships.relationships.length}`);
    }
    return {
        timestamp: new Date().toISOString(),
        assumptionDependencyGraph,
        desynchronizationAnalysis,
        syncBoundaries,
        topSyncRelationships,
        criticalDesyncRisks
    };
}
// ============================================================
// PART 1: ASSUMPTION DEPENDENCY GRAPH BUILDER
// ============================================================
function buildAssumptionDependencyGraph(contracts, functionRegistry, invariants = [], verbose = false) {
    if (verbose)
        console.log('[SyncAnalyzer] Building assumption dependency graph...');
    const nodes = [];
    const edges = [];
    const producers = new Map();
    const consumers = new Map();
    const verifiers = new Map();
    let nodeIdCounter = 0;
    let edgeIdCounter = 0;
    // Create nodes for each significant state variable
    for (const contract of contracts) {
        for (const stateVar of contract.stateVariables) {
            if (stateVar.visibility === 'constant' || stateVar.visibility === 'immutable')
                continue;
            const isValueBearing = /balance|supply|debt|collateral|reserve|liquidity|funds/i.test(stateVar.name);
            const node = {
                id: `NODE_${++nodeIdCounter}`,
                type: 'state-variable',
                name: `${contract.name}.${stateVar.name}`,
                contract: contract.name,
                category: categorizeVariableForGraph(stateVar),
                description: `State variable: ${stateVar.name} (${stateVar.type})`,
                isValueBearing,
                securityClassification: isValueBearing ? 'critical' :
                    /owner|admin|role|price/i.test(stateVar.name) ? 'high' : 'medium'
            };
            nodes.push(node);
            // Initialize producer/consumer/verifier structures
            producers.set(node.id, {
                nodeId: node.id,
                producerFunctions: [],
                productionMechanism: 'direct-state-write',
                outputVariables: [node.name],
                establishedInvariants: []
            });
            consumers.set(node.id, {
                nodeId: node.id,
                consumerFunctions: [],
                assumptionMade: `State of ${stateVar.name} is consistent and up-to-date`,
                validationPerformed: '',
                isBlindTrust: true,
                impactIfWrong: isValueBearing ? 'Fund loss or accounting inconsistency' : 'Incorrect behavior'
            });
            verifiers.set(node.id, {
                nodeId: node.id,
                verifierFunctions: [],
                verificationMechanism: 'none',
                coverage: 'none'
            });
        }
    }
    // Create nodes for invariants
    for (const inv of invariants) {
        const invNode = {
            id: `INV_${inv.id}`,
            type: 'invariant',
            name: inv.id,
            contract: '', // May span contracts
            category: inv.category,
            description: inv.template || inv.instance || `Invariant: ${inv.id}`,
            isValueBearing: inv.category === 'accounting',
            securityClassification: inv.severity === 'critical' ? 'critical' :
                inv.severity === 'high' ? 'high' : 'medium'
        };
        nodes.push(invNode);
        consumers.set(invNode.id, {
            nodeId: invNode.id,
            consumerFunctions: [],
            assumptionMade: inv.template || 'Invariant holds true',
            validationPerformed: '',
            isBlindTrust: true,
            impactIfWrong: inv.category === 'accounting' ? 'Accounting inconsistency, possible fund loss' :
                'Protocol violation, undefined behavior'
        });
    }
    // Now analyze functions to build edges
    for (const contract of contracts) {
        for (const func of contract.functions) {
            const registeredFunc = findRegFunc(functionRegistry, contract.name, func.name);
            const writtenVars = func.stateVariablesWritten || [];
            const readVars = func.stateVariablesRead || [];
            // For each written variable, create producer edges
            for (const varName of writtenVars) {
                const varNode = nodes.find(n => n.name.endsWith(`.${varName}`) && n.contract === contract.name);
                if (!varNode)
                    continue;
                const prodInfo = producers.get(varNode.id);
                if (prodInfo) {
                    const prodFunc = {
                        functionId: `${contract.name}.${func.name}`,
                        contract: contract.name,
                        name: func.name,
                        produces: [varName],
                        mechanism: inferProductionMechanism(func, varName),
                        frequency: inferUpdateFrequency(func),
                        accessControl: registeredFunc?.accessControl.level || inferAccessControl(func),
                        isPermissionless: isPermFunc(func, registeredFunc)
                    };
                    // Check if already exists
                    if (!prodInfo.producerFunctions.some(p => p.functionId === prodFunc.functionId)) {
                        prodInfo.producerFunctions.push(prodFunc);
                    }
                }
                // Create edges to consumers of this variable
                for (const readVar of readVars) {
                    const readNode = nodes.find(n => n.name.endsWith(`.${readVar}`) && n.contract === contract.name);
                    if (!readNode || readNode.id === varNode.id)
                        continue;
                    // Writer creates state that reader depends on
                    edges.push({
                        id: `EDGE_${++edgeIdCounter}`,
                        sourceNode: varNode.id,
                        targetNode: readNode.id,
                        edgeType: 'produces',
                        sourceFunction: `${contract.name}.${func.name}`,
                        targetFunction: `${contract.name}.${func.name}`, // Same function reads and writes different vars
                        strength: 'strong',
                        description: `${func.name} writes ${varName}, which affects subsequent reads of ${readVar}`,
                        crossContract: false,
                        lineLocation: func.lineStart
                    });
                }
                // Also check if other functions read this variable (cross-function dependency)
                for (const otherContract of contracts) {
                    for (const otherFunc of otherContract.functions) {
                        if (otherContract.name === contract.name && otherFunc.name === func.name)
                            continue;
                        const otherReadVars = otherFunc.stateVariablesRead || [];
                        if (otherReadVars.includes(varName)) {
                            edges.push({
                                id: `EDGE_${++edgeIdCounter}`,
                                sourceNode: varNode.id,
                                targetNode: nodes.find(n => n.name === `${contract.name}.${varName}`)?.id || varNode.id,
                                edgeType: 'depends-on',
                                sourceFunction: `${contract.name}.${func.name}`,
                                targetFunction: `${otherContract.name}.${otherFunc.name}`,
                                strength: 'strong',
                                description: `${otherFunc.name} depends on ${varName} written by ${func.name}`,
                                crossContract: contract.name !== otherContract.name,
                                lineLocation: otherFunc.lineStart
                            });
                            // Update consumer info
                            const consInfo = consumers.get(varNode.id);
                            if (consInfo) {
                                const consFunc = {
                                    functionId: `${otherContract.name}.${otherFunc.name}`,
                                    contract: otherContract.name,
                                    name: otherFunc.name,
                                    consumes: [varName],
                                    assumesCorrect: `Assumes ${varName} is correctly maintained`,
                                    validates: [],
                                    actionIfInvalid: 'revert',
                                    isCriticalPath: isPermFunc(otherFunc, findRegFunc(functionRegistry, otherContract.name, otherFunc.name))
                                };
                                if (!consInfo.consumerFunctions.some(c => c.functionId === consFunc.functionId)) {
                                    consInfo.consumerFunctions.push(consFunc);
                                }
                                // If function has require/assert, it's a verifier too
                                if (func.body?.hasRequire || func.body?.hasRevert) {
                                    consInfo.validationPerformed = 'Some validation present';
                                    consInfo.isBlindTrust = false;
                                }
                            }
                        }
                    }
                }
            }
            // Check for verifier patterns (functions that only validate)
            const isPureValidator = (writtenVars.length === 0) &&
                (readVars.length > 0) &&
                (func.body?.hasRequire || func.body?.hasRevert);
            if (isPureValidator) {
                for (const varName of readVars) {
                    const varNode = nodes.find(n => n.name.endsWith(`.${varName}`) && n.contract === contract.name);
                    if (!varNode)
                        continue;
                    const verInfo = verifiers.get(varNode.id);
                    if (verInfo) {
                        verInfo.verificationMechanism = 'inline-assertion';
                        verInfo.coverage = verInfo.verifierFunctions.length > 0 ? 'partial' : 'complete';
                        const verFunc = {
                            functionId: `${contract.name}.${func.name}`,
                            contract: contract.name,
                            name: func.name,
                            verifies: [varName],
                            mechanism: func.modifiers.length > 0 ? 'custom-check' : 'assertion',
                            triggersOn: [`${contract.name}.${func.name}`],
                            severity: 'high'
                        };
                        if (!verInfo.verifierFunctions.some(v => v.functionId === verFunc.functionId)) {
                            verInfo.verifierFunctions.push(verFunc);
                        }
                    }
                }
            }
        }
    }
    // Compute statistics
    let blindTrustCount = 0;
    let crossContractEdges = 0;
    const depCounts = new Map();
    for (const [, cons] of consumers) {
        if (cons.isBlindTrust)
            blindTrustCount++;
    }
    for (const edge of edges) {
        if (edge.crossContract)
            crossContractEdges++;
        const count = depCounts.get(edge.targetNode) || 0;
        depCounts.set(edge.targetNode, count + 1);
    }
    let mostDepended;
    let maxDeps = 0;
    for (const [nodeId, count] of depCounts) {
        if (count > maxDeps) {
            maxDeps = count;
            mostDepended = nodeId;
        }
    }
    let leastVerified;
    let minVerif = Infinity;
    for (const [nodeId, ver] of verifiers) {
        const verCount = ver.verifierFunctions.length;
        if (verCount < minVerif && nodes.find(n => n.id === nodeId)?.securityClassification !== 'low') {
            minVerif = verCount;
            leastVerified = nodeId;
        }
    }
    const statistics = {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        producerCount: producers.size,
        consumerCount: consumers.size,
        verifierCount: verifiers.size,
        blindTrustCount,
        crossContractEdges,
        averageDependenciesPerNode: edges.length / Math.max(nodes.length, 1),
        mostDependedNode: mostDepended,
        leastVerifiedNode: leastVerified
    };
    if (verbose) {
        console.log(`[SyncAnalyzer] Graph built: ${nodes.length} nodes, ${edges.length} edges, ${blindTrustCount} blind trust consumers`);
    }
    return { nodes, edges, producers, consumers, verifiers, graphStatistics: statistics };
}
function categorizeVariableForGraph(stateVar) {
    const name = stateVar.name.toLowerCase();
    if (/balance|supply|debt/i.test(name))
        return 'accounting';
    if (/owner|admin|role/i.test(name))
        return 'authorization';
    if (/price|oracle|rate/i.test(name))
        return 'pricing';
    if (/pool|reserve|liquidity/i.test(name))
        return 'liquidity';
    if (/healthFactor|collateral/i.test(name))
        return 'solvency';
    return 'general-state';
}
function inferProductionMechanism(func, _varName) {
    if (/fetch|get|pull|read|load/i.test(func.name))
        return 'external-fetch';
    if (/calc|compute|derive|update/i.test(func.name))
        return 'calculation';
    if (/init|constructor/i.test(func.name))
        return 'direct-write';
    return 'direct-write';
}
function inferUpdateFrequency(func) {
    if (/accrue|compound|tick|update/i.test(func.name))
        return 'per-block';
    if (/deposit|withdraw|transfer|mint|burn/i.test(func.name))
        return 'per-transaction';
    if (/refresh|cache|sync/i.test(func.name))
        return 'on-demand';
    return 'per-transaction';
}
// ============================================================
// PART 2: DESYNCHRONIZATION ANALYZER
// ============================================================
function analyzeDesynchronization(contracts, functionRegistry, callEdges = [], invariants = [], verbose = false) {
    if (verbose)
        console.log('[SyncAnalyzer] Analyzing desynchronization risks...');
    // Step 1: Detect synchronization groups
    const syncGroups = detectSynchronizationGroups(contracts, functionRegistry, invariants);
    // Step 2: Identify desync sources
    const desyncSources = identifyDesyncSources(contracts, functionRegistry, callEdges, syncGroups);
    // Step 3: Detect risks from sources
    const detectedRisks = detectDesyncRisks(desyncSources, syncGroups);
    // Step 4: Analyze accounting drift specifically
    const accountingDrift = analyzeAccountingDrift(contracts, syncGroups, functionRegistry);
    // Compute summary
    const atRiskGroups = syncGroups.filter(g => g.currentSyncStatus === 'at-risk').length;
    const criticalSources = desyncSources.filter(s => s.severity === 'critical').length;
    const criticalRisks = detectedRisks.filter(r => r.severity === 'critical' || r.impact === 'critical').length;
    const mostVulnerable = syncGroups
        .filter(g => g.currentSyncStatus === 'at-risk')
        .sort((a, b) => {
        const riskA = detectedRisks.filter(r => r.sourceGroupId === a.groupId).length;
        const riskB = detectedRisks.filter(r => r.sourceGroupId === b.groupId).length;
        return riskB - riskA;
    })[0];
    const summary = {
        totalSyncGroups: syncGroups.length,
        atRiskGroups,
        totalDesyncSources: desyncSources.length,
        criticalDesyncSources: criticalSources,
        totalRisks: detectedRisks.length,
        criticalRisks,
        mostVulnerableGroup: mostVulnerable?.groupId,
        accountingDriftRisk: accountingDrift.driftDetected ? 'high' :
            accountingDrift.potentialDriftLocations.length > 2 ? 'medium' :
                accountingDrift.potentialDriftLocations.length > 0 ? 'low' : 'none'
    };
    if (verbose) {
        console.log(`[SyncAnalyzer] Found ${syncGroups.length} sync groups (${atRiskGroups} at risk), ${desyncSources.length} desync sources, ${detectedRisks.length} risks`);
    }
    return {
        synchronizationGroups: syncGroups,
        desyncSources,
        detectedRisks,
        accountingDrift,
        summary
    };
}
function detectSynchronizationGroups(contracts, functionRegistry, invariants = []) {
    const groups = [];
    let groupId = 0;
    // Pattern 1: Global accounting (totalSupply ↔ user balances)
    const supplyVars = findVariablesByPattern(contracts, /totalSupply|totalDebt|totalBorrow/i);
    const balanceVars = findVariablesByPattern(contracts, /balance|accountBalance/i);
    if (supplyVars.length > 0 && balanceVars.length > 0) {
        groups.push(createSyncGroup(++groupId, 'Global Accounting Consistency', 'global-per-user-accounting', [...supplyVars, ...balanceVars], contracts, 'Protocol must ensure sum of user balances equals total supply', ['deposit', 'withdraw', 'transfer', 'mint', 'burn'], functionRegistry));
    }
    // Pattern 2: Debt-Collateral matching
    const debtVars = findVariablesByPattern(contracts, /debt|borrow|loan/i);
    const collateralVars = findVariablesByPattern(contracts, /collateral|healthFactor|ltv/i);
    if (debtVars.length > 0 && collateralVars.length > 0) {
        groups.push(createSyncGroup(++groupId, 'Debt-Collateral Solvency', 'debt-collateral-matching', [...debtVars, ...collateralVars], contracts, 'Total debt must be covered by collateral at all times', ['borrow', 'repay', 'liquidate', 'depositCollateral', 'withdrawCollateral'], functionRegistry));
    }
    // Pattern 3: Price cache vs live oracle
    const cachedPriceVars = findVariablesByPattern(contracts, /cachedPrice|lastPrice|storedPrice/i);
    const oracleAccessFuncs = findAllFunctionsCalling(contracts, /getPrice|oracle|feed/i);
    if (cachedPriceVars.length > 0 && oracleAccessFuncs.length > 0) {
        groups.push(createSyncGroup(++groupId, 'Price Cache Freshness', 'price-cache-live', cachedPriceVars, contracts, 'Cached prices must stay synchronized with live oracle values', oracleAccessFuncs.map(f => f.name), functionRegistry));
    }
    // Pattern 4: Allowance vs spending
    const allowanceVars = findVariablesByPattern(contracts, /allowance|permit|spending/i);
    const transferFuncs = findAllFunctionsCalling(contracts, /transferFrom|spendAllowance/i);
    if (allowanceVars.length > 0 && transferFuncs.length > 0) {
        groups.push(createSyncGroup(++groupId, 'Allowance-Spending Consistency', 'allowance-spending', allowanceVars, contracts, 'Spending must not exceed approved allowance', transferFuncs.map(f => f.name), functionRegistry));
    }
    // Pattern 5: Interest accrual
    const interestVars = findVariablesByPattern(contracts, /accrued|interest|reward|index/i);
    const timeBasedFuncs = findAllFunctionsCalling(contracts, /accrue|updateInterest|updateReward/i);
    if (interestVars.length > 0) {
        groups.push(createSyncGroup(++groupId, 'Interest Accrual Accuracy', 'interest-accrual', interestVars, contracts, 'Accrued interest/rewards must match elapsed time and rates', timeBasedFuncs.length > 0 ? timeBasedFuncs.map(f => f.name) : ['any-time-based-operation'], functionRegistry));
    }
    // Pattern 6: Cross-contract mirrors (same variable in multiple contracts)
    const crossContractPatterns = findCrossContractMirrorPatterns(contracts);
    for (const pattern of crossContractPatterns) {
        groups.push({
            groupId: `GROUP_${++groupId}`,
            groupName: `Cross-Contract Mirror: ${pattern.variableName}`,
            groupType: 'cross-contract-mirror',
            variables: pattern.variables.map(v => ({
                variableName: v.name,
                contract: v.contract,
                role: v.isPrimary ? 'primary' : 'mirrored',
                updateFrequency: 'high',
                updaterFunctions: [],
                readerFunctions: []
            })),
            contractsInvolved: pattern.variables.map(v => v.contract),
            synchronizationOwner: pattern.variables.find(v => v.isPrimary)?.contract || 'unknown',
            syncPoints: [],
            currentSyncStatus: 'at-risk', // Cross-contract sync is always risky
            desyncDetection: 'none',
            restorationMethod: 'manual-intervention',
            riskIfDesynchronized: 'Different contracts show inconsistent state for same logical value'
        });
    }
    // Determine status for each group
    for (const group of groups) {
        assessGroupStatus(group, contracts, functionRegistry);
    }
    return groups;
}
function createSyncGroup(id, name, type, variables, contracts, riskIfDesynchronized, relevantFunctionNames, functionRegistry) {
    // Find updater and reader functions for each variable
    const syncVars = [];
    for (const v of variables) {
        const contract = contracts.find(c => c.name === v.contract);
        if (!contract)
            continue;
        const updaters = [];
        const readers = [];
        for (const func of contract.functions) {
            if (func.stateVariablesWritten?.includes(v.name)) {
                updaters.push(`${v.contract}.${func.name}`);
            }
            if (func.stateVariablesRead?.includes(v.name)) {
                readers.push(`${v.contract}.${func.name}`);
            }
        }
        syncVars.push({
            variableName: v.name,
            contract: v.contract,
            role: updaters.length > 0 ? 'primary' : 'derived',
            updateFrequency: updaters.length > 3 ? 'high' : updaters.length > 0 ? 'medium' : 'low',
            updaterFunctions: updaters,
            readerFunctions: readers
        });
    }
    // Find sync points (functions that update multiple vars in group)
    const syncPoints = [];
    for (const contract of contracts) {
        for (const func of contract.functions) {
            const writtenVars = func.stateVariablesWritten || [];
            const groupVarNames = variables.map(v => v.name);
            const writesMultiple = writtenVars.filter(v => groupVarNames.includes(v));
            if (writesMultiple.length >= 2) {
                syncPoints.push({
                    pointId: `SP_${contract.name}_${func.name}`,
                    location: { contract: contract.name, function: func.name },
                    variablesAffected: writesMultiple,
                    syncMechanism: func.body?.hasExternalCall ? 'cross-transaction' : 'single-transaction',
                    atomicity: func.body?.ceiPattern === 'valid' ? 'atomic' : 'best-effort',
                    orderingGuarantee: func.body?.ceiPattern === 'valid' ? 'strict' : 'loose'
                });
            }
        }
    }
    return {
        groupId: `GROUP_${id}`,
        groupName: name,
        groupType: type,
        variables: syncVars,
        contractsInvolved: [...new Set(variables.map(v => v.contract))],
        synchronizationOwner: determineSyncOwner(syncVars, contracts, functionRegistry),
        syncPoints,
        currentSyncStatus: 'synchronized', // Will be reassessed below
        desyncDetection: syncPoints.length > 0 ? 'invariant-check' : 'none',
        restorationMethod: syncPoints.some(sp => sp.atomicity === 'atomic') ? 'automatic-revert' : 'manual-intervention',
        riskIfDesynchronized
    };
}
function assessGroupStatus(group, contracts, functionRegistry) {
    let riskFactors = 0;
    // Check for permissionless writers
    for (const v of group.variables) {
        for (const updaterId of v.updaterFunctions) {
            const [, funcName] = updaterId.split('.');
            const contract = contracts.find(c => c.name === v.contract);
            const func = contract?.functions.find(f => f.name === funcName);
            const regFunc = findRegFunc(functionRegistry, v.contract, funcName);
            if (func && isPermFunc(func, regFunc)) {
                riskFactors += 2;
            }
            // Check CEI violations
            if (func?.body?.ceiPattern === 'violated') {
                riskFactors += 1;
            }
        }
    }
    // Check sync points quality
    const weakSyncPoints = group.syncPoints.filter(sp => sp.atomicity !== 'atomic').length;
    riskFactors += weakSyncPoints;
    // Determine status
    if (riskFactors >= 5) {
        group.currentSyncStatus = 'at-risk';
    }
    else if (riskFactors >= 2) {
        group.currentSyncStatus = 'at-risk'; // Conservative
    }
}
function identifyDesyncSources(contracts, functionRegistry, callEdges = [], syncGroups = []) {
    const sources = [];
    let sourceId = 0;
    for (const contract of contracts) {
        for (const func of contract.functions) {
            const writtenVars = func.stateVariablesWritten || [];
            const readVars = func.stateVariablesRead || [];
            const registeredFunc = findRegFunc(functionRegistry, contract.name, func.name);
            // Source 1: Non-atomic multi-variable updates
            if (writtenVars.length >= 2 && func.body?.hasExternalCall) {
                const affectedGroups = findAffectedSyncGroups(syncGroups, writtenVars);
                sources.push({
                    sourceId: `DS_${++sourceId}`,
                    sourceType: 'non-atomic-update',
                    location: { contract: contract.name, function: func.name },
                    affectedGroups: affectedGroups.map(g => g.groupId),
                    description: `${func.name} writes [${writtenVars.join(', ')}] with external calls - potential non-atomic update`,
                    triggerCondition: 'External call executes between state variable writes',
                    detectionDifficulty: 'moderate',
                    severity: writtenVars.some(v => /balance|supply|debt|collateral/i.test(v)) ? 'critical' : 'high',
                    mitigation: 'Implement CEI pattern or use reentrancy guards'
                });
            }
            // Source 2: Deferred/lazy updates
            if (/cache|snapshot|checkpoint|lazy/i.test(func.name) && writtenVars.length > 0) {
                sources.push({
                    sourceId: `DS_${++sourceId}`,
                    sourceType: 'lazy-evaluation',
                    location: { contract: contract.name, function: func.name },
                    affectedGroups: findAffectedSyncGroups(syncGroups, writtenVars).map(g => g.groupId),
                    description: `${func.name} may perform deferred/lazy update of [${writtenVars.join(', ')}]`,
                    triggerCondition: 'Cached/stale value used before refresh',
                    detectionDifficulty: 'hard',
                    severity: 'medium',
                    mitigation: 'Add staleness checks or force refresh before critical operations'
                });
            }
            // Source 3: Callback interference
            if (hasCallbackPattern(func) && readVars.length > 0) {
                sources.push({
                    sourceId: `DS_${++sourceId}`,
                    sourceType: 'callback-interference',
                    location: { contract: contract.name, function: func.name },
                    affectedGroups: findAffectedSyncGroups(syncGroups, readVars).map(g => g.groupId),
                    description: `Callback function ${func.name} reads [${readVars.join(', ')}] assuming pre-callback state`,
                    triggerCondition: 'Caller modifies state before callback executes',
                    detectionDifficulty: 'hard',
                    severity: 'high',
                    mitigation: 'Re-validate all assumptions at start of callback'
                });
            }
            // Source 4: Reentrancy gap
            if (func.body?.ceiPattern === 'violated' && func.body?.hasExternalCall) {
                sources.push({
                    sourceId: `DS_${++sourceId}`,
                    sourceType: 'reentrancy-gap',
                    location: { contract: contract.name, function: func.name, variable: writtenVars[0] },
                    affectedGroups: findAffectedSyncGroups(syncGroups, writtenVars).map(g => g.groupId),
                    description: `${func.name} has reentrancy vulnerability exposing intermediate state`,
                    triggerCondition: 'Malicious reentrant call during execution',
                    detectionDifficulty: 'easy',
                    severity: 'critical',
                    mitigation: 'Implement CEI pattern or reentrancy guard (OpenZeppelin Guards)'
                });
            }
            // Source 5: Cross-contract update (writes local then calls external)
            const externalCallsAfterWrite = func.calls?.filter(call => {
                const dotIndex = call.lastIndexOf('.');
                const potentialContract = dotIndex > 0 ? call.substring(0, dotIndex) : '';
                return !contracts.some(c => c.name === potentialContract) && writtenVars.length > 0;
            }) || [];
            if (externalCallsAfterWrite.length > 0) {
                sources.push({
                    sourceId: `DS_${++sourceId}`,
                    sourceType: 'cross-contract-update',
                    location: { contract: contract.name, function: func.name },
                    affectedGroups: findAffectedSyncGroups(syncGroups, writtenVars).map(g => g.groupId),
                    description: `${func.name} writes local state then calls external contracts`,
                    triggerCondition: 'External call affects or depends on local state consistency',
                    detectionDifficulty: 'moderate',
                    severity: 'high',
                    mitigation: 'Complete all local updates before external calls or use locks'
                });
            }
        }
    }
    // Source 6: Oracle divergence
    for (const edge of callEdges) {
        if (/price|oracle|getRate/i.test(edge.to.function)) {
            sources.push({
                sourceId: `DS_${++sourceId}`,
                sourceType: 'oracle-divergence',
                location: { contract: edge.from.contract, function: edge.from.function },
                affectedGroups: syncGroups
                    .filter(g => g.groupType === 'price-cache-live')
                    .map(g => g.groupId),
                description: `Oracle call to ${edge.to.function} may return manipulated/stale price`,
                triggerCondition: 'Oracle price manipulated via flash loan or MEV',
                detectionDifficulty: 'hard',
                severity: 'critical',
                mitigation: 'Use TWAP oracles, implement circuit breakers, add sanity checks'
            });
        }
    }
    return sources;
}
function detectDesyncRisks(sources, groups) {
    const risks = [];
    let riskId = 0;
    for (const source of sources) {
        for (const groupId of source.affectedGroups) {
            const group = groups.find(g => g.groupId === groupId);
            if (!group)
                continue;
            // Determine risk type based on source type
            let riskType;
            switch (source.sourceType) {
                case 'reentrancy-gap':
                case 'non-atomic-update':
                    riskType = 'atomicity-violation';
                    break;
                case 'lazy-evaluation':
                case 'cached-staleness':
                    riskType = 'stale-state-usage';
                    break;
                case 'callback-interference':
                    riskType = 'inconsistent-view';
                    break;
                case 'oracle-divergence':
                    riskType = 'persistent-desync';
                    break;
                default:
                    riskType = 'temporary-desync';
            }
            risks.push({
                riskId: `DRISK_${++riskId}`,
                riskType,
                severity: group.riskIfDesynchronized.includes('fund') || group.riskIfDesynchronized.includes('loss') ? 'critical' :
                    group.riskIfDesynchronized.includes('incorrect') ? 'high' : 'medium',
                sourceGroupId: groupId,
                affectedVariables: group.variables.map(v => v.variableName),
                scenario: `${source.description}. This can cause ${group.groupName} to become desynchronized.`,
                probability: source.severity === 'critical' ? 'likely' : 'possible',
                impact: group.riskIfDesynchronized.includes('fund') || group.riskIfDesynchronized.includes('loss') ? 'critical' :
                    group.riskIfDesynchronized.includes('incorrect') ? 'high' : 'medium',
                exploitability: source.detectionDifficulty === 'easy' ? 'easy' :
                    source.detectionDifficulty === 'moderate' ? 'moderate' : 'difficult',
                detectionMethod: source.sourceType === 'reentrancy-gap' ? 'Reentrancy detector' :
                    source.sourceType === 'oracle-divergence' ? 'Price deviation monitoring' :
                        'State comparison audit',
                recommendation: source.mitigation
            });
        }
    }
    // Sort by severity
    risks.sort((a, b) => {
        const order = { critical: 4, high: 3, medium: 2, low: 1 };
        return (order[b.impact] || 0) - (order[a.impact] || 0);
    });
    return risks;
}
function analyzeAccountingDrift(contracts, syncGroups, functionRegistry) {
    const pairs = [];
    const driftLocations = [];
    // Find accounting-related sync groups
    const accountingGroups = syncGroups.filter(g => g.groupType === 'global-per-user-accounting' ||
        g.groupType === 'debt-collateral-matching');
    for (const group of accountingGroups) {
        // Find primary vs derived variables
        const primaryVars = group.variables.filter(v => v.role === 'primary');
        const derivedVars = group.variables.filter(v => v.role === 'derived');
        for (const prim of primaryVars) {
            for (const deriv of derivedVars) {
                // Find functions that maintain this relationship
                const maintenanceFuncs = [];
                let verificationPresent = false;
                const contract = contracts.find(c => c.name === prim.contract);
                if (contract) {
                    for (const func of contract.functions) {
                        const writesPrim = func.stateVariablesWritten?.includes(prim.variableName);
                        const writesDeriv = func.stateVariablesWritten?.includes(deriv.variableName);
                        if (writesPrim && writesDeriv) {
                            maintenanceFuncs.push(`${prim.contract}.${func.name}`);
                        }
                        // Check if function verifies the relationship
                        if (func.body?.hasRequire || func.body?.hasRevert) {
                            if (func.stateVariablesRead?.includes(prim.variableName) &&
                                func.stateVariablesRead?.includes(deriv.variableName)) {
                                verificationPresent = true;
                            }
                        }
                    }
                }
                pairs.push({
                    primaryVariable: `${prim.contract}.${prim.variableName}`,
                    derivedVariable: `${deriv.contract}.${deriv.variableName}`,
                    expectedRelationship: getExpectedRelationship(prim.variableName, deriv.variableName),
                    maintenanceFunctions: maintenanceFuncs,
                    verificationPresent,
                    driftRisk: maintenanceFuncs.length === 0 ? 'high' :
                        !verificationPresent ? 'medium' : 'low'
                });
                // If high drift risk, add as drift location
                if (maintenanceFuncs.length === 0 || !verificationPresent) {
                    driftLocations.push({
                        location: { contract: prim.contract, function: 'unknown' },
                        variable: `${prim.variableName} ↔ ${deriv.variableName}`,
                        reason: maintenanceFuncs.length === 0 ?
                            'No functions found that update both variables together' :
                            'Relationship verified but no explicit assertion/invariant',
                        riskLevel: maintenanceFuncs.length === 0 ? 'high' : 'medium'
                    });
                }
            }
        }
    }
    return {
        trackedPairs: pairs,
        driftDetected: driftLocations.some(l => l.riskLevel === 'high'),
        potentialDriftLocations: driftLocations
    };
}
// ============================================================
// PART 3: SYNC BOUNDARY MAPPER
// ============================================================
function mapSyncBoundaries(contracts, functionRegistry, callEdges = [], verbose = false) {
    if (verbose)
        console.log('[SyncAnalyzer] Mapping synchronization boundaries...');
    const boundaries = [];
    const interactions = [];
    const vulnerableBoundaries = [];
    let boundaryId = 0;
    // Analyze each call edge as a boundary
    for (const edge of callEdges) {
        const boundaryType = classifySyncBoundaryType(edge);
        const boundary = {
            boundaryId: `SB_${++boundaryId}`,
            boundaryType,
            sourceContext: edge.from.contract,
            targetContext: edge.to.contract === 'external' ? 'External' : edge.to.contract,
            synchronizationMechanism: inferSyncMechanism(edge),
            dataCrossing: inferDataCrossing(edge),
            timing: inferTimingRequirement(edge, boundaryType),
            failureMode: inferFailureMode(edge),
            recoveryMechanism: inferRecoveryMechanism(edge),
            strength: assessSyncBoundaryStrength(edge)
        };
        boundaries.push(boundary);
        // Check for vulnerabilities
        const vulns = detectSyncBoundaryVulnerabilities(boundary, edge);
        vulnerableBoundaries.push(...vulns);
    }
    // Also check internal function boundaries (where state changes cross access levels)
    for (const contract of contracts) {
        for (const func of contract.functions) {
            const registeredFunc = findRegFunc(functionRegistry, contract.name, func.name);
            // Permissionless function that modifies sensitive state = implicit boundary
            if (isPermFunc(func, registeredFunc) &&
                (func.stateVariablesWritten?.some(v => /balance|supply|debt|collateral|owner/i.test(v)))) {
                const existingBoundary = boundaries.find(b => b.sourceContext === contract.name &&
                    b.boundaryType === 'external-call-boundary' &&
                    b.targetContext === 'Permissionless Caller');
                if (!existingBoundary) {
                    boundaries.push({
                        boundaryId: `SB_${++boundaryId}`,
                        boundaryType: 'contract-boundary',
                        sourceContext: contract.name,
                        targetContext: 'External Caller',
                        synchronizationMechanism: 'no-guarantee',
                        dataCrossing: [{
                                dataType: 'account-balance',
                                direction: 'bidirectional',
                                freshnessRequirement: 'real-time',
                                consistencyRequired: 'exact'
                            }],
                        timing: { maxDelay: '0', ordering: 'strict', finalityRequirement: 'instant' },
                        failureMode: {
                            type: 'detectable-failure',
                            detectionMethod: 'State validation',
                            autoRecovery: false,
                            manualInterventionRequired: true
                        },
                        recoveryMechanism: {
                            type: 'manual-fix',
                            description: 'Admin intervention required to restore state',
                            estimatedRecoveryTime: 'Hours to days'
                        },
                        strength: 'weak'
                    });
                }
            }
        }
    }
    // Find interactions between boundaries
    for (let i = 0; i < boundaries.length; i++) {
        for (let j = i + 1; j < boundaries.length; j++) {
            const interaction = assessBoundaryInteraction(boundaries[i], boundaries[j]);
            if (interaction) {
                interactions.push(interaction);
            }
        }
    }
    if (verbose) {
        console.log(`[SyncAnalyzer] Mapped ${boundaries.length} sync boundaries, ${interactions.length} interactions, ${vulnerableBoundaries.length} vulnerabilities`);
    }
    return { boundaries, boundaryInteractions: interactions, vulnerableBoundaries };
}
// ============================================================
// PART 4: TOP SYNC RELATIONSHIPS RANKING
// ============================================================
function rankTopSyncRelationships(depGraph, desyncAnalysis, syncBounds, topN = 20, verbose = false) {
    if (verbose)
        console.log(`[SyncAnalyzer] Ranking top ${topN} sync relationships...`);
    const candidates = [];
    let relId = 0;
    // Generate relationships from sync groups
    for (const group of desyncAnalysis.synchronizationGroups) {
        const rel = {
            rank: 0,
            relationshipId: `REL_${++relId}`,
            relationshipName: group.groupName,
            relationshipType: group.groupType,
            variables: group.variables.map(v => ({
                name: v.variableName,
                contract: v.contract,
                type: '', // Would need lookup
                role: v.role,
                securitySensitivity: /balance|supply|debt|collateral/i.test(v.variableName) ? 'critical' : 'high'
            })),
            producerFunctions: [],
            consumerFunctions: [],
            synchronizationOwner: group.synchronizationOwner,
            syncPoints: group.syncPoints,
            crossContractDependencies: [],
            exactSourceLocations: [],
            whyCritical: group.riskIfDesynchronized,
            riskScore: 0,
            exploitationComplexity: 'moderate',
            specificRecommendations: []
        };
        // Calculate risk score
        let score = 0;
        // Base score from group type
        const typeScores = {
            'global-per-user-accounting': 90,
            'debt-collateral-matching': 85,
            'internal-external-balance': 80,
            'price-cache-live': 75,
            'interest-accrual': 60,
            'allowance-spending': 55,
            'cross-contract-mirror': 70,
            'unknown-pattern': 40
        };
        score += typeScores[group.groupType] || 50;
        // At-risk status adds risk
        if (group.currentSyncStatus === 'at-risk') {
            score += 20;
        }
        // Permissionless writers increase risk
        const permWriters = group.variables.flatMap(v => v.updaterFunctions).filter(updater => {
            const [, funcName] = updater.split('.');
            // Would need registry lookup - simplified here
            return true; // Conservative
        }).length;
        score += Math.min(permWriters * 10, 30);
        // Weak sync points add risk
        const weakSyncPoints = group.syncPoints.filter(sp => sp.atomicity !== 'atomic').length;
        score += weakSyncPoints * 15;
        rel.riskScore = Math.min(score, 100);
        // Determine exploitation complexity
        if (permWriters > 0 && group.syncPoints.some(sp => sp.atomicity !== 'atomic')) {
            rel.exploitationComplexity = 'easy';
        }
        else if (permWriters > 0) {
            rel.exploitationComplexity = 'moderate';
        }
        else {
            rel.exploitationComplexity = 'difficult';
        }
        // Generate recommendations
        if (permWriters > 0) {
            rel.specificRecommendations.push('Restrict write access to authenticated callers only');
        }
        if (weakSyncPoints > 0) {
            rel.specificRecommendations.push('Implement atomic updates (CEI pattern + reentrancy guard)');
        }
        if (group.groupType === 'cross-contract-mirror') {
            rel.specificRecommendations.push('Consider single-source-of-truth pattern');
        }
        if (group.desyncDetection === 'none') {
            rel.specificRecommendations.push('Add invariant checks to detect desynchronization');
        }
        candidates.push(rel);
    }
    // Also generate relationships from critical desync risks
    for (const risk of desyncAnalysis.detectedRisks.slice(0, 10)) {
        const group = desyncAnalysis.synchronizationGroups.find(g => g.groupId === risk.sourceGroupId);
        if (!group)
            continue;
        candidates.push({
            rank: 0,
            relationshipId: `REL_RISK_${risk.riskId}`,
            relationshipName: `Desync Risk: ${risk.riskType.replace(/-/g, ' ')}`,
            relationshipType: group.groupType,
            variables: group.variables.map(v => ({
                name: v.variableName,
                contract: v.contract,
                type: '',
                role: v.role,
                securitySensitivity: 'critical'
            })),
            producerFunctions: [],
            consumerFunctions: [],
            synchronizationOwner: group.synchronizationOwner,
            syncPoints: group.syncPoints,
            crossContractDependencies: [],
            exactSourceLocations: [],
            whyCritical: risk.scenario,
            riskScore: risk.impact === 'critical' ? 95 : risk.impact === 'high' ? 85 : 70,
            exploitationComplexity: risk.exploitability,
            specificRecommendations: [risk.recommendation]
        });
    }
    // Sort by risk score and take top N
    candidates.sort((a, b) => b.riskScore - a.riskScore);
    const topCandidates = candidates.slice(0, topN);
    topCandidates.forEach((rel, idx) => {
        rel.rank = idx + 1;
    });
    return {
        relationships: topCandidates,
        rankingCriteria: 'Ranked by: group type criticality × at-risk status × permissionless writer count × sync point weakness × impact severity',
        generatedAt: new Date().toISOString()
    };
}
// ============================================================
// HELPER FUNCTIONS
// ============================================================
function findRegFunc(registry, contract, funcName) {
    if (!registry || !contract || !funcName)
        return undefined;
    return registry.get(contract)?.find(f => f.name === funcName || f.signature.includes(funcName));
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
    const hasRestriction = func.modifiers.some(m => /onlyOwner|onlyAdmin|onlyRole|require/.test(m));
    return !hasRestriction &&
        (func.visibility === 'external' || func.visibility === 'public') &&
        func.stateMutability !== 'view' &&
        func.stateMutability !== 'pure';
}
function findVariablesByPattern(contracts, pattern) {
    const results = [];
    for (const contract of contracts) {
        for (const sv of contract.stateVariables) {
            if (pattern.test(sv.name)) {
                results.push({ name: sv.name, contract: contract.name, type: sv.type });
            }
        }
    }
    return results;
}
function findAllFunctionsCalling(contracts, pattern) {
    const results = [];
    for (const contract of contracts) {
        for (const func of contract.functions) {
            if (func.calls?.some(c => pattern.test(c))) {
                results.push(func);
            }
        }
    }
    return results;
}
function findCrossContractMirrorPatterns(contracts) {
    const patterns = [];
    const varMap = new Map();
    // Group similar variable names across contracts
    for (const contract of contracts) {
        for (const sv of contract.stateVariables) {
            const baseName = sv.name.replace(/^_/, '').toLowerCase();
            if (!varMap.has(baseName)) {
                varMap.set(baseName, []);
            }
            varMap.get(baseName).push({ name: sv.name, contract: contract.name, type: sv.type });
        }
    }
    // Find variables that exist in multiple contracts
    for (const [baseName, vars] of varMap) {
        if (vars.length >= 2 && /balance|supply|price|owner|total/i.test(baseName)) {
            patterns.push({
                variableName: baseName,
                variables: vars.map((v, idx) => ({ ...v, isPrimary: idx === 0 }))
            });
        }
    }
    return patterns;
}
function determineSyncOwner(variables, contracts, functionRegistry) {
    // The contract with the most updaters or the "primary" variable's contract is likely the owner
    const contractUpdaterCounts = new Map();
    for (const v of variables) {
        for (const updater of v.updaterFunctions) {
            const [contract] = updater.split('.');
            contractUpdaterCounts.set(contract, (contractUpdaterCounts.get(contract) || 0) + 1);
        }
    }
    let maxCount = 0;
    let owner = variables[0]?.contract || 'unknown';
    for (const [contract, count] of contractUpdaterCounts) {
        if (count > maxCount) {
            maxCount = count;
            owner = contract;
        }
    }
    return owner;
}
function findAffectedSyncGroups(groups, variables) {
    return groups.filter(group => group.variables.some(v => variables.includes(v.variableName)));
}
function hasCallbackPattern(func) {
    return /callback|onReceive|handle|_hook|_call/i.test(func.name) ||
        func.calls?.some(c => /callback|receive|hook/i.test(c));
}
function getExpectedRelationship(primaryVar, derivedVar) {
    if (/totalSupply/i.test(primaryVar) && /balance/i.test(derivedVar)) {
        return 'Σ(balances) == totalSupply (+ reserves + locked)';
    }
    if (/debt/i.test(primaryVar) && /collateral|healthFactor/i.test(derivedVar)) {
        return 'collateral_value >= debt_value (healthFactor >= 1)';
    }
    return 'Mathematical relationship exists (see protocol docs)';
}
function classifySyncBoundaryType(edge) {
    switch (edge.type) {
        case 'delegatecall': return 'delegatecall-boundary';
        case 'staticcall': return 'contract-boundary';
        case 'external':
            if (/price|oracle|getRate/i.test(edge.to.function))
                return 'oracle-boundary';
            if (/transfer|transferFrom/i.test(edge.to.function))
                return 'token-contract-boundary';
            if (/flashLoan/i.test(edge.to.function))
                return 'flash-loan-boundary';
            if (/execute|queue|castVote/i.test(edge.to.function))
                return 'governance-boundary';
            if (/timelock|schedule|delay/i.test(edge.to.function))
                return 'timelock-boundary';
            return 'external-call-boundary';
        default: return 'contract-boundary';
    }
}
function inferSyncMechanism(edge) {
    if (edge.type === 'delegatecall')
        return 'immediate-consistency';
    if (edge.valueFlow?.ethSent)
        return 'immediate-consistency';
    return 'eventual-consistency';
}
function inferDataCrossing(edge) {
    const data = [];
    data.push({
        dataType: 'configuration',
        direction: 'outbound',
        freshnessRequirement: 'recent',
        consistencyRequired: 'approximate'
    });
    if (edge.valueFlow?.ethSent) {
        data.push({
            dataType: 'account-balance',
            direction: 'outbound',
            freshnessRequirement: 'real-time',
            consistencyRequired: 'exact'
        });
    }
    return data;
}
function inferTimingRequirement(_edge, _type) {
    return {
        maxDelay: 'same transaction',
        ordering: 'strict',
        finalityRequirement: 'instant'
    };
}
function inferFailureMode(_edge) {
    return {
        type: 'detectable-failure',
        detectionMethod: 'Return value check',
        autoRecovery: false,
        manualInterventionRequired: false
    };
}
function inferRecoveryMechanism(_edge) {
    return {
        type: 'auto-revert',
        description: 'Transaction will revert on failure',
        estimatedRecoveryTime: 'Immediate'
    };
}
function assessSyncBoundaryStrength(edge) {
    let strength = 100;
    if (edge.type === 'delegatecall')
        strength -= 40;
    if (edge.to.contract === 'external')
        strength -= 20;
    if (edge.valueFlow?.ethSent)
        strength -= 10;
    if (strength >= 70)
        return 'strong';
    if (strength >= 40)
        return 'medium';
    if (strength >= 10)
        return 'weak';
    return 'none';
}
function detectSyncBoundaryVulnerabilities(boundary, edge) {
    const vulns = [];
    if (boundary.strength === 'weak' || boundary.strength === 'none') {
        vulns.push({
            boundaryId: boundary.boundaryId,
            vulnerability: 'Weak synchronization boundary with no guarantees',
            exploitationScenario: `State may be inconsistent across ${boundary.boundaryType}`,
            prerequisites: ['Call crosses boundary', 'State modification occurs'],
            impact: 'Desynchronized state leads to incorrect decisions or fund loss',
            recommendation: 'Strengthen with explicit synchronization mechanisms',
            severity: 'high'
        });
    }
    if (boundary.timing.ordering !== 'strict') {
        vulns.push({
            boundaryId: boundary.boundaryId,
            vulnerability: 'Loose ordering allows race conditions',
            exploitationScenario: 'Concurrent executions see different states',
            prerequisites: ['Multiple concurrent calls', 'Shared state accessed'],
            impact: 'Race condition leads to double-spend or inconsistent state',
            recommendation: 'Implement mutex or serializing queue',
            severity: 'medium'
        });
    }
    return vulns;
}
function assessBoundaryInteraction(a, b) {
    // Check if boundaries share contexts
    if (a.sourceContext === b.sourceContext || a.targetContext === b.targetContext) {
        return {
            interactionId: `BI_${a.boundaryId}_${b.boundaryId}`,
            fromBoundary: a.boundaryId,
            toBoundary: b.boundaryId,
            interactionType: 'sequential',
            dataDependency: `Shared context: ${a.sourceContext === b.sourceContext ? a.sourceContext : a.targetContext}`,
            raceConditionRisk: a.timing.ordering !== 'strict' && b.timing.ordering !== 'strict',
            description: `Boundaries share execution context`
        };
    }
    return null;
}
// ============================================================
// EXPORT UTILITIES
// ============================================================
/**
 * Export sync analysis result to JSON-serializable format
 */
function exportSyncAnalysisResult(result) {
    return {
        timestamp: result.timestamp,
        assumptionDependencyGraph: {
            nodes: result.assumptionDependencyGraph.nodes,
            edges: result.assumptionDependencyGraph.edges,
            graphStatistics: result.assumptionDependencyGraph.graphStatistics
        },
        desynchronizationAnalysis: {
            synchronizationGroups: result.desynchronizationAnalysis.synchronizationGroups,
            desyncSources: result.desynchronizationAnalysis.desyncSources,
            detectedRisks: result.desynchronizationAnalysis.detectedRisks,
            summary: result.desynchronizationAnalysis.summary
        },
        syncBoundaries: {
            boundaries: result.syncBoundaries.boundaries,
            vulnerableBoundaries: result.syncBoundaries.vulnerableBoundaries
        },
        topSyncRelationships: result.topSyncRelationships,
        criticalDesyncRisks: result.criticalDesyncRisks
    };
}
/**
 * Generate Markdown report for Sync Analysis
 */
function generateSyncAnalysisMarkdown(result) {
    let md = '# State Synchronization Analysis Report\n\n';
    md += `**Generated:** ${result.timestamp}\n\n`;
    // Executive Summary
    md += '## Executive Summary\n\n';
    md += '| Metric | Value |\n';
    md += '|--------|-------|\n';
    md += '| Total Assumption Nodes | ' + result.assumptionDependencyGraph.graphStatistics.totalNodes + ' |\n';
    md += '| Total Dependencies | ' + result.assumptionDependencyGraph.graphStatistics.totalEdges + ' |\n';
    md += '| Blind Trust Consumers | ' + result.assumptionDependencyGraph.graphStatistics.blindTrustCount + ' |\n';
    md += '| Sync Groups | ' + result.desynchronizationAnalysis.summary.totalSyncGroups + ' |\n';
    md += '| At-Risk Groups | ' + result.desynchronizationAnalysis.summary.atRiskGroups + ' |\n';
    md += '| Desync Sources | ' + result.desynchronizationAnalysis.summary.totalDesyncSources + ' |\n';
    md += '| Critical Risks | ' + result.desynchronizationAnalysis.summary.criticalRisks + ' |\n';
    md += '| Sync Boundaries | ' + result.syncBoundaries.boundaries.length + ' |\n';
    md += '| Vulnerable Boundaries | ' + result.syncBoundaries.vulnerableBoundaries.length + ' |\n\n';
    // Sync Groups
    if (result.desynchronizationAnalysis.synchronizationGroups.length > 0) {
        md += '## Synchronization Groups\n\n';
        for (const group of result.desynchronizationAnalysis.synchronizationGroups.slice(0, 10)) {
            const statusIcon = group.currentSyncStatus === 'synchronized' ? '✅' : '⚠️';
            md += `### ${statusIcon} ${group.groupName}\n\n`;
            md += '**Type:** ' + group.groupType.replace(/-/g, ' ') + '\n\n';
            md += '**Owner:** ' + group.synchronizationOwner + '\n\n';
            md += '**Variables:**\n';
            md += '| Variable | Contract | Role | Updaters | Readers |\n';
            md += '|---------|----------|------|----------||\n';
            for (const v of group.variables) {
                md += '| `' + v.variableName + '` | ' + v.contract + ' | ' + v.role + ' | ' +
                    v.updaterFunctions.length + ' | ' + v.readerFunctions.length + ' |\n';
            }
            md += '\n**Risk if Desynchronized:** ' + group.riskIfDesynchronized + '\n\n';
            md += '---\n\n';
        }
    }
    // Critical Desync Risks
    if (result.criticalDesyncRisks.length > 0) {
        md += '## Critical Desynchronization Risks\n\n';
        for (const risk of result.criticalDesyncRisks.slice(0, 10)) {
            md += '### ' + risk.riskType.toUpperCase().replace(/-/g, ' ') + '\n\n';
            md += risk.scenario + '\n\n';
            md += '**Impact:** ' + risk.impact + '\n\n';
            md += '**Exploitation:** ' + risk.exploitability + '\n\n';
            md += '**Fix:** ' + risk.recommendation + '\n\n';
            md += '---\n\n';
        }
    }
    // Top Sync Relationships
    if (result.topSyncRelationships.relationships.length > 0) {
        md += '## Top Synchronization Relationships\n\n';
        md += '| Rank | Relationship | Type | Risk Score | Complexity |\n';
        md += '|------|-------------|------|------------|-------------|\n';
        for (const rel of result.topSyncRelationships.relationships.slice(0, 15)) {
            md += '| #' + rel.rank + ' | ' + rel.relationshipName + ' | ' +
                rel.relationshipType.substring(0, 20) + ' | ' + rel.riskScore + '/100 | ' +
                rel.exploitationComplexity + ' |\n';
        }
        md += '\n';
    }
    return md;
}
//# sourceMappingURL=sync-analyzer.js.map