"use strict";
// ============================================================
// TRACKATOR Phase 1 Enhancement - Storage Dependency Analyzer
// Implements Prompt 1 requirements:
// - Storage Write Graph (which functions modify same variables)
// - Shared-State Matrix (permissionless entry points × shared storage)
// - Per-Write Accounting Rule Explanation
// - Cross-Contract Storage Dependencies
// - Protocol Trust Boundaries from External Calls
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeStorageDependencies = analyzeStorageDependencies;
exports.exportStorageDependencyResult = exportStorageDependencyResult;
exports.generateStorageWriteGraphMermaid = generateStorageWriteGraphMermaid;
exports.generateStorageDependencyMarkdown = generateStorageDependencyMarkdown;
/**
 * Main entry point for Storage Dependency Analysis
 * Implements Prompt 1 requirements comprehensively
 */
function analyzeStorageDependencies(options) {
    const { contracts, functionRegistry, callEdges = [], invariants = [], includeTrustBoundaries = true, verbose = false } = options;
    if (verbose)
        console.log('[StorageDepAnalyzer] Starting comprehensive storage dependency analysis...');
    // Step 1: Build Storage Write Graph
    const storageWriteGraph = buildStorageWriteGraph(contracts, functionRegistry, invariants, verbose);
    // Step 2: Build Shared-State Matrix for permissionless entry points
    const sharedStateMatrix = buildSharedStateMatrix(contracts, functionRegistry, storageWriteGraph, callEdges, verbose);
    // Step 3: Generate per-write explanations
    const writeExplanations = generateWriteExplanations(storageWriteGraph, invariants, verbose);
    // Step 4: Build Trust Boundary Map (optional)
    let trustBoundaryMap;
    if (includeTrustBoundaries) {
        trustBoundaryMap = buildTrustBoundaryMap(contracts, functionRegistry, callEdges, verbose);
    }
    // Step 5: Compile high-risk findings
    const highRiskFindings = compileHighRiskFindings(storageWriteGraph, sharedStateMatrix, trustBoundaryMap, verbose);
    // Step 6: Generate recommendations
    const recommendations = generateRecommendations(highRiskFindings, storageWriteGraph, sharedStateMatrix);
    return {
        timestamp: new Date().toISOString(),
        storageWriteGraph,
        sharedStateMatrix,
        writeExplanations,
        trustBoundaryMap,
        highRiskFindings,
        recommendations
    };
}
// ============================================================
// STEP 1: STORAGE WRITE GRAPH BUILDER
// ============================================================
function buildStorageWriteGraph(contracts, functionRegistry, invariants = [], verbose = false) {
    if (verbose)
        console.log('[StorageDepAnalyzer] Building storage write graph...');
    const variableWriters = new Map();
    const multiWriterList = [];
    const contendedVars = [];
    // Process each contract
    for (const contract of contracts) {
        // Process each function's state writes
        for (const func of contract.functions) {
            const writtenVars = func.stateVariablesWritten || [];
            const readVars = func.stateVariablesRead || [];
            // Get registered function info for additional context
            const registeredFunc = findRegisteredFunction(functionRegistry, contract.name, func.name);
            // Track each written variable
            for (const varName of writtenVars) {
                const key = `${contract.name}.${varName}`;
                if (!variableWriters.has(key)) {
                    const stateVar = findStateVariable(contracts, contract.name, varName);
                    const relatedInvs = findRelatedInvariants(invariants, varName);
                    variableWriters.set(key, {
                        variableName: varName,
                        variableType: stateVar?.type || 'unknown',
                        contract: contract.name,
                        slot: stateVar?.slot,
                        writers: [],
                        readerFunctions: [],
                        isValueBearing: isValueBearingVariable(varName, stateVar),
                        accountingCategory: inferAccountingCategory(varName, stateVar),
                        relatedInvariants: relatedInvs
                    });
                }
                const varInfo = variableWriters.get(key);
                // Add writer info
                varInfo.writers.push({
                    functionName: func.name,
                    contract: contract.name,
                    visibility: func.visibility,
                    accessControl: registeredFunc?.accessControl.level || inferAccessControl(func),
                    isPermissionless: isPermissionlessFunction(func, registeredFunc),
                    ceiPattern: func.body?.ceiPattern || 'unknown',
                    externalCallsBeforeWrite: [], // Would need deeper AST analysis
                    externalCallsAfterWrite: [], // Would need deeper AST analysis
                    lineLocation: func.lineStart
                });
            }
            // Track readers for each variable
            for (const varName of readVars) {
                const key = `${contract.name}.${varName}`;
                if (variableWriters.has(key)) {
                    const varInfo = variableWriters.get(key);
                    const registeredFunc = findRegisteredFunction(functionRegistry, contract.name, func.name);
                    varInfo.readerFunctions.push({
                        functionName: func.name,
                        contract: contract.name,
                        visibility: func.visibility,
                        accessControl: registeredFunc?.accessControl.level || inferAccessControl(func),
                        lineLocation: func.lineStart
                    });
                }
                else {
                    // Variable is read but never written (might be constant or only written elsewhere)
                    const stateVar = findStateVariable(contracts, contract.name, varName);
                    variableWriters.set(key, {
                        variableName: varName,
                        variableType: stateVar?.type || 'unknown',
                        contract: contract.name,
                        slot: stateVar?.slot,
                        writers: [],
                        readerFunctions: [{
                                functionName: func.name,
                                contract: contract.name,
                                visibility: func.visibility,
                                accessControl: inferAccessControl(func),
                                lineLocation: func.lineStart
                            }],
                        isValueBearing: isValueBearingVariable(varName, stateVar),
                        accountingCategory: inferAccountingCategory(varName, stateVar),
                        relatedInvariants: findRelatedInvariants(invariants, varName)
                    });
                }
            }
            // Track multi-variable writers
            if (writtenVars.length >= 2) {
                multiWriterList.push({
                    functionName: func.name,
                    contract: contract.name,
                    variablesWritten: writtenVars,
                    writeCount: writtenVars.length,
                    hasMixedAccessControl: false, // Will be computed below
                    riskLevel: assessMultiWriterRisk(func, writtenVars)
                });
            }
        }
    }
    // Identify contended variables (written by multiple functions)
    for (const [key, varInfo] of variableWriters) {
        if (varInfo.writers.length >= 2) {
            const permissionlessWriters = varInfo.writers.filter(w => w.isPermissionless);
            contendedVars.push({
                variableName: varInfo.variableName,
                contract: varInfo.contract,
                writerCount: varInfo.writers.length,
                writerFunctions: varInfo.writers.map(w => w.functionName),
                permissionlessWriterCount: permissionlessWriters.length,
                hasCrossFunctionDependency: varInfo.readerFunctions.length > 0,
                riskScore: calculateContentionRisk(varInfo),
                synchronizationRequired: varInfo.isValueBearing ||
                    varInfo.accountingCategory === 'accounting' ||
                    varInfo.accountingCategory === 'conservation'
            });
        }
    }
    // Sort by risk score
    contendedVars.sort((a, b) => b.riskScore - a.riskScore);
    // Compute summary
    let totalWrites = 0;
    let totalReads = 0;
    let permissionlessWrites = 0;
    let valueBearingCount = 0;
    for (const [, varInfo] of variableWriters) {
        totalWrites += varInfo.writers.length;
        totalReads += varInfo.readerFunctions.length;
        permissionlessWrites += varInfo.writers.filter(w => w.isPermissionless).length;
        if (varInfo.isValueBearing)
            valueBearingCount++;
    }
    const summary = {
        totalVariablesTracked: variableWriters.size,
        totalWriteOperations: totalWrites,
        totalReadOperations: totalReads,
        contendedVariableCount: contendedVars.length,
        highRiskContentionCount: contendedVars.filter(v => v.riskScore >= 70).length,
        permissionlessWriteCount: permissionlessWrites,
        valueBearingVariableCount: valueBearingCount,
        crossContractDependencyCount: countCrossContractDeps(variableWriters, contracts)
    };
    if (verbose) {
        console.log(`[StorageDepAnalyzer] Graph built: ${variableWriters.size} variables, ${totalWrites} writes, ${contendedVars.length} contended`);
    }
    return {
        variableWriters,
        multiVariableWriters: multiWriterList,
        contentedVariables: contendedVars,
        summary
    };
}
// ============================================================
// STEP 2: SHARED STATE MATRIX BUILDER
// ============================================================
function buildSharedStateMatrix(contracts, functionRegistry, writeGraph, callEdges = [], verbose = false) {
    if (verbose)
        console.log('[StorageDepAnalyzer] Building shared-state matrix...');
    // Identify permissionless entry points
    const entryPoints = [];
    const allSharedVars = new Map();
    for (const contract of contracts) {
        for (const func of contract.functions) {
            // Check if this is a permissionless entry point
            const registeredFunc = findRegisteredFunction(functionRegistry, contract.name, func.name);
            if (isPermissionlessEntryPoint(func, registeredFunc)) {
                const writtenVars = func.stateVariablesWritten || [];
                const readVars = func.stateVariablesRead || [];
                const riskScore = assessEntryPointRisk(func, writtenVars, readVars);
                entryPoints.push({
                    functionName: func.name,
                    contract: contract.name,
                    fullSignature: `${contract.name}.${func.name}`,
                    access: 'permissionless',
                    variablesRead: readVars,
                    variablesWritten: writtenVars,
                    riskScore
                });
                // Track shared variables
                for (const varName of [...writtenVars, ...readVars]) {
                    const varKey = `${contract.name}.${varName}`;
                    if (!allSharedVars.has(varKey)) {
                        const stateVar = findStateVariable(contracts, contract.name, varName);
                        allSharedVars.set(varKey, {
                            variableName: varName,
                            contract: contract.name,
                            type: stateVar?.type || 'unknown',
                            isValueBearing: isValueBearingVariable(varName, stateVar),
                            totalReaders: 0,
                            totalWriters: 0,
                            entryPointReaders: 0,
                            entryPointWriters: 0,
                            syncCategory: inferSyncCategory(varName, stateVar)
                        });
                    }
                    const col = allSharedVars.get(varKey);
                    if (writtenVars.includes(varName)) {
                        col.entryPointWriters++;
                        col.totalWriters++;
                    }
                    if (readVars.includes(varName)) {
                        col.entryPointReaders++;
                        col.totalReaders++;
                    }
                }
            }
        }
    }
    // Build matrix cells
    const cells = new Map();
    let highRiskCells = 0;
    let criticalIntersections = 0;
    for (const ep of entryPoints) {
        const rowCells = new Map();
        for (const [varKey, varCol] of allSharedVars) {
            const isWritten = ep.variablesWritten.includes(varCol.variableName);
            const isRead = ep.variablesRead.includes(varCol.variableName);
            if (isWritten || isRead) {
                const depTypes = ['direct'];
                const riskFactors = [];
                // Assess risk factors
                if (isWritten && varCol.isValueBearing) {
                    riskFactors.push('writes-value-bearing-variable');
                    criticalIntersections++;
                }
                if (isWritten && varCol.totalWriters > 1) {
                    riskFactors.push('shared-write-access');
                }
                if (isRead && varCol.totalWriters > 0) {
                    riskFactors.push('reads-writable-state');
                }
                // Check CEI compliance
                const func = findFunction(contracts, ep.contract, ep.functionName);
                const ceiCompliant = func?.body?.ceiPattern === 'valid';
                // Check for external calls around this access
                const hasExternalCallBefore = false; // Would need deeper analysis
                const hasExternalCallAfter = false; // Would need deeper analysis
                if (riskFactors.length > 1)
                    highRiskCells++;
                rowCells.set(varKey, {
                    accessType: isWritten && isRead ? 'read-write' : isWritten ? 'write' : 'read',
                    dependencyType: depTypes,
                    riskFactors,
                    ceiCompliant,
                    hasExternalCallBefore,
                    hasExternalCallAfter
                });
            }
        }
        cells.set(ep.fullSignature, rowCells);
    }
    // Find weakest and most contended
    const weakestEntryPoint = entryPoints.reduce((max, ep) => ep.riskScore > max.riskScore ? ep : max, entryPoints[0]);
    const mostContendedVar = Array.from(allSharedVars.values()).reduce((max, v) => (v.totalWriters + v.totalReaders) > (max.totalWriters + max.totalReaders) ? v : max, Array.from(allSharedVars.values())[0] || { variableName: 'none', contract: '', type: '', isValueBearing: false, totalReaders: 0, totalWriters: 0, entryPointReaders: 0, entryPointWriters: 0 });
    const riskSummary = {
        highRiskCells,
        criticalIntersections,
        totalIntersectionPoints: highRiskCells + criticalIntersections,
        averageRiskPerEntryPoint: entryPoints.reduce((sum, ep) => sum + ep.riskScore, 0) / Math.max(entryPoints.length, 1),
        weakestEntryPoint: weakestEntryPoint ? { name: weakestEntryPoint.fullSignature, riskScore: weakestEntryPoint.riskScore } : undefined,
        mostContendedVariable: mostContendedVar && mostContendedVar.contract ? { name: `${mostContendedVar.contract}.${mostContendedVar.variableName}`, contentionScore: mostContendedVar.totalWriters + mostContendedVar.totalReaders } : undefined
    };
    if (verbose) {
        console.log(`[StorageDepAnalyzer] Matrix built: ${entryPoints.length} entry points, ${allSharedVars.size} shared variables, ${highRiskCells} high-risk cells`);
    }
    return {
        entryPoints,
        sharedVariables: Array.from(allSharedVars.values()),
        cells,
        riskSummary
    };
}
// ============================================================
// STEP 3: WRITE EXPLANATION GENERATOR
// ============================================================
function generateWriteExplanations(writeGraph, invariants = [], verbose = false) {
    if (verbose)
        console.log('[StorageDepAnalyzer] Generating write explanations...');
    const explanations = new Map();
    const unexplainedWrites = [];
    const discoveredRules = [];
    const ruleSet = new Set();
    for (const [varKey, varInfo] of writeGraph.variableWriters) {
        for (const writer of varInfo.writers) {
            const explainKey = `${writer.contract}.${writer.functionName}.${varInfo.variableName}`;
            // Infer reason category
            const reason = inferWriteReason(writer.functionName, varInfo.variableName, varInfo.variableType);
            // Generate explanation
            const explanation = generateNaturalLanguageExplanation(writer.functionName, varInfo.variableName, reason, writer.contract);
            // Find related accounting rule
            const rule = findOrCreateAccountingRule(varInfo.variableName, reason, writer.contract, writer.functionName, ruleSet, discoveredRules);
            // Determine atomicity requirement
            const atomicity = determineAtomicityRequirement(varInfo.variableName, reason, varInfo.isValueBearing);
            // Find related invariants
            const maintainedInv = varInfo.relatedInvariants.find(inv => couldMaintainInvariant(writer.functionName, inv, invariants));
            const violatedInv = varInfo.relatedInvariants.find(inv => couldViolateInvariant(writer.functionName, inv, invariants));
            // Describe state transition
            const stateTransition = describeStateTransition(writer.functionName, varInfo.variableName, reason);
            const writeExpl = {
                key: explainKey,
                contract: writer.contract,
                function: writer.functionName,
                variable: varInfo.variableName,
                reason,
                explanation,
                accountingRule: rule?.name,
                invariantMaintained: maintainedInv,
                invariantPotentiallyViolated: violatedInv,
                stateTransition,
                atomicityRequirement: atomicity
            };
            explanations.set(explainKey, writeExpl);
            // Track unexplained writes
            if (reason === 'unknown') {
                unexplainedWrites.push({
                    key: explainKey,
                    contract: writer.contract,
                    function: writer.functionName,
                    variable: varInfo.variableName,
                    suggestedAnalysis: 'Manual review required - could not automatically categorize this write operation'
                });
            }
        }
    }
    if (verbose) {
        console.log(`[StorageDepAnalyzer] Generated ${explanations.size} explanations, ${discoveredRules.length} rules, ${unexplainedWrites.length} unexplained`);
    }
    return {
        explanations,
        unexplainedWrites,
        discoveredRules
    };
}
// ============================================================
// STEP 4: TRUST BOUNDARY MAP BUILDER
// ============================================================
function buildTrustBoundaryMap(contracts, functionRegistry, callEdges = [], verbose = false) {
    if (verbose)
        console.log('[StorageDepAnalyzer] Building trust boundary map...');
    const boundaries = [];
    const crossBoundaryFlows = [];
    const vulnerableBoundaries = [];
    let boundaryId = 0;
    // Analyze call edges for trust boundaries
    for (const edge of callEdges) {
        const boundaryType = inferBoundaryType(edge);
        if (boundaryType) {
            const sourceFunc = findFunction(contracts, edge.from.contract, edge.from.function);
            const registeredSource = findRegisteredFunction(functionRegistry, edge.from.contract, edge.from.function);
            const isPermissionlessSource = sourceFunc ?
                isPermissionlessFunction(sourceFunc, registeredSource) : false;
            // Determine trust assumption
            const trustAssumption = inferTrustAssumption(edge, boundaryType);
            // Determine strength
            const strength = assessBoundaryStrength(edge, boundaryType, isPermissionlessSource);
            const boundary = {
                id: `TB_${++boundaryId}`,
                sourceContext: edge.from.contract,
                targetContext: edge.to.contract === 'external' ? 'External' : edge.to.contract,
                boundaryType,
                mechanism: edge.type,
                sourceContract: edge.from.contract,
                targetContract: edge.to.contract !== 'external' ? edge.to.contract : undefined,
                sourceFunction: edge.from.function,
                targetFunction: edge.to.function,
                trustAssumption,
                ifBreached: describeBoundaryBreachImpact(boundaryType, edge),
                strength,
                dataExposed: guessDataExposed(edge, sourceFunc),
                stateModified: hasStateModificationAcrossBoundary(sourceFunc, edge),
                ceiOrdering: assessCEIOrdering(sourceFunc, edge)
            };
            boundaries.push(boundary);
            // Check for vulnerabilities
            const vulns = detectBoundaryVulnerabilities(boundary, edge, sourceFunc);
            vulnerableBoundaries.push(...vulns);
            // Track cross-boundary flows
            if (edge.type === 'delegatecall') {
                crossBoundaryFlows.push({
                    fromBoundary: boundary.id,
                    toBoundary: '', // Would need matching analysis
                    dataType: 'state-reference',
                    description: `Full storage context shared via delegatecall to ${edge.to.function}`,
                    riskLevel: 'critical'
                });
            }
        }
    }
    // Also check individual functions for external calls
    for (const contract of contracts) {
        for (const func of contract.functions) {
            if (func.body?.hasExternalCall && func.body?.ceiPattern === 'violated') {
                // This function has potential trust boundary issue
                boundaries.push({
                    id: `TB_${++boundaryId}`,
                    sourceContext: contract.name,
                    targetContext: 'External (unknown)',
                    boundaryType: 'external-call',
                    mechanism: 'external-call',
                    sourceContract: contract.name,
                    sourceFunction: func.name,
                    trustAssumption: 'External call will not re-enter before state updates complete',
                    ifBreached: 'Reentrancy attack possible - state may be manipulated mid-execution',
                    strength: 'weak',
                    dataExposed: ['contract storage', 'execution context'],
                    stateModified: true,
                    ceiOrdering: 'unsafe'
                });
            }
        }
    }
    if (verbose) {
        console.log(`[StorageDepAnalyzer] Found ${boundaries.length} trust boundaries, ${vulnerableBoundaries.length} vulnerabilities`);
    }
    return {
        boundaries,
        crossBoundaryFlows,
        vulnerableBoundaries
    };
}
// ============================================================
// STEP 5 & 6: HIGH-RISK FINDINGS AND RECOMMENDATIONS
// ============================================================
function compileHighRiskFindings(writeGraph, matrix, trustMap, verbose = false) {
    const findings = [];
    let findingId = 0;
    // Check for contended value-bearing variables with permissionless writers
    for (const contended of writeGraph.contentedVariables) {
        if (contended.permissionlessWriterCount > 0 && contended.riskScore >= 70) {
            findings.push({
                id: `HRF_${++findingId}`,
                type: 'contention',
                severity: contended.riskScore >= 90 ? 'critical' : 'high',
                title: `High-contention value-bearing variable: ${contended.variableName}`,
                description: `Variable ${contended.variableName} in ${contended.contract} is written by ${contended.writerCount} functions including ${contended.permissionlessWriterCount} permissionless entry points`,
                location: { contract: contended.contract, variable: contended.variableName },
                evidence: [
                    `Writer functions: ${contended.writerFunctions.join(', ')}`,
                    `Permissionless writers: ${contended.permissionlessWriterCount}`,
                    `Risk score: ${contended.riskScore}/100`,
                    `Synchronization required: ${contended.synchronizationRequired}`
                ],
                recommendation: contended.synchronizationRequired
                    ? 'Implement reentrancy guards and consider mutex/locks for atomic updates'
                    : 'Review access control - some writers should likely be restricted'
            });
        }
    }
    // Check for CEI violations in matrix
    for (const [epKey, rowCells] of matrix.cells) {
        for (const [varKey, cell] of rowCells) {
            if (!cell.ceiCompliant && cell.accessType !== 'none') {
                findings.push({
                    id: `HRF_${++findingId}`,
                    type: 'cei-violation',
                    severity: 'high',
                    title: `CEI violation at ${epKey} → ${varKey}`,
                    description: `Entry point ${epKey} accesses ${varKey} without proper checks-effects-interactions ordering`,
                    location: {
                        contract: epKey.split('.')[0],
                        function: epKey.split('.')[1],
                        variable: varKey.split('.')[1]
                    },
                    evidence: [
                        `Access type: ${cell.accessType}`,
                        `Risk factors: ${cell.riskFactors.join(', ')}`
                    ],
                    recommendation: 'Reorder operations to perform external calls after all state updates'
                });
            }
        }
    }
    // Check trust boundary vulnerabilities
    if (trustMap) {
        for (const vuln of trustMap.vulnerableBoundaries) {
            findings.push({
                id: `HRF_${++findingId}`,
                type: 'trust-boundary',
                severity: vuln.severity,
                title: `Vulnerable trust boundary: ${vuln.boundaryId}`,
                description: vuln.vulnerability,
                location: { contract: vuln.boundaryId },
                evidence: [vuln.exploitationScenario],
                recommendation: vuln.recommendation
            });
        }
    }
    // Sort by severity
    findings.sort((a, b) => {
        const order = { critical: 4, high: 3, medium: 2, low: 1 };
        return order[b.severity] - order[a.severity];
    });
    if (verbose) {
        console.log(`[StorageDepAnalyzer] Compiled ${findings.length} high-risk findings`);
    }
    return findings;
}
function generateRecommendations(findings, writeGraph, matrix) {
    const recommendations = [];
    const seen = new Set();
    // Generate recommendations from findings
    for (const finding of findings) {
        const key = `${finding.type}:${finding.location.contract}`;
        if (seen.has(key))
            continue;
        seen.add(key);
        switch (finding.type) {
            case 'contention':
                recommendations.push({
                    priority: finding.severity === 'critical' ? 'immediate' : 'short-term',
                    category: 'access-control',
                    title: 'Restrict write access to contended variables',
                    description: `Implement stricter access control for writes to ${finding.location.variable}. Consider adding onlyRole modifiers or reentrancy guards.`,
                    affectedComponents: [finding.location.contract]
                });
                break;
            case 'cei-violation':
                recommendations.push({
                    priority: 'immediate',
                    category: 'reentrancy',
                    title: 'Fix CEI pattern violations',
                    description: 'Move all external calls to occur after state modifications to prevent reentrancy attacks.',
                    affectedComponents: [finding.location.contract, finding.location.function].filter(Boolean)
                });
                break;
            case 'trust-boundary':
                recommendations.push({
                    priority: finding.severity === 'critical' ? 'immediate' : 'short-term',
                    category: 'trust-boundary',
                    title: 'Harden trust boundary protections',
                    description: finding.recommendation,
                    affectedComponents: [finding.location.contract]
                });
                break;
        }
    }
    // Add general recommendations based on summary stats
    if (writeGraph.summary.highRiskContentionCount > 3) {
        recommendations.push({
            priority: 'short-term',
            category: 'architecture',
            title: 'Consider implementing mutex/lock pattern',
            description: `Multiple high-contention variables detected (${writeGraph.summary.highRiskContentionCount}). Consider implementing a mutex pattern or serializing state changes.`,
            affectedComponents: Array.from(new Set(writeGraph.contentedVariables.map(v => v.contract)))
        });
    }
    if (matrix.riskSummary.criticalIntersections > 5) {
        recommendations.push({
            priority: 'review',
            category: 'design-review',
            title: 'Review permissionless entry point surface area',
            description: `Many critical intersections (${matrix.riskSummary.criticalIntersections}) between permissionless entry points and sensitive state. Consider reducing attack surface.`,
            affectedComponents: matrix.entryPoints.map(ep => ep.contract)
        });
    }
    return recommendations;
}
// ============================================================
// HELPER FUNCTIONS
// ============================================================
function findRegisteredFunction(registry, contract, funcName) {
    if (!registry || !contract || !funcName)
        return undefined;
    const contractFuncs = registry.get(contract);
    return contractFuncs?.find(f => f.name === funcName || f.signature.includes(funcName));
}
function findStateVariable(contracts, contractName, varName) {
    const contract = contracts.find(c => c.name === contractName);
    return contract?.stateVariables.find(v => v.name === varName);
}
function findFunction(contracts, contractName, funcName) {
    const contract = contracts.find(c => c.name === contractName);
    return contract?.functions.find(f => f.name === funcName);
}
function findRelatedInvariants(invariants, varName) {
    return invariants
        .filter(inv => inv.relatedStateVars?.includes(varName))
        .map(inv => inv.id);
}
function isValueBearingVariable(varName, stateVar) {
    const valuePatterns = /balance|totalSupply|totalDebt|collateral|reserve|liquidity|funds|assets|liabilities|vault|pool|staked|locked/i;
    return valuePatterns.test(varName) ||
        (stateVar?.type?.toLowerCase().includes('uint') &&
            /(amount|value|share|token)/i.test(varName));
}
function inferAccountingCategory(varName, stateVar) {
    if (/balance|supply|debt|collateral|reserve|liquidity/i.test(varName)) {
        return 'conservation';
    }
    if (/price|rate|ratio|exchange/i.test(varName)) {
        return 'proportional';
    }
    if (/owner|admin|role|permission/i.test(varName)) {
        return 'access-control';
    }
    if (/timestamp|deadline|epoch|start|end/i.test(varName)) {
        return 'temporal-ordering';
    }
    return undefined;
}
function inferSyncCategory(varName, stateVar) {
    if (/balance|supply|totalSupply/i.test(varName))
        return 'accounting';
    if (/owner|admin|role|hasRole/i.test(varName))
        return 'authorization';
    if (/price|oracle|twap/i.test(varName))
        return 'pricing';
    if (/pool|liquidity|reserve/i.test(varName))
        return 'liquidity';
    if (/healthFactor|collateralRatio|ltv/i.test(varName))
        return 'solvency';
    if (/pending|settled|executed|queued/i.test(varName))
        return 'settlement';
    if (/ownerOf|tokenId|nft/i.test(varName))
        return 'ownership';
    if (/timestamp|lastUpdate/i.test(varName))
        return 'timestamp';
    if (/fee|ratio|percentage|threshold/i.test(varName))
        return 'configuration';
    return 'unknown';
}
function inferAccessControl(func) {
    if (func.modifiers.some(m => /onlyOwner|onlyAdmin|onlyRole/.test(m))) {
        return 'admin-only';
    }
    if (func.modifiers.length > 0) {
        return 'restricted';
    }
    if (func.visibility === 'internal' || func.visibility === 'private') {
        return 'internal';
    }
    return 'public';
}
function isPermissionlessFunction(func, registered) {
    if (registered) {
        return registered.accessControl.level === 'public' &&
            (func.visibility === 'external' || func.visibility === 'public');
    }
    // Fallback heuristic
    const hasAccessRestriction = func.modifiers.some(m => /onlyOwner|onlyAdmin|onlyRole|require|whenNotPaused/.test(m));
    return !hasAccessRestriction &&
        (func.visibility === 'external' || func.visibility === 'public') &&
        func.stateMutability !== 'view' &&
        func.stateMutability !== 'pure';
}
function isPermissionlessEntryPoint(func, registered) {
    return isPermissionlessFunction(func, registered) &&
        (func.stateVariablesWritten?.length > 0 || func.stateVariablesRead?.length > 0);
}
function assessMultiWriterRisk(func, varsWritten) {
    let riskScore = 0;
    // More variables written = higher complexity
    riskScore += Math.min(varsWritten.length * 10, 30);
    // CEI violation adds significant risk
    if (func.body?.ceiPattern === 'violated')
        riskScore += 30;
    // External calls add risk
    if (func.body?.hasExternalCall)
        riskScore += 20;
    // Loops can indicate unbounded iteration
    if (func.body?.hasLoop)
        riskScore += 15;
    // Delegatecall is very risky
    if (func.body?.hasDelegateCall)
        riskScore += 25;
    if (riskScore >= 70)
        return 'critical';
    if (riskScore >= 50)
        return 'high';
    if (riskScore >= 25)
        return 'medium';
    return 'low';
}
function calculateContentionRisk(varInfo) {
    let risk = 0;
    // Base risk from number of writers
    risk += Math.min(varInfo.writers.length * 15, 40);
    // Value bearing significantly increases risk
    if (varInfo.isValueBearing)
        risk += 30;
    // Permissionless writers are dangerous
    const permWriters = varInfo.writers.filter(w => w.isPermissionless).length;
    risk += permWriters * 20;
    // Having readers means dependencies exist
    if (varInfo.readerFunctions.length > 0)
        risk += 10;
    // Related invariants mean correctness matters more
    risk += Math.min(varInfo.relatedInvariants.length * 5, 15);
    return Math.min(risk, 100);
}
function assessEntryPointRisk(func, writtenVars, readVars) {
    let risk = 0;
    // More state touched = more risk
    risk += (writtenVars.length + readVars.length) * 5;
    // Writing is riskier than reading
    risk += writtenVars.length * 10;
    // CEI violation
    if (func.body?.ceiPattern === 'violated')
        risk += 25;
    // External calls
    if (func.body?.hasExternalCall)
        risk += 15;
    // Delegatecall
    if (func.body?.hasDelegateCall)
        risk += 30;
    return Math.min(risk, 100);
}
function inferWriteReason(funcName, varName, varType) {
    const nameLower = funcName.toLowerCase();
    const varLower = varName.toLowerCase();
    // Check function name patterns
    if (/deposit|mint|add|supply|provide/i.test(nameLower))
        return 'deposit';
    if (/withdraw|burn|remove|redeem|claim/i.test(nameLower))
        return 'withdrawal';
    if (/transfer|send|move|swap/i.test(nameLower))
        return 'transfer';
    if (/liquidat|seize|close|force/i.test(nameLower))
        return 'liquidation';
    if (/approve|permit|authorize|allow/i.test(nameLower))
        return 'approval';
    if (/update.*price|set.*price|fetch.*price/i.test(nameLower))
        return 'price-update';
    if (/accrue|interest|reward|yield|collect/i.test(nameLower))
        return 'accrual';
    if (/init|constructor|initialize/i.test(nameLower))
        return 'initialize';
    if (/own|transfer.*own/i.test(nameLower))
        return 'ownership-change';
    if (/pause|unpause|enable|disable|toggle/i.test(nameLower))
        return 'state-flag';
    if (/config|set.*param|update.*param/i.test(nameLower))
        return 'configuration';
    if (/reconcile|sync|check|verify/i.test(nameLower))
        return 'accounting';
    if (/refresh|cache|update.*cache/i.test(nameLower))
        return 'cache-update';
    // Check variable name patterns
    if (/balance/i.test(varLower) && /add|inc|increase/i.test(nameLower))
        return 'deposit';
    if (/balance/i.test(varLower) && /sub|dec|decrease/i.test(nameLower))
        return 'withdrawal';
    if (/totalSupply/i.test(varLower))
        return 'transfer';
    if (/timestamp/i.test(varLower))
        return 'cache-update';
    if (/owner/i.test(varLower))
        return 'ownership-change';
    return 'unknown';
}
function generateNaturalLanguageExplanation(funcName, varName, reason, contract) {
    switch (reason) {
        case 'deposit':
            return `${funcName}() updates ${varName} to record new funds/tokens deposited into ${contract}`;
        case 'withdrawal':
            return `${funcName}() decrements ${varName} to process withdrawal/burn request`;
        case 'transfer':
            return `${funcName}() modifies ${varName} to execute transfer between accounts`;
        case 'liquidation':
            return `${funcName}() updates ${varName} as part of liquidation processing`;
        case 'approval':
            return `${funcName}() sets ${varName} to grant/delegate spending allowance`;
        case 'price-update':
            return `${funcName}() writes ${varName} with updated price/oracle data`;
        case 'accrual':
            return `${funcName}() increments ${varName} to accumulate interest/rewards`;
        case 'initialize':
            return `${funcName}() sets initial value for ${varName} during setup`;
        case 'ownership-change':
            return `${funcName}() transfers ownership by updating ${varName}`;
        case 'state-flag':
            return `${funcName}() toggles/modifies ${varName} to change contract state`;
        case 'configuration':
            return `${funcName}() updates configuration parameter ${varName}`;
        case 'accounting':
            return `${funcName}() reconciles ${varName} to maintain accounting consistency`;
        case 'cache-update':
            return `${funcName}() refreshes cached value in ${varName}`;
        default:
            return `${funcName}() modifies ${varName} - manual review recommended to understand intent`;
    }
}
function findOrCreateAccountingRule(varName, reason, contract, funcName, existingRules, ruleList) {
    // Define known accounting rules based on patterns
    let rule;
    if (/balance/i.test(varName) && (reason === 'deposit' || reason === 'withdrawal' || reason === 'transfer')) {
        const ruleId = 'CONSERVATION_OF_BALANCES';
        if (!existingRules.has(ruleId)) {
            existingRules.add(ruleId);
            rule = {
                id: ruleId,
                name: 'Conservation of Balances',
                category: 'conservation',
                equation: 'Σ(userBalances) + reserved = totalSupply',
                variablesInvolved: [varName],
                functionsThatMaintain: [funcName],
                invariantsEnforced: ['non-negative-balances'],
                description: 'Total of all user balances plus any reserves must equal total token supply'
            };
            ruleList.push(rule);
        }
        else {
            rule = ruleList.find(r => r.id === ruleId);
            if (rule && !rule.functionsThatMaintain.includes(funcName)) {
                rule.functionsThatMaintain.push(funcName);
            }
            if (rule && !rule.variablesInvolved.includes(varName)) {
                rule.variablesInvolved.push(varName);
            }
        }
    }
    if (/totalSupply/i.test(varName)) {
        const ruleId = 'SUPPLY_INVARIANT';
        if (!existingRules.has(ruleId)) {
            existingRules.add(ruleId);
            rule = {
                id: ruleId,
                name: 'Total Supply Invariant',
                category: 'conservation',
                equation: 'totalSupply = Σ(balances) + burned + locked',
                variablesInvolved: [varName],
                functionsThatMaintain: [funcName],
                invariantsEnforced: ['no-mint-without-burn', 'supply-monotonic'],
                description: 'Total supply changes only through mint/burn operations'
            };
            ruleList.push(rule);
        }
        else {
            rule = ruleList.find(r => r.id === ruleId);
            if (rule && !rule.functionsThatMaintain.includes(funcName)) {
                rule.functionsThatMaintain.push(funcName);
            }
        }
    }
    return rule;
}
function determineAtomicityRequirement(varName, reason, isValueBearing) {
    // Transfers involving value MUST be atomic
    if (isValueBearing && ['transfer', 'deposit', 'withdrawal', 'liquidation'].includes(reason)) {
        return 'atomic-multi-slot';
    }
    // Single slot writes are inherently atomic
    if (reason === 'state-flag' || reason === 'cache-update') {
        return 'atomic-single-slot';
    }
    // Cross-contract operations need special handling
    if (reason === 'approval' || reason === 'ownership-change') {
        return 'atomic-multi-slot';
    }
    // Operations that interact with external state
    if (reason === 'price-update' || reason === 'configuration') {
        return 'eventual';
    }
    // Default for unknown writes - flag as potentially needing guard
    if (reason === 'unknown' && isValueBearing) {
        return 'requires-reentrancy-guard';
    }
    return 'atomic-single-slot';
}
function couldMaintainInvariant(funcName, invariantId, _invariants) {
    // Heuristic: if function name suggests it's maintaining state properly
    const maintainingPatterns = /update|sync|reconcile|adjust|settle|deposit|withdraw|transfer|mint|burn/i;
    if (maintainingPatterns.test(funcName)) {
        return invariantId;
    }
    return undefined;
}
function couldViolateInvariant(funcName, invariantId, _invariants) {
    // Heuristic: direct writes without clear maintenance pattern
    const riskyPatterns = /force|bypass|emergency|override|direct/i;
    if (riskyPatterns.test(funcName)) {
        return invariantId;
    }
    return undefined;
}
function describeStateTransition(funcName, varName, reason) {
    const transitions = {
        'deposit': {
            fromState: 'previous balance',
            toState: 'balance + deposited amount',
            trigger: `User calls ${funcName}()`,
            conditions: ['Sufficient funds provided', 'Transfer successful'],
            sideEffects: ['Emit Deposit event', 'Update totalSupply if minting']
        },
        'withdrawal': {
            fromState: 'current balance',
            toState: 'balance - withdrawn amount',
            trigger: `User calls ${funcName}()`,
            conditions: ['Sufficient balance', 'Not paused', 'Within limits'],
            sideEffects: ['Emit Withdrawal event', 'Transfer tokens']
        },
        'transfer': {
            fromState: 'sender balance, receiver balance',
            toState: 'sender - amount, receiver + amount',
            trigger: `Transfer initiated via ${funcName}()`,
            conditions: ['Sender has sufficient balance', 'Receiver address valid', 'Allowance sufficient'],
            sideEffects: ['Emit Transfer event', 'Update both balances atomically']
        }
    };
    return transitions[reason] || {
        fromState: 'current value',
        toState: 'new value (see explanation)',
        trigger: `${funcName}() called`,
        conditions: ['Access control passed'],
        sideEffects: []
    };
}
function inferBoundaryType(edge) {
    switch (edge.type) {
        case 'delegatecall': return 'delegatecall';
        case 'staticcall': return 'library-call';
        case 'external':
            if (edge.valueFlow?.ethSent)
                return 'token-transfer';
            if (/transfer|transferFrom|mint|burn/i.test(edge.to.function))
                return 'token-transfer';
            if (/price|oracle|getRate/i.test(edge.to.function))
                return 'oracle-read';
            if (/flashLoan/i.test(edge.to.function))
                return 'flash-loan';
            return 'external-call';
        default: return null;
    }
}
function inferTrustAssumption(edge, type) {
    switch (type) {
        case 'delegatecall':
            return 'Delegatecall target is trusted, immutable, and will not compromise storage';
        case 'flash-loan':
            return 'Flash loan callback will not manipulate protocol state maliciously';
        case 'oracle-read':
            return 'Oracle returns accurate, manipulation-resistant price data';
        case 'token-transfer':
            return 'Token contract behaves correctly (ERC20/721 compliant, no reentrancy)';
        default:
            return `External call to ${edge.to.function} will complete successfully or revert atomically`;
    }
}
function describeBoundaryBreachImpact(type, edge) {
    switch (type) {
        case 'delegatecall':
            return 'Malicious delegatecall target gains full storage access - can steal funds, modify permissions, destroy protocol';
        case 'flash-loan':
            return 'Flash loan attacker manipulates state within callback to extract value (e.g., oracle manipulation, collateral theft)';
        case 'oracle-read':
            return 'Manipulated oracle price causes incorrect valuation → bad debt, insolvent positions, unfair liquidations';
        case 'token-transfer':
            return 'Malicious token contract reenters or misbehaves → double-spend, balance inconsistency, fund drainage';
        default:
            return 'External call fails or behaves unexpectedly → inconsistent state, lost funds, locked functionality';
    }
}
function assessBoundaryStrength(edge, type, isPermissionlessSource) {
    let strength = 100;
    // Delegatecall is inherently risky
    if (type === 'delegatecall')
        strength -= 50;
    // Flash loans are very risky
    if (type === 'flash-loan')
        strength -= 40;
    // Permissionless caller makes it worse
    if (isPermissionlessSource)
        strength -= 20;
    // Unknown external targets are risky
    if (edge.to.contract === 'external')
        strength -= 15;
    // Value transfer adds risk
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
function guessDataExposed(edge, sourceFunc) {
    const exposed = [];
    // Always expose msg.sender context
    exposed.push('msg.sender');
    // If function reads state, those might influence the call
    if (sourceFunc?.stateVariablesRead) {
        exposed.push('contract state (may influence call parameters)');
    }
    // Value transfers expose amount
    if (edge.valueFlow?.ethSent) {
        exposed.push('ETH/token amount');
    }
    return exposed;
}
function hasStateModificationAcrossBoundary(sourceFunc, _edge) {
    // If source function writes state AND makes external call, state modification crosses boundary
    return !!(sourceFunc?.stateVariablesWritten?.length && sourceFunc?.body?.hasExternalCall);
}
function assessCEIOrdering(sourceFunc, _edge) {
    if (!sourceFunc)
        return 'unknown';
    if (sourceFunc.body?.ceiPattern === 'valid')
        return 'safe';
    if (sourceFunc.body?.ceiPattern === 'violated')
        return 'unsafe';
    return 'unknown';
}
function detectBoundaryVulnerabilities(boundary, edge, sourceFunc) {
    const vulns = [];
    // Check for weak/no strength with permissionless access
    if ((boundary.strength === 'weak' || boundary.strength === 'none') && boundary.stateModified) {
        vulns.push({
            boundaryId: boundary.id,
            vulnerability: 'Weak trust boundary with state modification',
            exploitationScenario: `Attacker calls ${boundary.sourceFunction} which modifies state then crosses weak boundary to ${boundary.targetContext}`,
            recommendation: 'Strengthen boundary with access controls, reentrancy guards, or use pull payment pattern',
            severity: 'high'
        });
    }
    // Check for delegatecall risks
    if (boundary.boundaryType === 'delegatecall') {
        vulns.push({
            boundaryId: boundary.id,
            vulnerability: 'Delegatecall exposes full storage context',
            exploitationScenario: 'Compromised or upgradable delegatecall target can read/write all contract storage',
            recommendation: 'Ensure delegatecall target is immutable, verified, and governed by robust access control',
            severity: 'critical'
        });
    }
    // Check for CEI violations at boundary
    if (boundary.ceiOrdering === 'unsafe') {
        vulns.push({
            boundaryId: boundary.id,
            vulnerability: 'CEI violation at trust boundary enables reentrancy',
            exploitationScenario: 'External call occurs before state finalization, allowing reentrant calls to see inconsistent state',
            recommendation: 'Reorder to complete all state modifications before crossing trust boundary',
            severity: 'critical'
        });
    }
    // Check for flash loan risks
    if (boundary.boundaryType === 'flash-loan') {
        vulns.push({
            boundaryId: boundary.id,
            vulnerability: 'Flash loan interaction creates temporary state inconsistency',
            exploitationScenario: 'Flash loan attacker manipulates prices or balances within callback execution',
            recommendation: 'Implement flash loan detection, use TWAP oracles, add slippage checks',
            severity: boundary.strength === 'none' ? 'critical' : 'high'
        });
    }
    return vulns;
}
function countCrossContractDeps(variableWriters, contracts) {
    let count = 0;
    const contractNames = new Set(contracts.map(c => c.name));
    for (const [, varInfo] of variableWriters) {
        // Check if readers are in different contracts than writers
        const writerContracts = new Set(varInfo.writers.map(w => w.contract));
        const readerContracts = new Set(varInfo.readerFunctions.map(r => r.contract));
        for (const readerContract of readerContracts) {
            if (!writerContracts.has(readerContract) && contractNames.has(readerContract)) {
                count++;
                break;
            }
        }
    }
    return count;
}
// ============================================================
// EXPORT UTILITIES
// ============================================================
/**
 * Export storage dependency analysis result to JSON-serializable format
 */
function exportStorageDependencyResult(result) {
    return {
        timestamp: result.timestamp,
        storageWriteGraph: {
            variableWriters: Array.from(result.storageWriteGraph.variableWriters.entries()).map(([k, v]) => ({
                key: k,
                ...v
            })),
            multiVariableWriters: result.storageWriteGraph.multiVariableWriters,
            contendedVariables: result.storageWriteGraph.contentedVariables,
            summary: result.storageWriteGraph.summary
        },
        sharedStateMatrix: {
            entryPoints: result.sharedStateMatrix.entryPoints,
            sharedVariables: result.sharedStateMatrix.sharedVariables,
            cells: Array.from(result.sharedStateMatrix.cells.entries()).map(([rowKey, colMap]) => ({
                entryPoint: rowKey,
                cells: Array.from(colMap.entries()).map(([colKey, cell]) => ({
                    variable: colKey,
                    ...cell
                }))
            })),
            riskSummary: result.sharedStateMatrix.riskSummary
        },
        writeExplanations: {
            explanations: Array.from(result.writeExplanations.explanations.entries()).map(([k, v]) => ({
                key: k,
                ...v
            })),
            unexplainedWrites: result.writeExplanations.unexplainedWrites,
            discoveredRules: result.writeExplanations.discoveredRules
        },
        trustBoundaryMap: result.trustBoundaryMap ? {
            boundaries: result.trustBoundaryMap.boundaries,
            crossBoundaryFlows: result.trustBoundaryMap.crossBoundaryFlows,
            vulnerableBoundaries: result.trustBoundaryMap.vulnerableBoundaries
        } : undefined,
        highRiskFindings: result.highRiskFindings,
        recommendations: result.recommendations
    };
}
/**
 * Generate Mermaid diagram for Storage Write Graph
 */
function generateStorageWriteGraphMermaid(graph) {
    const lines = ['graph LR'];
    lines.push('  %% Storage Write Graph');
    lines.push('  %% Nodes = Variables, Edges = Writers');
    // Create nodes for highly-contended variables
    const topContended = graph.contentedVariables.slice(0, 10);
    for (const cv of topContended) {
        const nodeId = cv.variableName.replace(/[^a-zA-Z0-9]/g, '_');
        lines.push(`  ${nodeId}["${cv.variableName}<br/>(${cv.writerCount} writers)"]`);
        // Add edges for each writer
        for (const writer of cv.writerFunctions) {
            const writerId = writer.replace(/[^a-zA-Z0-9]/g, '_');
            lines.push(`  ${writerId} -->|writes| ${nodeId}`);
        }
    }
    // Style high-risk nodes
    for (const cv of topContended.filter(v => v.riskScore >= 70)) {
        const nodeId = cv.variableName.replace(/[^a-zA-Z0-9]/g, '_');
        lines.push(`  style ${nodeId} fill:#ff6b6b,stroke:#333,color:white`);
    }
    return lines.join('\n');
}
/**
 * Generate Markdown report for Storage Dependency Analysis
 */
function generateStorageDependencyMarkdown(result) {
    let md = '# Storage Dependency Analysis Report\n\n';
    md += `**Generated:** ${result.timestamp}\n\n`;
    // Executive Summary
    md += '## Executive Summary\n\n';
    md += '| Metric | Value |\n';
    md += '|--------|-------|\n';
    md += '| Total Variables Tracked | ' + result.storageWriteGraph.summary.totalVariablesTracked + ' |\n';
    md += '| Total Write Operations | ' + result.storageWriteGraph.summary.totalWriteOperations + ' |\n';
    md += '| Contended Variables | ' + result.storageWriteGraph.summary.contendedVariableCount + ' |\n';
    md += '| High-Risk Contentions | ' + result.storageWriteGraph.summary.highRiskContentionCount + ' |\n';
    md += '| Permissionless Writes | ' + result.storageWriteGraph.summary.permissionlessWriteCount + ' |\n';
    md += '| Value-Bearing Variables | ' + result.storageWriteGraph.summary.valueBearingVariableCount + ' |\n';
    md += '| High-Risk Findings | ' + result.highRiskFindings.length + ' |\n\n';
    // Contended Variables
    if (result.storageWriteGraph.contentedVariables.length > 0) {
        md += '## Contended Variables (Multi-Writer)\n\n';
        md += '| Variable | Contract | Writers | Permissionless | Risk Score |\n';
        md += '|---------|----------|---------|---------------|------------|\n';
        for (const cv of result.storageWriteGraph.contentedVariables.slice(0, 20)) {
            md += '| **' + cv.variableName + '** | ' + cv.contract + ' | ' + cv.writerCount + ' | ' +
                cv.permissionlessWriterCount + ' | ' + cv.riskScore + '/100 |\n';
        }
        md += '\n';
    }
    // Shared State Matrix Summary
    md += '## Permissionless Entry Points\n\n';
    md += '| Entry Point | Variables Read | Variables Written | Risk Score |\n';
    md += '|-------------|---------------|-------------------|------------|\n';
    for (const ep of result.sharedStateMatrix.entryPoints.slice(0, 20)) {
        md += '| `' + ep.fullSignature + '` | ' + ep.variablesRead.length + ' | ' +
            ep.variablesWritten.length + ' | ' + ep.riskScore + '/100 |\n';
    }
    md += '\n';
    // High-Risk Findings
    if (result.highRiskFindings.length > 0) {
        md += '## High-Risk Findings\n\n';
        for (const finding of result.highRiskFindings) {
            md += '### ' + finding.severity.toUpperCase() + ': ' + finding.title + '\n\n';
            md += finding.description + '\n\n';
            md += '**Location:** ' + finding.location.contract +
                (finding.location.function ? '.' + finding.location.function : '') +
                (finding.location.variable ? ' → ' + finding.location.variable : '') + '\n\n';
            md += '**Recommendation:** ' + finding.recommendation + '\n\n';
            md += '---\n\n';
        }
    }
    // Recommendations
    if (result.recommendations.length > 0) {
        md += '## Recommendations\n\n';
        for (const rec of result.recommendations) {
            md += '- **[' + rec.priority.toUpperCase() + ']** ' + rec.title + '\n\n';
            md += rec.description + '\n\n';
        }
    }
    return md;
}
//# sourceMappingURL=storage-dependency-analyzer.js.map