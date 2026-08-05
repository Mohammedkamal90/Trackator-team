"use strict";
// ============================================================
// TRACKATOR Tier 1 - Function Registry
// Catalogs all functions with detailed metadata for analysis
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildFunctionRegistry = buildFunctionRegistry;
exports.findFunctions = findFunctions;
exports.getHighRiskFunctions = getHighRiskFunctions;
exports.getEntryPoints = getEntryPoints;
exports.exportRegistry = exportRegistry;
/**
 * Build complete function registry for all contracts
 */
function buildFunctionRegistry(contracts) {
    const registry = new Map();
    for (const contract of contracts) {
        const registeredFunctions = [];
        for (const func of contract.functions) {
            const registered = registerFunction(func, contract);
            registeredFunctions.push(registered);
        }
        registry.set(contract.name, registeredFunctions);
    }
    return registry;
}
/**
 * Register a single function with full analysis
 */
function registerFunction(func, contract) {
    const signature = buildSignature(func);
    const selector = computeSelector(signature.canonical);
    const rawCategory = categorizeFunction(func, contract);
    const accessControlDetail = analyzeAccessControl(func);
    const risk = assessRisk(func, accessControlDetail);
    const stateImpactDetail = analyzeStateImpact(func);
    const gasProfile = estimateGasProfile(func);
    return {
        // Canonical fields
        id: `${contract.name}.${signature.canonical}`,
        contract: contract.name,
        signature: signature.canonical,
        name: func.name,
        function: func.name,
        category: mapToCanonicalCategory(rawCategory),
        accessControl: mapToCanonicalAccessControl(accessControlDetail, func),
        risk,
        stateReads: stateImpactDetail.reads,
        stateWrites: stateImpactDetail.writes,
        externalCalls: [], // local analysis only tracks a count (stateImpactDetail.externalCalls); no per-call target names available here — cross-reference callEdges for real target data
        stateImpact: `${stateImpactDetail.reads.length} reads, ${stateImpactDetail.writes.length} writes` +
            (stateImpactDetail.mints ? ', mints' : '') +
            (stateImpactDetail.burns ? ', burns' : '') +
            (stateImpactDetail.transfers ? ', transfers' : ''),
        lineDeclared: func.lineStart,
        // Local-only extensions
        functionDef: func,
        selector,
        rawCategory,
        accessControlDetail,
        stateImpactDetail,
        gasProfile
    };
}
/**
 * Map local 12-value category to canonical 10-value FunctionCategory.
 * 6 values match directly; 6 local-only values are remapped (verified against
 * codebase usage — nothing outside this file depends on the raw values).
 */
function mapToCanonicalCategory(raw) {
    const map = {
        'admin': 'admin',
        'access-control': 'access-control',
        'core-logic': 'core-logic',
        'oracle': 'oracle',
        'constructor': 'constructor',
        'emergency': 'emergency',
        'view': 'utility',
        'external': 'callback',
        'event-emitter': 'utility',
        'modifier': 'access-control',
        'helper': 'utility',
        'unknown': 'utility'
    };
    return map[raw];
}
/**
 * Map local AccessControlInfo to canonical AccessControlEntry.
 * `level` is derived from local's richer `mechanism` field (not a naive
 * rename — local's AccessControlLevel values don't overlap with canonical's).
 */
function mapToCanonicalAccessControl(local, func) {
    let level;
    if (func.visibility === 'internal' || func.visibility === 'private') {
        level = 'internal';
    }
    else if (local.mechanism === 'onlyOwner') {
        level = 'admin-only';
    }
    else if (local.mechanism === 'onlyRole') {
        level = 'role-based';
    }
    else if (local.mechanism === 'require' || local.mechanism === 'custom') {
        level = 'restricted';
    }
    else {
        level = 'public';
    }
    const modifiers = func.modifiers || (local.modifierName ? [local.modifierName] : []);
    return {
        level,
        rolesRequired: local.roleRequired ? [local.roleRequired] : [],
        modifiers,
        ownerOnly: local.mechanism === 'onlyOwner',
        visibility: func.visibility,
        restrictions: local.bypassable ? local.bypassMethods : undefined,
        length: modifiers.length
    };
}
/**
 * Build canonical function signature
 */
function buildSignature(func) {
    const inputs = func.parameters.map(p => ({
        type: p.type,
        name: p.name || undefined
    }));
    const outputs = func.returnParameters.map(p => ({
        type: p.type,
        name: p.name || undefined
    }));
    const inputStr = inputs.map(i => i.type).join(',');
    const outputStr = outputs.length > 0 ? `returns(${outputs.map(o => o.type).join(',')})` : '';
    return {
        name: func.name,
        inputs,
        outputs,
        canonical: `${func.name}(${inputStr})${outputStr ? ` ${outputStr}` : ''}`
    };
}
/**
 * Compute 4-byte function selector (simplified - real impl uses keccak256)
 */
function computeSelector(signature) {
    // In production, this would be: keccak256(signature).slice(0, 4)
    // For now, return a deterministic hash-like value based on signature
    let hash = 0;
    for (let i = 0; i < signature.length; i++) {
        const char = signature.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    // Convert to 8-char hex (simulating 4 bytes)
    const hex = Math.abs(hash).toString(16).padStart(8, '0').slice(0, 8);
    return `0x${hex}`;
}
/**
 * Categorize function by its purpose and behavior
 */
function categorizeFunction(func, contract) {
    const name = func.name.toLowerCase();
    const modifiers = func.modifiers.map(m => m.toLowerCase());
    // Constructor types
    if (['constructor', 'receive', 'fallback', 'init'].includes(name)) {
        return 'constructor';
    }
    // Admin/owner functions
    if (name.includes('owner') || name.includes('transferownership') ||
        name.includes('renounce') || modifiers.includes('onlyowner')) {
        return 'admin';
    }
    // Access control / role management
    if (name.includes('grant') || name.includes('revoke') || name.includes('role') ||
        name.includes('setadmin') || modifiers.includes('onlyrole')) {
        return 'access-control';
    }
    // Emergency functions
    if (name.includes('pause') || name.includes('unpause') || name.includes('emergency')) {
        return 'emergency';
    }
    // Oracle/price functions
    if (name.includes('price') || name.includes('oracle') || name.includes('feed') ||
        name.includes('twap') || name.includes('spot')) {
        return 'oracle';
    }
    // View/pure functions
    if (func.stateMutability === 'view' || func.stateMutability === 'pure') {
        return 'view';
    }
    // Internal helpers
    if (func.visibility === 'internal' || func.visibility === 'private') {
        if (name.startsWith('_') || name.startsWith('__')) {
            return 'helper';
        }
    }
    // Core logic detection by common DeFi patterns
    const corePatterns = [
        'deposit', 'withdraw', 'borrow', 'repay', 'liquidate',
        'swap', 'trade', 'mint', 'burn', 'stake', 'unstake',
        'claim', 'reward', 'harvest', 'compound', 'leverage',
        'execute', 'invoke', 'call', 'flash', 'bridge', 'transfer'
    ];
    if (corePatterns.some(pattern => name.includes(pattern))) {
        return 'core-logic';
    }
    // External integration
    if (func.body.hasExternalCall && !func.body.hasTransfer) {
        return 'external';
    }
    return 'unknown';
}
/**
 * Analyze access control mechanisms
 */
function analyzeAccessControl(func) {
    const modifiers = func.modifiers.map(m => m.toLowerCase());
    let level;
    let mechanism;
    let roleRequired;
    let modifierName;
    let bypassable = false;
    const bypassMethods = [];
    // Check visibility first
    if (func.visibility === 'internal' || func.visibility === 'private') {
        level = func.visibility;
        mechanism = 'none';
    }
    else if (modifiers.includes('onlyowner')) {
        level = 'restricted';
        mechanism = 'onlyOwner';
        modifierName = 'onlyOwner';
        roleRequired = 'owner';
        // Check if owner can be set to address(0)
        bypassable = true;
        bypassMethods.push('If ownership can be transferred to address(0)');
    }
    else if (modifiers.some(m => m.includes('role'))) {
        level = 'restricted';
        mechanism = 'onlyRole';
        modifierName = modifiers.find(m => m.includes('role'));
        roleRequired = modifierName?.replace('only', '');
    }
    else if (func.body.hasRequire) {
        // Check for require statements that might be access control
        level = 'public'; // Assume public unless we find specific require(msg.sender)
        mechanism = 'require';
        // Could add deeper analysis of require conditions here
    }
    else {
        level = func.visibility === 'external' ? 'external' : 'public';
        mechanism = 'none';
        // Public/external without access control is notable
        if (func.stateMutability !== 'view' && func.stateMutability !== 'pure') {
            bypassable = true;
            bypassMethods.push('No access control modifier');
        }
    }
    return {
        level,
        mechanism,
        roleRequired,
        modifierName,
        linesChecked: [], // Would need AST line tracking
        bypassable,
        bypassMethods
    };
}
/**
 * Assess risk level of function
 */
function assessRisk(func, accessControl) {
    const factors = [];
    let totalScore = 0;
    // CEI Pattern violation
    if (func.body.ceiPattern === 'violated') {
        factors.push({
            type: 'cei-violation',
            severity: 'critical',
            description: 'Effects occur before interactions - potential reentrancy vulnerability',
            mitigated: false
        });
        totalScore += 30;
    }
    // External calls with state changes
    if (func.body.hasExternalCall && func.stateVariablesWritten.length > 0) {
        factors.push({
            type: 'external-call-state-change',
            severity: 'high',
            description: 'External calls combined with state modifications',
            mitigated: func.body.ceiPattern === 'valid'
        });
        totalScore += 20;
    }
    // Delegate call usage
    if (func.body.hasDelegateCall) {
        factors.push({
            type: 'delegatecall',
            severity: 'critical',
            description: 'Usage of delegatecall - execution context forwarded',
            mitigated: false
        });
        totalScore += 35;
    }
    // ETH transfer
    if (func.body.hasTransfer) {
        factors.push({
            type: 'eth-transfer',
            severity: 'medium',
            description: 'Direct ETH transfer detected',
            mitigated: false
        });
        totalScore += 10;
    }
    // Loops over unbounded data
    if (func.body.hasLoop) {
        factors.push({
            type: 'unbounded-loop',
            severity: 'medium',
            description: 'Loop detected - potential DoS if unbounded',
            mitigated: false
        });
        totalScore += 15;
    }
    // Missing access control on state-changing function
    if (accessControl.mechanism === 'none' &&
        func.stateMutability !== 'view' &&
        func.stateMutability !== 'pure' &&
        (func.visibility === 'public' || func.visibility === 'external')) {
        factors.push({
            type: 'missing-access-control',
            severity: 'high',
            description: 'State-changing function lacks explicit access control',
            mitigated: false
        });
        totalScore += 25;
    }
    // High complexity
    if (func.complexity > 10) {
        factors.push({
            type: 'high-complexity',
            severity: 'low',
            description: `Cyclomatic complexity is ${func.complexity} - consider simplifying`,
            mitigated: false
        });
        totalScore += Math.min(func.complexity, 15);
    }
    // Determine overall risk level
    let overall;
    if (totalScore >= 50) {
        overall = 'critical';
    }
    else if (totalScore >= 35) {
        overall = 'high';
    }
    else if (totalScore >= 20) {
        overall = 'medium';
    }
    else if (totalScore >= 5) {
        overall = 'low';
    }
    else {
        overall = 'safe';
    }
    return {
        score: Math.min(totalScore, 100),
        factors,
        overall
    };
}
/**
 * Analyze state impact of function
 */
function analyzeStateImpact(func) {
    const name = func.name.toLowerCase();
    return {
        reads: func.stateVariablesRead,
        writes: func.stateVariablesWritten,
        mints: ['mint', '_mint'].some(m => name.includes(m)),
        burns: ['burn', '_burn'].some(b => name.includes(b)),
        transfers: ['transfer', '_transfer', 'send'].some(t => name.includes(t)),
        approves: ['approve', '_approve', 'permit', 'increaseAllowance', 'decreaseAllowance'].some(a => name.includes(a)),
        externalCalls: func.calls.filter(c => !['require', 'revert', 'assert', 'super'].includes(c)).length,
        potentialReentrancy: func.body.hasExternalCall && func.body.ceiPattern !== 'valid',
        ceiCompliant: func.body.ceiPattern === 'valid' || func.body.ceiPattern === 'not-applicable'
    };
}
/**
 * Estimate gas profile of function
 */
function estimateGasProfile(func) {
    // Base gas costs
    const baseCost = 21000; // Transaction base
    // Estimate based on complexity
    const complexityMultiplier = func.complexity * 500;
    // Count storage operations (approximate)
    const sloadCount = func.stateVariablesRead.length;
    const sstoreCount = func.stateVariablesWritten.length;
    // Storage gas costs (cold vs warm - using cold costs)
    const storageGasCost = (sloadCount * 2100) + (sstoreCount * 20000); // SSTORE can be up to 20000
    // External call cost
    const externalCallCost = func.body.hasExternalCall ? 2600 : 0;
    const delegateCallCost = func.body.hasDelegateCall ? 100 : 0; // Additional overhead
    // Loop overhead
    const loopOverhead = func.body.hasLoop ? 5000 : 0;
    const estimatedMin = baseCost + complexityMultiplier + storageGasCost + externalCallCost;
    const estimatedMax = estimatedMin * 2 + loopOverhead + delegateCallCost;
    // Extract loop info (simplified)
    const loops = [];
    if (func.body.hasLoop) {
        loops.push({
            variable: 'unknown',
            type: 'for',
            bounded: false,
            line: func.lineStart
        });
    }
    // Storage ops info
    const storageOps = [
        ...func.stateVariablesRead.map(v => ({
            operation: 'sload',
            variable: v,
            line: func.lineStart
        })),
        ...func.stateVariablesWritten.map(v => ({
            operation: 'sstore',
            variable: v,
            line: func.lineStart
        }))
    ];
    return {
        estimatedMin,
        estimatedMax,
        loops,
        storageOps,
        externalCallCount: func.body.hasExternalCall ? 1 : 0,
        sstoreCount,
        sloadCount
    };
}
// ============================================================
// QUERY FUNCTIONS
// ============================================================
/**
 * Find all functions matching criteria
 */
function findFunctions(registry, criteria) {
    const results = [];
    for (const [, functions] of registry) {
        for (const func of functions) {
            let matches = true;
            if (criteria.category && func.category !== criteria.category) {
                matches = false;
            }
            if (criteria.accessLevel && func.accessControl.level !== criteria.accessLevel) {
                matches = false;
            }
            if (criteria.minRisk !== undefined && func.risk.score < criteria.minRisk) {
                matches = false;
            }
            if (criteria.hasExternalCalls !== undefined) {
                if (criteria.hasExternalCalls && func.stateImpactDetail.externalCalls === 0) {
                    matches = false;
                }
                if (!criteria.hasExternalCalls && func.stateImpactDetail.externalCalls > 0) {
                    matches = false;
                }
            }
            if (criteria.stateMutability && func.functionDef.stateMutability !== criteria.stateMutability) {
                matches = false;
            }
            if (criteria.visibility && func.functionDef.visibility !== criteria.visibility) {
                matches = false;
            }
            if (matches) {
                results.push(func);
            }
        }
    }
    return results;
}
/**
 * Get high-risk functions sorted by risk score
 */
function getHighRiskFunctions(registry, minScore = 25) {
    const allFunctions = [];
    for (const [, functions] of registry) {
        allFunctions.push(...functions);
    }
    return allFunctions
        .filter(f => f.risk.score >= minScore)
        .sort((a, b) => b.risk.score - a.risk.score);
}
/**
 * Get entry points (external/public non-view functions)
 */
function getEntryPoints(registry) {
    const results = [];
    for (const [, functions] of registry) {
        for (const func of functions) {
            if ((func.functionDef.visibility === 'external' || func.functionDef.visibility === 'public') &&
                func.functionDef.stateMutability !== 'view' &&
                func.functionDef.stateMutability !== 'pure' &&
                !['constructor', 'fallback', 'receive'].includes(func.functionDef.kind)) {
                results.push(func);
            }
        }
    }
    return results;
}
/**
 * Export registry to JSON-serializable format
 */
function exportRegistry(registry) {
    const output = {};
    for (const [contract, functions] of registry) {
        output[contract] = functions.map(f => ({
            signature: f.signature,
            selector: f.selector,
            category: f.category,
            rawCategory: f.rawCategory,
            accessControl: f.accessControl,
            risk: f.risk,
            stateImpact: f.stateImpact,
            stateImpactDetail: f.stateImpactDetail,
            gasProfile: f.gasProfile
        }));
    }
    return output;
}
//# sourceMappingURL=function-registry.js.map