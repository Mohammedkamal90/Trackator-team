"use strict";
// ============================================================
// TRACKATOR Tier 1 - Role Extraction Module
// Extracts protocol roles (Trusted & Non-Trusted) from Solidity
// Pure static analysis - no AI/LLM required
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractProtocolRoles = extractProtocolRoles;
exports.detectOwnerRole = detectOwnerRole;
exports.detectAdminRoles = detectAdminRoles;
exports.detectRBACRoles = detectRBACRoles;
exports.detectSpecialRoles = detectSpecialRoles;
exports.detectGovernanceRoles = detectGovernanceRoles;
exports.extractNonTrustedRoles = extractNonTrustedRoles;
exports.findCapabilitiesForModifier = findCapabilitiesForModifier;
exports.createCapabilityFromFunction = createCapabilityFromFunction;
exports.categorizeCapability = categorizeCapability;
exports.assessCapabilityImpact = assessCapabilityImpact;
const function_registry_1 = require("./function-registry");
/**
 * Main entry point for role extraction
 */
function extractProtocolRoles(contracts, registry) {
    const funcRegistry = registry || (0, function_registry_1.buildFunctionRegistry)(contracts);
    // Step 1: Extract trusted roles from access control patterns
    const trustedRoles = extractTrustedRoles(contracts, funcRegistry);
    // Step 2: Identify non-trusted roles (public-facing)
    const nonTrustedRoles = extractNonTrustedRoles(contracts, funcRegistry);
    // Step 3: Build role hierarchy/relationships
    const roleHierarchy = buildRoleHierarchy(trustedRoles, contracts);
    // Step 4: Generate summary statistics
    const summary = generateRoleSummary(trustedRoles, nonTrustedRoles, contracts);
    return {
        extractedAt: new Date().toISOString(),
        totalRoles: trustedRoles.length + nonTrustedRoles.length,
        trustedRoles,
        nonTrustedRoles,
        roleHierarchy,
        summary
    };
}
// ============================================================
// TRUSTED ROLE EXTRACTION
// ============================================================
function extractTrustedRoles(contracts, registry) {
    const roles = [];
    const seenRoles = new Map(); // Deduplication
    for (const contract of contracts) {
        // Skip interfaces and abstract contracts for role definition
        if (contract.abstract || isInterface(contract))
            continue;
        // 1. Detect Owner role
        const ownerRole = detectOwnerRole(contract);
        if (ownerRole && !seenRoles.has(ownerRole.id)) {
            seenRoles.set(ownerRole.id, ownerRole);
            roles.push(ownerRole);
        }
        // 2. Detect Admin roles
        const adminRoles = detectAdminRoles(contract);
        for (const role of adminRoles) {
            if (!seenRoles.has(role.id)) {
                seenRoles.set(role.id, role);
                roles.push(role);
            }
        }
        // 3. Detect Role-based access (onlyRole modifiers)
        const rbacRoles = detectRBACRoles(contract, registry);
        for (const role of rbacRoles) {
            const dedupeKey = `${role.name}_${role.sourceContract}`;
            if (!seenRoles.has(dedupeKey)) {
                seenRoles.set(dedupeKey, role);
                roles.push(role);
            }
        }
        // 4. Detect special roles (Guardian, Manager, Operator, etc.)
        const specialRoles = detectSpecialRoles(contract, registry);
        for (const role of specialRoles) {
            const dedupeKey = `${role.name}_${role.sourceContract}`;
            if (!seenRoles.has(dedupeKey)) {
                seenRoles.set(dedupeKey, role);
                roles.push(role);
            }
        }
        // 5. Detect Timelock/Multisig roles
        const governanceRoles = detectGovernanceRoles(contract);
        for (const role of governanceRoles) {
            if (!seenRoles.has(role.id)) {
                seenRoles.set(role.id, role);
                roles.push(role);
            }
        }
    }
    return roles;
}
/**
 * Detect the Owner role from contract patterns
 */
function detectOwnerRole(contract) {
    // Look for owner-related patterns
    const hasOwnerVar = contract.stateVariables.some(sv => sv.name.toLowerCase() === 'owner' ||
        sv.name.toLowerCase() === '_owner' ||
        sv.name.toLowerCase() === 'admin');
    const hasOwnerFunc = contract.functions.some(f => f.name.toLowerCase() === 'owner' &&
        f.stateMutability === 'view');
    const hasOnlyOwnerModifier = contract.functions.some(f => f.modifiers.some(m => m.toLowerCase().includes('onlyowner')));
    const hasTransferOwnership = contract.functions.some(f => f.name.toLowerCase().includes('transferownership') ||
        f.name.toLowerCase().includes('renounce'));
    if (!hasOwnerVar && !hasOwnerFunc && !hasOnlyOwnerModifier) {
        return null;
    }
    // Find address source
    let addressSource;
    let addressType = 'unknown';
    const ownerVar = contract.stateVariables.find(sv => sv.name.toLowerCase() === 'owner' || sv.name.toLowerCase() === '_owner');
    if (ownerVar) {
        addressSource = `${ownerVar.name} (state variable)`;
        addressType = 'state-var';
    }
    else if (hasOwnerFunc) {
        addressSource = 'owner() function';
        addressType = 'function-return';
    }
    // Find capabilities (functions with onlyOwner)
    const capabilities = findCapabilitiesForModifier(contract, 'onlyOwner', ['onlyowner', 'only_owner']);
    return {
        id: `ROLE_OWNER_${contract.name}`,
        name: 'Owner',
        category: 'trusted',
        addressSource,
        addressType,
        trustLevel: hasTransferOwnership ? 'HIGH' : 'CRITICAL',
        trustReasoning: hasTransferOwnership
            ? 'Ownership can be transferred - verify transfer protection exists'
            : 'Single admin with full control over critical functions',
        capabilities,
        constraints: deriveConstraints(capabilities),
        sourceContract: contract.name,
        modifierName: 'onlyOwner',
        relatedFunctions: capabilities.map(c => c.functionSignature),
        riskIfCompromised: assessOwnerRisk(capabilities),
        isSinglePointOfFailure: true
    };
}
/**
 * Detect Admin roles (separate from Owner)
 */
function detectAdminRoles(contract) {
    const roles = [];
    // Look for admin state variables
    const adminVars = contract.stateVariables.filter(sv => sv.name.toLowerCase().includes('admin') &&
        !sv.name.toLowerCase().includes('role') &&
        sv.type.toLowerCase().includes('address'));
    for (const adminVar of adminVars) {
        const modifierName = `only${capitalize(adminVar.name)}`;
        const capabilities = findCapabilitiesForModifier(contract, modifierName, [adminVar.name.toLowerCase(), `only${adminVar.name.toLowerCase()}`]);
        if (capabilities.length > 0) {
            roles.push({
                id: `ROLE_${adminVar.name.toUpperCase()}_${contract.name}`,
                name: capitalize(adminVar.name).replace(/_/g, ' '),
                category: 'trusted',
                addressSource: `${adminVar.name} (state variable)`,
                addressType: 'state-var',
                trustLevel: 'HIGH',
                trustReasoning: 'Admin role with significant but not complete control',
                capabilities,
                constraints: deriveConstraints(capabilities),
                sourceContract: contract.name,
                modifierName,
                relatedFunctions: capabilities.map(c => c.functionSignature),
                riskIfCompromised: `Admin can execute ${capabilities.length} privileged functions`,
                isSinglePointOfFailure: false
            });
        }
    }
    return roles;
}
/**
 * Detect RBAC (Role-Based Access Control) roles from onlyRole modifiers
 */
function detectRBACRoles(contract, registry) {
    const roles = [];
    const contractFuncs = registry.get(contract.name) || [];
    // Find all unique role constants used in onlyRole modifiers
    const rolePatterns = new Map();
    for (const func of contract.functions) {
        for (const modifier of func.modifiers) {
            const modLower = modifier.toLowerCase();
            // Match onlyRole(ROLE_NAME) or onlyRole(role) patterns
            if (modLower.includes('onlyrole') || modLower.includes('hasrole') || modLower.includes('require')) {
                // Try to extract role name from modifier arguments or context
                const roleName = extractRoleNameFromModifier(modifier, func, contract);
                if (roleName) {
                    if (!rolePatterns.has(roleName)) {
                        rolePatterns.set(roleName, { functions: [], constantName: findRoleConstant(roleName, contract) });
                    }
                    rolePatterns.get(roleName).functions.push(func);
                }
            }
        }
    }
    // Create ProtocolRole for each detected RBAC role
    for (const [roleName, data] of rolePatterns) {
        const capabilities = data.functions.map(f => createCapabilityFromFunction(f, contract.name));
        // Determine trust level based on capability impact
        const trustLevel = calculateTrustLevel(capabilities);
        roles.push({
            id: `ROLE_${roleName.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_${contract.name}`,
            name: formatRoleName(roleName),
            category: 'trusted',
            addressSource: data.constantName ? `${data.constantName} (bytes32 constant)` : undefined,
            addressType: data.constantName ? 'immutable' : 'unknown',
            roleConstant: data.constantName,
            trustLevel,
            trustReasoning: generateTrustReasoning(roleName, capabilities, trustLevel),
            capabilities,
            constraints: deriveConstraints(capabilities),
            sourceContract: contract.name,
            modifierName: 'onlyRole',
            relatedFunctions: data.functions.map(f => `${f.name}(${f.parameters.map(p => p.type).join(',')})`),
            riskIfCompromised: assessRoleRisk(roleName, capabilities),
            isSinglePointOfFailure: capabilities.some(c => c.impact === 'critical') && data.functions.length < 3
        });
    }
    return roles;
}
/**
 * Detect special protocol-specific roles
 */
function detectSpecialRoles(contract, registry) {
    const roles = [];
    const contractFuncs = registry.get(contract.name) || [];
    // Special role patterns to detect
    const specialPatterns = [
        { keywords: ['guardian', 'pause'], name: 'Guardian', trustLevel: 'HIGH' },
        { keywords: ['manager', 'portfolio'], name: 'Manager', trustLevel: 'MEDIUM' },
        { keywords: ['operator'], name: 'Operator', trustLevel: 'MEDIUM' },
        { keywords: ['liquidator'], name: 'Liquidator', trustLevel: 'LOW' },
        { keywords: ['servicer'], name: 'Servicer', trustLevel: 'MEDIUM' },
        { keywords: ['originator'], name: 'Originator', trustLevel: 'MEDIUM' },
        { keywords: ['whitelist'], name: 'Whitelisted User', trustLevel: 'LOW' },
    ];
    for (const pattern of specialPatterns) {
        const matchingFunctions = contract.functions.filter(f => {
            const nameLower = f.name.toLowerCase();
            return pattern.keywords.some(kw => nameLower.includes(kw));
        });
        // Check if these have specific modifiers (not just public)
        const restrictedFunctions = matchingFunctions.filter(f => f.modifiers.length > 0 ||
            f.visibility === 'internal' ||
            f.visibility === 'private');
        if (restrictedFunctions.length > 0) {
            const capabilities = restrictedFunctions.map(f => createCapabilityFromFunction(f, contract.name));
            roles.push({
                id: `ROLE_${pattern.name.toUpperCase().replace(/ /g, '_')}_${contract.name}`,
                name: pattern.name,
                category: 'trusted',
                trustLevel: pattern.trustLevel,
                trustReasoning: `${pattern.name} role with ${capabilities.length} specific capabilities`,
                capabilities,
                constraints: deriveConstraints(capabilities),
                sourceContract: contract.name,
                relatedFunctions: restrictedFunctions.map(f => `${f.name}()`),
                riskIfCompromised: `${pattern.name} can manipulate ${capabilities.length} functions`,
                isSinglePointOfFailure: false
            });
        }
    }
    return roles;
}
/**
 * Detect governance roles (Timelock, Multisig)
 */
function detectGovernanceRoles(contract) {
    const roles = [];
    // Timelock detection
    const hasTimelock = contract.stateVariables.some(sv => sv.name.toLowerCase().includes('timelock') ||
        sv.name.toLowerCase().includes('delay')) || contract.functions.some(f => f.name.toLowerCase().includes('timelock') ||
        f.name.toLowerCase().includes('execute') && f.modifiers.some(m => m.toLowerCase().includes('timelock')));
    if (hasTimelock) {
        const timelockFuncs = contract.functions.filter(f => f.name.toLowerCase().includes('timelock') ||
            f.name.toLowerCase().includes('schedule') ||
            f.name.toLowerCase().includes('execute') && f.modifiers.some(m => m.toLowerCase().includes('timelock')));
        roles.push({
            id: 'ROLE_TIMELOCK',
            name: 'Timelock Controller',
            category: 'trusted',
            addressSource: 'Timelock contract',
            addressType: 'immutable',
            trustLevel: 'HIGH',
            trustReasoning: 'Time-delayed execution provides security against immediate attacks',
            capabilities: timelockFuncs.map(f => createCapabilityFromFunction(f, contract.name)),
            constraints: ['Execution delayed by configured time period', 'Can be cancelled during delay'],
            sourceContract: contract.name,
            relatedFunctions: timelockFuncs.map(f => f.name + '()'),
            riskIfCompromised: 'Attacker with timelock control can queue malicious transactions',
            isSinglePointOfFailure: false
        });
    }
    // Multisig detection
    const hasMultisig = contract.stateVariables.some(sv => sv.name.toLowerCase().includes('guardians') ||
        sv.name.toLowerCase().includes('owners') && sv.type.includes('[]') ||
        sv.name.toLowerCase().includes('signers') ||
        sv.name.toLowerCase().includes('threshold'));
    if (hasMultisig) {
        roles.push({
            id: 'ROLE_MULTISIG',
            name: 'Multisig Wallet',
            category: 'trusted',
            addressSource: 'Multiple signers',
            addressType: 'state-var',
            trustLevel: 'HIGH',
            trustReasoning: 'Multiple signatures required reduces single point of compromise',
            capabilities: [],
            constraints: ['Requires M-of-N signatures', 'Confirmation delay possible'],
            sourceContract: contract.name,
            relatedFunctions: [],
            riskIfCompromised: 'Majority of signers must be compromised',
            isSinglePointOfFailure: false
        });
    }
    return roles;
}
// ============================================================
// NON-TRUSTED ROLE EXTRACTION
// ============================================================
function extractNonTrustedRoles(contracts, registry) {
    const roles = [];
    const seenNonTrusted = new Set();
    for (const contract of contracts) {
        const contractFuncs = registry.get(contract.name) || [];
        // Find public/external functions WITHOUT access control
        const publicFunctions = contract.functions.filter(f => {
            if (f.visibility !== 'external' && f.visibility !== 'public')
                return false;
            if (f.stateMutability === 'view' || f.stateMutability === 'pure')
                return false;
            // Skip constructors
            if (f.kind === 'constructor')
                return false;
            // Check if has NO access control modifiers
            const hasAccessControl = f.modifiers.some(m => {
                const mLower = m.toLowerCase();
                return mLower.includes('only') ||
                    mLower.includes('require') ||
                    mLower.includes('auth') ||
                    mLower.includes('role');
            });
            // Also check function name patterns that indicate auth
            const nameHasAuthHint = f.name.toLowerCase().includes('only') ||
                f.name.toLowerCase().includes('restricted');
            return !hasAccessControl && !nameHasAuthHint;
        });
        if (publicFunctions.length > 0) {
            // Categorize the type of user interaction
            const categories = categorizePublicFunctions(publicFunctions, contract);
            for (const [categoryName, funcs] of Object.entries(categories)) {
                const roleId = `ROLE_PUBLIC_${categoryName.toUpperCase().replace(/ /g, '_')}`;
                if (!seenNonTrusted.has(roleId)) {
                    seenNonTrusted.add(roleId);
                    const capabilities = funcs.map(f => createCapabilityFromFunction(f, contract.name));
                    roles.push({
                        id: roleId,
                        name: categoryName,
                        category: 'non-trusted',
                        addressSource: 'msg.sender (any caller)',
                        addressType: 'msg-sender',
                        trustLevel: 'NONE',
                        trustReasoning: 'No authentication required - anyone can call these functions',
                        capabilities,
                        constraints: ['May require token approval', 'May require balance checks', 'Rate limits may apply'],
                        sourceContract: contract.name,
                        relatedFunctions: funcs.map(f => `${f.name}()`),
                        riskIfCompromised: assessPublicRisk(categoryName, capabilities),
                        isSinglePointOfFailure: false
                    });
                }
            }
        }
        // Specific non-trusted role: Borrower/Lender
        const borrowerPattern = detectBorrowerRole(contract, registry);
        if (borrowerPattern) {
            const roleId = 'ROLE_BORROWER';
            if (!seenNonTrusted.has(roleId)) {
                seenNonTrusted.add(roleId);
                roles.push(borrowerPattern);
            }
        }
    }
    return roles;
}
/**
 * Detect borrower/lender specific role
 */
function detectBorrowerRole(contract, registry) {
    const borrowRelatedFuncs = contract.functions.filter(f => {
        const nameLower = f.name.toLowerCase();
        return nameLower.includes('borrow') ||
            nameLower.includes('repay') ||
            nameLower.includes('collateral');
    });
    if (borrowRelatedFuncs.length === 0)
        return null;
    const capabilities = borrowRelatedFuncs.map(f => createCapabilityFromFunction(f, contract.name));
    return {
        id: 'ROLE_BORROWER',
        name: 'Borrower',
        category: 'non-trusted',
        addressSource: 'msg.sender (authenticated via position)',
        addressType: 'msg-sender',
        trustLevel: 'LOW',
        trustReasoning: 'Borrower can only interact with their own positions',
        capabilities,
        constraints: ['Must have collateral posted', 'Must maintain health factor', 'Subject to liquidation'],
        sourceContract: contract.name,
        relatedFunctions: borrowRelatedFuncs.map(f => `${f.name}()`),
        riskIfCompromised: 'Borrower can default on loans causing bad debt',
        isSinglePointOfFailure: false
    };
}
// ============================================================
// ROLE HIERARCHY & RELATIONSHIPS
// ============================================================
function buildRoleHierarchy(trustedRoles, contracts) {
    const relationships = [];
    for (const contract of contracts) {
        // Detect grant/revoke relationships
        for (const func of contract.functions) {
            const nameLower = func.name.toLowerCase();
            // Grant patterns
            if (nameLower.includes('grant') || nameLower.includes('assign') || nameLower.includes('set')) {
                const targetRole = inferTargetRole(func, trustedRoles);
                if (targetRole) {
                    relationships.push({
                        fromRole: 'Owner/Admin',
                        toRole: targetRole,
                        relationshipType: 'assigns-to',
                        mechanism: `${func.name}() in ${contract.name}`
                    });
                }
            }
            // Revoke patterns
            if (nameLower.includes('revoke') || nameLower.includes('remove') || nameLower.includes('strip')) {
                const targetRole = inferTargetRole(func, trustedRoles);
                if (targetRole) {
                    relationships.push({
                        fromRole: 'Owner/Admin',
                        toRole: targetRole,
                        relationshipType: 'revokes-from',
                        mechanism: `${func.name}() in ${contract.name}`
                    });
                }
            }
        }
    }
    // Add implied hierarchy (Owner > Admin > Manager > Operator)
    const roleNames = trustedRoles.map(r => r.name);
    if (roleNames.includes('Owner') && roleNames.includes('Admin')) {
        relationships.push({
            fromRole: 'Owner',
            toRole: 'Admin',
            relationshipType: 'can-escalate-to',
            mechanism: 'Ownership implies administrative rights'
        });
    }
    return relationships;
}
// ============================================================
// CAPABILITY & CONSTRAINT ANALYSIS
// ============================================================
function findCapabilitiesForModifier(contract, primaryModifier, modifierVariants) {
    const capabilities = [];
    for (const func of contract.functions) {
        const funcModifiers = func.modifiers.map(m => m.toLowerCase());
        // Check if function uses this modifier
        const usesModifier = modifierVariants.some(variant => funcModifiers.some(fm => fm.includes(variant)));
        if (usesModifier && (func.visibility === 'external' || func.visibility === 'public')) {
            if (func.stateMutability !== 'view' && func.stateMutability !== 'pure') {
                capabilities.push(createCapabilityFromFunction(func, contract.name));
            }
        }
    }
    return capabilities;
}
function createCapabilityFromFunction(func, contractName) {
    const signature = `${func.name}(${func.parameters.map(p => p.type).join(',')})`;
    // Categorize the capability
    const category = categorizeCapability(func);
    // Assess impact level
    const impact = assessCapabilityImpact(func);
    // Generate description
    const description = generateCapabilityDescription(func);
    return {
        functionSignature: signature,
        contractName,
        category,
        impact,
        description
    };
}
function categorizeCapability(func) {
    const nameLower = func.name.toLowerCase();
    // Admin functions
    if (nameLower.includes('owner') || nameLower.includes('transferown') || nameLower.includes('renounce')) {
        return 'admin';
    }
    // Emergency functions
    if (nameLower.includes('pause') || nameLower.includes('unpause') ||
        nameLower.includes('emergency') || nameLower.includes('rescue')) {
        return 'emergency';
    }
    // Access control functions
    if (nameLower.includes('grant') || nameLower.includes('revoke') ||
        nameLower.includes('role') || nameLower.includes('setadmin')) {
        return 'access-control';
    }
    // Financial functions
    if (nameLower.includes('transfer') || nameLower.includes('mint') ||
        nameLower.includes('burn') || nameLower.includes('withdraw') ||
        nameLower.includes('deposit') || nameLower.includes('fund') ||
        nameLower.includes('collect') || nameLower.includes('send')) {
        return 'financial';
    }
    // Operational functions
    if (nameLower.includes('set') || nameLower.includes('update') ||
        nameLower.includes('configure') || nameLower.includes('change')) {
        return 'operational';
    }
    return 'unknown';
}
function assessCapabilityImpact(func) {
    const body = func.body;
    const nameLower = func.name.toLowerCase();
    // Critical impacts
    if (body?.hasExternalCall && body?.hasTransfer) {
        return 'critical';
    }
    if (nameLower.includes('mint') || nameLower.includes('burn') ||
        nameLower.includes('pause') || nameLower.includes('emergency')) {
        return 'critical';
    }
    // High impacts
    if (body?.hasTransfer || body?.hasDelegateCall) {
        return 'high';
    }
    if (nameLower.includes('withdraw') || nameLower.includes('transfer') ||
        nameLower.includes('setowner') || nameLower.includes('grant')) {
        return 'high';
    }
    // Medium impacts
    if (body?.hasExternalCall || func.stateVariablesWritten.length > 2) {
        return 'medium';
    }
    // Low impacts
    if (func.stateVariablesWritten.length <= 2) {
        return 'low';
    }
    return 'medium';
}
function generateCapabilityDescription(func) {
    const nameLower = func.name.toLowerCase();
    const params = func.parameters.map(p => p.type).join(', ');
    // Generate human-readable descriptions
    if (nameLower.includes('deposit'))
        return `Deposit assets into the protocol`;
    if (nameLower.includes('withdraw'))
        return `Withdraw assets from the protocol`;
    if (nameLower.includes('transfer'))
        return `Transfer tokens/assets`;
    if (nameLower.includes('mint'))
        return `Mint new tokens/shares`;
    if (nameLower.includes('burn'))
        return `Burn existing tokens/shares`;
    if (nameLower.includes('pause'))
        return `Pause protocol operations`;
    if (nameLower.includes('unpause'))
        return `Resume paused operations`;
    if (nameLower.includes('grant'))
        return `Grant permissions to an address`;
    if (nameLower.includes('revoke'))
        return `Revoke permissions from an address`;
    if (nameLower.includes('set') && nameLower.includes('oracle'))
        return `Update oracle price feed`;
    if (nameLower.includes('set') && nameLower.includes('fee'))
        return `Update fee configuration`;
    if (nameLower.includes('fund'))
        return `Fund loans or provide capital`;
    if (nameLower.includes('collect'))
        return `Collect payments or revenue`;
    if (nameLower.includes('liquidate'))
        return `Liquidate unhealthy positions`;
    if (nameLower.includes('borrow'))
        return `Borrow against collateral`;
    if (nameLower.includes('repay'))
        return `Repay outstanding debt`;
    if (nameLower.includes('emergency'))
        return `Emergency extraction of funds`;
    return `Execute ${func.name}(${params})`;
}
function deriveConstraints(capabilities) {
    const constraints = [];
    const hasFinancial = capabilities.some(c => c.category === 'financial');
    const hasEmergency = capabilities.some(c => c.category === 'emergency');
    const hasAccessControl = capabilities.some(c => c.category === 'access-control');
    if (hasEmergency) {
        constraints.push('Emergency actions may require additional safeguards');
    }
    if (hasFinancial && capabilities.length > 5) {
        constraints.push('Extensive financial access should be monitored');
    }
    if (hasAccessControl) {
        constraints.push('Cannot revoke own privileges');
    }
    // Check for timelock patterns
    const hasTimelocked = capabilities.some(c => c.description.toLowerCase().includes('delay') ||
        c.description.toLowerCase().includes('queue'));
    if (!hasTimelocked && capabilities.some(c => c.impact === 'critical')) {
        constraints.push('Consider adding timelock for critical operations');
    }
    return constraints;
}
// ============================================================
// TRUST LEVEL CALCULATION
// ============================================================
function calculateTrustLevel(capabilities) {
    if (capabilities.length === 0)
        return 'NONE';
    const criticalCount = capabilities.filter(c => c.impact === 'critical').length;
    const highCount = capabilities.filter(c => c.impact === 'high').length;
    if (criticalCount >= 2 || (criticalCount >= 1 && highCount >= 3)) {
        return 'CRITICAL';
    }
    if (criticalCount >= 1 || highCount >= 3) {
        return 'HIGH';
    }
    if (highCount >= 1 || capabilities.length >= 5) {
        return 'MEDIUM';
    }
    return 'LOW';
}
function generateTrustReasoning(roleName, capabilities, trustLevel) {
    const criticalCaps = capabilities.filter(c => c.impact === 'critical');
    const highCaps = capabilities.filter(c => c.impact === 'high');
    switch (trustLevel) {
        case 'CRITICAL':
            return `${roleName} has ${criticalCaps.length} critical and ${highCaps.length} high-impact capabilities including: ${criticalCaps.slice(0, 2).map(c => c.functionSignature).join(', ')}`;
        case 'HIGH':
            return `${roleName} controls ${capabilities.length} sensitive functions with potential for significant impact`;
        case 'MEDIUM':
            return `${roleName} has moderate privileges within defined scope`;
        case 'LOW':
            return `${roleName} has limited operational capabilities`;
        default:
            return 'Trust level could not be determined';
    }
}
function assessOwnerRisk(capabilities) {
    const criticalCaps = capabilities.filter(c => c.impact === 'critical');
    if (criticalCaps.length > 0) {
        return `Owner can execute ${criticalCaps.length} critical functions: ${criticalCaps.map(c => c.functionSignature).join(', ')}. Full protocol compromise possible.`;
    }
    return `Owner has administrative control over ${capabilities.length} functions. Verify ownership transfer protections.`;
}
function assessRoleRisk(roleName, capabilities) {
    const financialCaps = capabilities.filter(c => c.category === 'financial');
    const emergencyCaps = capabilities.filter(c => c.category === 'emergency');
    if (emergencyCaps.length > 0) {
        return `${roleName} can trigger emergency protocols: ${emergencyCaps.map(c => c.functionSignature).join(', ')}`;
    }
    if (financialCaps.length > 2) {
        return `${roleName} has extensive financial control over ${financialCaps.length} fund movement functions`;
    }
    return `${roleName} can execute ${capabilities.length} privileged operations`;
}
function assessPublicRisk(roleName, capabilities) {
    const financialCaps = capabilities.filter(c => c.category === 'financial');
    if (financialCaps.length > 0) {
        return `Public access to financial functions could enable exploitation: ${financialCaps.map(c => c.functionSignature).join(', ')}`;
    }
    return `Unrestricted access may enable DoS or unexpected state changes`;
}
// ============================================================
// SUMMARY GENERATION
// ============================================================
function generateRoleSummary(trustedRoles, nonTrustedRoles, contracts) {
    const spoRoles = trustedRoles.filter(r => r.isSinglePointOfFailure);
    // Count public functions
    let publicFunctionCount = 0;
    for (const contract of contracts) {
        publicFunctionCount += contract.functions.filter(f => {
            if (f.visibility !== 'external' && f.visibility !== 'public')
                return false;
            if (f.stateMutability === 'view' || f.stateMutability === 'pure')
                return false;
            return !f.modifiers.some(m => {
                const ml = m.toLowerCase();
                return ml.includes('only') || ml.includes('require') || ml.includes('auth');
            });
        }).length;
    }
    // Check for timelock/multisig
    const hasTimelock = contracts.some(c => c.stateVariables.some(sv => sv.name.toLowerCase().includes('timelock')));
    const hasMultisig = contracts.some(c => c.stateVariables.some(sv => sv.name.toLowerCase().includes('guardians') ||
        (sv.name.toLowerCase().includes('owners') && sv.type.includes('[]')) ||
        sv.name.toLowerCase().includes('threshold')));
    return {
        trustedCount: trustedRoles.length,
        nonTrustedCount: nonTrustedRoles.length,
        highTrustCount: trustedRoles.filter(r => r.trustLevel === 'CRITICAL' || r.trustLevel === 'HIGH').length,
        singlePointsOfFailure: spoRoles.map(r => `${r.name} (${r.sourceContract})`),
        publicFunctionCount,
        hasTimelock,
        hasMultisig
    };
}
// ============================================================
// HELPER FUNCTIONS
// ============================================================
function isInterface(contract) {
    return contract.functions.every(f => f.body === undefined || f.body === null);
}
function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}
function formatRoleName(roleName) {
    return roleName
        .split(/[_\s]+/)
        .map(word => capitalize(word))
        .join(' ')
        .replace(/Role$/i, '')
        .trim() || roleName;
}
function extractRoleNameFromModifier(modifier, func, contract) {
    const modLower = modifier.toLowerCase();
    // Try to extract from modifier like "onlyRole(ADMIN_ROLE)"
    const roleMatch = modifier.match(/only[\w]*\(?(\w+)\)?/i);
    if (roleMatch && roleMatch[1]) {
        const candidate = roleMatch[1];
        // Filter out generic names
        if (!['role', 'hasrole', 'require'].includes(candidate.toLowerCase())) {
            return candidate;
        }
    }
    // Try to infer from function name
    const funcNameLower = func.name.toLowerCase();
    if (funcNameLower.includes('manager'))
        return 'MANAGER';
    if (funcNameLower.includes('guardian'))
        return 'GUARDIAN';
    if (funcNameLower.includes('operator'))
        return 'OPERATOR';
    return null;
}
function findRoleConstant(roleName, contract) {
    // Look for bytes32 constant matching role name
    const candidates = contract.stateVariables.filter(sv => {
        const nameUpper = sv.name.toUpperCase();
        const roleUpper = roleName.toUpperCase();
        return ((sv.type.includes('bytes32') || sv.type.includes('roles')) &&
            (nameUpper.includes(roleUpper) || roleUpper.includes(nameUpper.replace('_', ''))));
    });
    return candidates[0]?.name;
}
function inferTargetRole(func, trustedRoles) {
    const nameLower = func.name.toLowerCase();
    for (const role of trustedRoles) {
        const roleNameLower = role.name.toLowerCase();
        if (nameLower.includes(roleNameLower.replace(/\s+/g, ''))) {
            return role.name;
        }
    }
    // Check parameters for role hints
    for (const param of func.parameters) {
        const paramLower = (param.name || '').toLowerCase();
        if (paramLower.includes('role') || paramLower.includes('account')) {
            // Found a role-related parameter
            return param.name || undefined;
        }
    }
    return null;
}
function categorizePublicFunctions(functions, contract) {
    const categories = {
        'User (General)': [],
        'Depositor': [],
        'Trader': [],
        'Liquidator': []
    };
    for (const func of functions) {
        const nameLower = func.name.toLowerCase();
        if (nameLower.includes('deposit') || nameLower.includes('mint')) {
            categories['Depositor'].push(func);
        }
        else if (nameLower.includes('swap') || nameLower.includes('trade') || nameLower.includes('exchange')) {
            categories['Trader'].push(func);
        }
        else if (nameLower.includes('liquidate')) {
            categories['Liquidator'].push(func);
        }
        else {
            categories['User (General)'].push(func);
        }
    }
    // Remove empty categories
    Object.keys(categories).forEach(key => {
        if (categories[key].length === 0) {
            delete categories[key];
        }
    });
    return categories;
}
//# sourceMappingURL=role-extractor.js.map