"use strict";
// ============================================================
// TRACKATOR Tier 1 - Diagram Generator
// Generates Mermaid diagrams for contracts, state, and flows
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateAllDiagrams = generateAllDiagrams;
exports.getValueTransfers = getValueTransfers;
const state_inventory_1 = require("./state-inventory");
const function_registry_1 = require("./function-registry");
const call_graph_1 = require("./call-graph");
/**
 * Generate all diagrams for a set of contracts
 */
function generateAllDiagrams(contracts, options = {}) {
    const { includeRisk = true, includeState = true, includeFlows = true, includeValueFlow = true // NEW: Include value flow by default
     } = options;
    const diagramSet = {
        contractDiagrams: [],
        stateDiagrams: [],
        flowDiagrams: [],
        riskDiagrams: [],
        valueFlowDiagrams: [], // NEW
        valueTransfers: [] // NEW: Raw transfer data
    };
    // Build supporting data structures
    const callGraph = (0, call_graph_1.buildCallGraph)(contracts);
    const registry = (0, function_registry_1.buildFunctionRegistry)(contracts);
    // Contract structure diagrams
    const classDiagramStr = (0, call_graph_1.generateClassDiagram)(contracts);
    diagramSet.contractDiagrams.push(generateContractOverview(contracts), { type: 'classDiagram', title: 'Class Diagram', code: classDiagramStr, description: 'Class inheritance and relationships' }, generateInheritanceGraph(contracts));
    // Per-contract diagrams
    for (const contract of contracts) {
        diagramSet.contractDiagrams.push(generateContractDetail(contract), generateEventFlow(contract));
        if (includeState) {
            const inventory = (0, state_inventory_1.generateStateInventory)(contract);
            const regFuncs = registry.get(contract.name) || [];
            diagramSet.stateDiagrams.push(generateStorageLayout(inventory), generateStateTransition(contract, regFuncs));
        }
        if (includeFlows) {
            diagramSet.flowDiagrams.push(...generateExecutionFlows(contract, callGraph, registry));
        }
        if (includeRisk) {
            const regFuncs = registry.get(contract.name) || [];
            diagramSet.riskDiagrams.push(generateRiskHeatmap(contract, regFuncs), generateAccessControlMap(contract, regFuncs));
        }
    }
    // NEW: Generate Value Flow diagrams for the entire protocol
    if (includeValueFlow) {
        // Detect and store raw value transfers for summary tables
        diagramSet.valueTransfers = detectValueTransfers(contracts, registry);
        // Generate Mermaid diagrams
        diagramSet.valueFlowDiagrams.push(...generateProtocolValueFlows(contracts, registry));
    }
    return diagramSet;
}
/**
 * Generate overview diagram showing all contracts and relationships
 */
function generateContractOverview(contracts) {
    const lines = ['graph TB'];
    // Add contract nodes
    for (const contract of contracts) {
        const label = `${contract.name}\\n`;
        const details = [
            `${contract.functions.length} functions`,
            `${contract.stateVariables.length} state vars`,
            `${contract.events.length} events`,
            `${contract.modifiers.length} modifiers`
        ].join('\\n');
        lines.push(`  "${contract.name}"["${label}${details}"]`);
    }
    // Add inheritance relationships
    lines.push('');
    lines.push('  %% Inheritance');
    for (const contract of contracts) {
        for (const parent of contract.inherited) {
            lines.push(`  "${parent}" --> "${contract.name}"`);
        }
    }
    // Style by complexity
    lines.push('');
    lines.push('  %% Styling');
    for (const contract of contracts) {
        const funcCount = contract.functions.length;
        let color = '#e1f5fe'; // Light blue - simple
        if (funcCount > 20) {
            color = '#ffebee'; // Red - complex
        }
        else if (funcCount > 10) {
            color = '#fff3e0'; // Orange - moderate
        }
        lines.push(`  style "${contract.name}" fill:${color},stroke:#333`);
    }
    return {
        type: 'flowchart',
        title: 'Protocol Overview',
        code: lines.join('\n'),
        description: 'High-level view of all contracts in the protocol'
    };
}
/**
 * Generate inheritance graph
 */
function generateInheritanceGraph(contracts) {
    const lines = ['graph TD'];
    // Group by inheritance chains
    const processed = new Set();
    for (const contract of contracts) {
        if (processed.has(contract.name))
            continue;
        // Trace full inheritance chain
        const chain = getInheritanceChain(contract.name, contracts);
        chain.forEach(c => processed.add(c));
        // Draw chain
        for (let i = 0; i < chain.length - 1; i++) {
            lines.push(`  "${chain[i]}" --> "${chain[i + 1]}"`);
        }
    }
    return {
        type: 'flowchart',
        title: 'Inheritance Graph',
        code: lines.join('\n'),
        description: 'Contract inheritance hierarchy'
    };
}
function getInheritanceChain(name, contracts) {
    const chain = [name];
    const contract = contracts.find(c => c.name === name);
    if (!contract || contract.inherited.length === 0) {
        return chain;
    }
    // For simplicity, just add direct parents (could recurse deeper)
    chain.unshift(...contract.inherited.filter(p => !chain.includes(p)));
    return chain;
}
/**
 * Generate detailed single-contract diagram
 */
function generateContractDetail(contract) {
    const lines = ['classDiagram'];
    // Main class
    lines.push(`class ${contract.name} {`);
    // State variables section
    lines.push('  <<State Variables>>');
    for (const sv of contract.stateVariables) {
        const icon = getVisibilityIcon(sv.visibility);
        lines.push(`    ${icon}${sv.name} : ${sv.type}`);
    }
    lines.push('  --');
    // Functions section
    lines.push('  <<Functions>>');
    for (const func of contract.functions) {
        const icon = getVisibilityIcon(func.visibility);
        const params = func.parameters.map(p => p.type).join(', ');
        const returns = func.returnParameters.length > 0 ?
            ` ${func.returnParameters.map(p => p.type).join(', ')}` : '';
        const badge = getMutabilityBadge(func.stateMutability);
        lines.push(`    ${icon}${func.name}(${params})${returns} ${badge}`);
    }
    lines.push('}');
    // Events
    for (const event of contract.events) {
        const params = event.parameters.map(p => p.indexed ? `${p.type} indexed` : p.type).join(', ');
        lines.push(`${contract.name}..>${event.name} : ${params}`);
    }
    return {
        type: 'classDiagram',
        title: `${contract.name} - Detailed Structure`,
        code: lines.join('\n'),
        description: 'Complete structure of contract including state variables and functions'
    };
}
/**
 * Generate storage layout diagram
 */
function generateStorageLayout(inventory) {
    const lines = ['graph LR'];
    const contractName = inventory.contractName || inventory.contract || 'Unknown';
    lines.push('  subgraph Storage Layout[' + contractName + ']');
    // Show slots with variables
    const variables = inventory.variables || [];
    for (const item of variables) {
        const slotLabel = `Slot ${item.computedSlot ?? item.slot ?? 'unknown'}`;
        const varName = item.variable?.name || item.name || 'unknown';
        const typeInfo = item.typeInfo || { category: 'unknown' };
        const byteSize = item.byteSize || item.typeSize || 0;
        const offset = item.computedOffset || item.offset || 0;
        const varLabel = `${varName}\\n(${typeInfo.category})\\n${byteSize} bytes`;
        lines.push(`    ${slotLabel}["${slotLabel}"] -- ${offset} --> ${varName}["${varLabel}"]`);
        const packedWith = item.packedWith || [];
        if (packedWith.length > 0) {
            lines.push(`    %% Packed with: ${packedWith.join(', ')}`);
        }
    }
    // Show mappings separately
    const mappings = inventory.mappings || [];
    if (mappings.length > 0) {
        lines.push('  subgraph Mappings[Mappings]');
        for (const mapping of mappings) {
            lines.push(`    M${mapping.slot}["${mapping.variable || mapping.mappingVar}\\n(mapping(${mapping.keyType} => ${mapping.valueType}))"]`);
        }
        lines.push('  end');
    }
    lines.push('  end');
    // Highlight packing issues
    const packingIssues = inventory.potentialPackingIssues || [];
    if (packingIssues.length > 0) {
        lines.push('');
        lines.push('  %% Packing Issues');
        for (const issue of packingIssues) {
            lines.push(`    style "Slot ${issue.slot}" fill:#ff6b6b`);
        }
    }
    return {
        type: 'flowchart',
        title: `${contractName} - Storage Layout`,
        code: lines.join('\n'),
        description: 'Storage slot assignments and variable packing'
    };
}
/**
 * Generate state transition diagram based on function analysis
 */
function generateStateTransition(contract, registeredFuncs) {
    const lines = ['stateDiagram-v2'];
    lines.push('  [*] --> Idle');
    // Identify state-changing functions and their effects
    // Cast to any to handle extended RegisteredFunction shape from function-registry
    const stateChangingFuncs = registeredFuncs.filter((f) => {
        const funcDef = f.function || {};
        const stateImpact = f.stateImpact || {};
        return funcDef.stateMutability !== 'view' &&
            funcDef.stateMutability !== 'pure' &&
            stateImpact.writes && stateImpact.writes.length > 0;
    });
    // Create states for major operations
    const states = new Set(['Idle']);
    for (const func of stateChangingFuncs.slice(0, 10)) { // Limit to avoid huge diagrams
        const funcName = func.function?.name || func.name || 'unknown';
        const stateName = funcName.charAt(0).toUpperCase() +
            funcName.slice(1).replace(/([A-Z])/g, '_$1');
        states.add(stateName);
    }
    // Add transitions
    for (const func of stateChangingFuncs.slice(0, 10)) {
        const fromState = 'Idle';
        const funcName = func.function?.name || func.name || 'unknown';
        const toState = funcName.charAt(0).toUpperCase() +
            funcName.slice(1).replace(/([A-Z])/g, '_$1');
        const writes = (func.stateImpact?.writes || []).slice(0, 3).join(', ');
        lines.push(`  ${fromState} --> ${toState}: ${funcName}()`);
        lines.push(`  ${toState} --> Idle: complete`);
    }
    return {
        type: 'stateDiagram',
        title: `${contract.name} - State Transitions`,
        code: lines.join('\n'),
        description: 'Major state changes triggered by function calls'
    };
}
/**
 * Generate event emission flow diagram
 */
function generateEventFlow(contract) {
    const lines = ['sequenceDiagram'];
    // Participants
    lines.push('  participant Caller');
    lines.push(`  participant ${contract.name}`);
    lines.push('  participant EventLog');
    // Map events to emitting functions
    const eventEmitters = new Map();
    for (const func of contract.functions) {
        // This would need deeper analysis to find actual emit statements
        // For now, we'll create a simplified version
    }
    // Show event emissions (simplified)
    for (const event of contract.events.slice(0, 5)) {
        lines.push(`  Caller->>${contract.name}: trigger action`);
        lines.push(`${contract.name}-->EventLog: ${event.name}`);
        lines.push(`  Note right of EventLog: ${event.parameters.map(p => p.type).join(', ')}`);
    }
    return {
        type: 'sequenceDiagram',
        title: `${contract.name} - Event Flow`,
        code: lines.join('\n'),
        description: 'Events emitted by the contract'
    };
}
/**
 * Generate execution flow diagrams for entry points
 */
function generateExecutionFlows(contract, callGraph, registry) {
    const diagrams = [];
    const entryPoints = (0, function_registry_1.getEntryPoints)(registry);
    // Limit to top entry points to avoid overwhelming output
    const topEntries = entryPoints
        .filter((e) => e.contract === contract.name)
        .slice(0, 5);
    for (const entry of topEntries) {
        const funcName = entry.function?.name || entry.name || 'unknown';
        const key = `${entry.contract}.${funcName}`;
        const seqDiagram = (0, call_graph_1.generateSequenceDiagram)(callGraph, key, 3);
        diagrams.push({
            type: 'sequenceDiagram',
            title: `Execution Flow: ${funcName}()`,
            code: seqDiagram,
            description: `Call sequence when invoking ${funcName}`
        });
    }
    return diagrams;
}
/**
 * Generate risk heatmap diagram
 */
function generateRiskHeatmap(contract, registeredFuncs) {
    const lines = ['graph TB'];
    lines.push('  subgraph Risk Assessment[' + contract.name + ']');
    // Get high-risk functions - filter by score since we have an array, not a Map
    const highRisk = registeredFuncs
        .filter((f) => f.risk?.score >= 25)
        .filter(f => f.contract === contract.name)
        .slice(0, 10);
    for (const func of highRisk) {
        const funcName = func.function?.name || func.name || 'unknown';
        const riskColor = getRiskColor(func.risk?.overall || 'low');
        const factors = (func.risk?.factors || []).slice(0, 2)
            .map((f) => (f.type || '').replace(/-/g, ' '))
            .join(', ');
        lines.push(`    ${funcName}["${funcName}\\nScore: ${func.risk?.score || 0}\\n${factors}"]`);
        lines.push(`    style ${funcName} fill:${riskColor}`);
    }
    if (highRisk.length === 0) {
        lines.push('    NoHighRisk["No high-risk functions detected"]');
        lines.push('    style NoHighRisk fill:#c8e6c9');
    }
    lines.push('  end');
    return {
        type: 'flowchart',
        title: `${contract.name} - Risk Heatmap`,
        code: lines.join('\n'),
        description: 'Functions colored by risk level'
    };
}
/**
 * Generate access control map
 */
function generateAccessControlMap(contract, registeredFuncs) {
    const lines = ['graph LR'];
    // Group functions by access control level
    const groups = new Map();
    for (const func of registeredFuncs) {
        const level = func.accessControl?.level || 'unknown';
        const funcName = func.function?.name || func.name || 'unknown';
        const existing = groups.get(level) || [];
        existing.push(funcName);
        groups.set(level, existing);
    }
    // Create subgraphs for each access level
    const levelColors = {
        'public': '#ffcdd2', // Red - most permissive
        'external': '#f8bbd0', // Pink
        'restricted': '#c8e6c9', // Green - controlled
        'internal': '#b3e5fc', // Blue
        'private': '#e1bee7' // Purple - most restricted
    };
    for (const [level, funcs] of groups) {
        lines.push(`  subgraph ${level} [${level.toUpperCase()}]`);
        for (const func of funcs) {
            lines.push(`    ${func}`);
        }
        lines.push(`  end`);
        lines.push(`  style ${level} fill:${levelColors[level] || '#eeeeee'}`);
    }
    return {
        type: 'flowchart',
        title: `${contract.name} - Access Control Map`,
        code: lines.join('\n'),
        description: 'Functions grouped by access control level'
    };
}
// ============================================================
// VALUE FLOW DIAGRAM GENERATION (NEW FEATURE)
// ============================================================
/**
 * Sanitize string for safe use in Mermaid diagrams
 * Removes newlines, balances quotes, escapes special chars
 */
function sanitizeMermaidString(str) {
    return str
        .replace(/\n/g, ' ') // Remove newlines
        .replace(/\r/g, '') // Remove carriage returns
        .replace(/\t/g, ' ') // Replace tabs with spaces
        .replace(/"/g, "'") // Escape double quotes
        .replace(/\s+/g, ' ') // Collapse multiple spaces
        .trim();
}
/**
 * Sanitize a complete Mermaid diagram code block
 * Fixes common syntax issues that break rendering
 */
function sanitizeMermaidCode(code) {
    return code
        .split('\n')
        .map(line => line.trimEnd()) // Remove trailing whitespace
        .filter(line => line.length > 0 || true) // Keep empty lines for structure
        .join('\n');
}
/**
 * Detect value transfer patterns across all contracts
 * Analyzes function names, calls, state variables, and events
 */
function detectValueTransfers(contracts, registry) {
    const transfers = [];
    // Patterns that indicate value movement (using string methods instead of regex for safety)
    // We check function names using includes() for simplicity and reliability
    for (const contract of contracts) {
        // Check state variables for asset holdings
        const hasERC20 = contract.stateVariables.some(sv => sv.type.toLowerCase().includes('erc20') ||
            sv.type.toLowerCase().includes('ierc20') ||
            sv.name.toLowerCase().includes('token'));
        const hasETH = contract.functions.some(f => f.stateMutability === 'payable');
        const hasNFT = contract.stateVariables.some(sv => sv.type.toLowerCase().includes('erc721') ||
            sv.type.toLowerCase().includes('nft') ||
            contract.name.toLowerCase().includes('nft'));
        const isTokenContract = contract.name.toLowerCase().includes('token') ||
            contract.inherited.some(i => i.toLowerCase().includes('erc20'));
        const isVault = contract.name.toLowerCase().includes('vault');
        const isExchange = contract.name.toLowerCase().includes('exchange');
        const isLoans = contract.name.toLowerCase().includes('loan');
        const isCalculator = contract.name.toLowerCase().includes('calculator') ||
            contract.name.toLowerCase().includes('nav');
        // Analyze each external function for value patterns
        for (const func of contract.functions) {
            if (func.visibility !== 'external' && func.visibility !== 'public')
                continue;
            if (func.stateMutability === 'view' || func.stateMutability === 'pure')
                continue;
            const funcName = func.name;
            const body = func.body;
            const calls = func.calls || [];
            const hasExternalCall = body?.hasExternalCall;
            const hasTransfer = body?.hasTransfer;
            // Detect based on function name patterns (using string includes for safety)
            if (funcName.toLowerCase().includes('mint')) {
                if (isTokenContract) {
                    transfers.push({
                        from: contract.name,
                        to: 'User',
                        asset: 'Shares/Tokens',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'mint',
                        condition: 'Role-based access control'
                    });
                }
                else if (isLoans || isExchange) {
                    transfers.push({
                        from: 'Protocol',
                        to: 'User',
                        asset: 'NFT (Loan Position)',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'mint',
                        condition: 'Valid loan data required'
                    });
                }
            }
            if (funcName.toLowerCase().includes('burn')) {
                if (isTokenContract) {
                    transfers.push({
                        from: 'User',
                        to: contract.name,
                        asset: 'Shares/Tokens',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'burn',
                        condition: 'Sufficient balance required'
                    });
                }
            }
            if (funcName.toLowerCase().includes('deposit')) {
                if (isVault) {
                    transfers.push({
                        from: 'User',
                        to: contract.name,
                        asset: hasERC20 ? 'Underlying Asset' : 'ETH',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'deposit',
                        condition: 'Approval may be required'
                    });
                }
            }
            if (funcName.toLowerCase().includes('withdraw') || funcName.toLowerCase().includes('redeem')) {
                if (isVault) {
                    transfers.push({
                        from: contract.name,
                        to: 'User',
                        asset: hasERC20 ? 'Underlying Asset' : 'ETH',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'withdraw',
                        condition: 'Sufficient shares/balance required'
                    });
                }
                else if (isLoans) {
                    // Could be servicerWithdraw, originatorWithdraw, investorWithdraw
                    if (funcName.includes('servicer')) {
                        transfers.push({
                            from: contract.name,
                            to: 'Servicer',
                            asset: 'Fees/Principal',
                            viaFunction: funcName,
                            contractName: contract.name,
                            type: 'collect',
                            condition: 'Only callable by authorized servicer'
                        });
                    }
                    else if (funcName.includes('originator')) {
                        transfers.push({
                            from: contract.name,
                            to: 'Originator',
                            asset: 'Excess Principal',
                            viaFunction: funcName,
                            contractName: contract.name,
                            type: 'withdraw',
                            condition: 'Loan must be fully paid or terminated'
                        });
                    }
                    else if (funcName.includes('investor')) {
                        transfers.push({
                            from: contract.name,
                            to: 'Investor',
                            asset: 'Principal + Interest',
                            viaFunction: funcName,
                            contractName: contract.name,
                            type: 'withdraw',
                            condition: 'Loan must be fully paid'
                        });
                    }
                }
            }
            if (funcName.toLowerCase().includes('fund') && !funcName.toLowerCase().includes('refund')) {
                if (isVault && isLoans === false) {
                    transfers.push({
                        from: contract.name,
                        to: 'Loans Contract',
                        asset: 'Capital',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'fund',
                        condition: 'Manager role required'
                    });
                }
            }
            if (funcName.toLowerCase().includes('pay') || funcName.toLowerCase().includes('repay')) {
                if (isLoans) {
                    transfers.push({
                        from: 'Borrower',
                        to: contract.name,
                        asset: 'Principal + Interest',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'pay',
                        condition: 'Must be called by borrower or authorized party'
                    });
                }
            }
            if (funcName.toLowerCase().includes('collect') || funcName.toLowerCase().includes('cashflow') ||
                funcName.toLowerCase().includes('claim') || funcName.toLowerCase().includes('disburse')) {
                if (isVault) {
                    transfers.push({
                        from: 'Loans Contract',
                        to: contract.name,
                        asset: 'Repayments + Interest',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'collect',
                        condition: 'Accrued interest available'
                    });
                }
            }
            if (funcName.toLowerCase().includes('swap') || funcName.toLowerCase().includes('exchange') ||
                funcName.toLowerCase().includes('offer') || funcName.toLowerCase().includes('sale') ||
                funcName.toLowerCase().includes('purchase') || funcName.toLowerCase().includes('buy') ||
                funcName.toLowerCase().includes('sell')) {
                if (isExchange) {
                    if (funcName.includes('accept')) {
                        transfers.push({
                            from: 'Buyer',
                            to: contract.name,
                            asset: 'Payment (ETH/ERC20)',
                            viaFunction: funcName,
                            contractName: contract.name,
                            type: 'swap',
                            condition: 'Valid offer must exist'
                        });
                        transfers.push({
                            from: contract.name,
                            to: 'Buyer',
                            asset: 'NFT (Loan Position)',
                            viaFunction: funcName,
                            contractName: contract.name,
                            type: 'transfer',
                            condition: 'Offer accepted by seller'
                        });
                        transfers.push({
                            from: contract.name,
                            to: 'Seller',
                            asset: 'Proceeds',
                            viaFunction: funcName,
                            contractName: contract.name,
                            type: 'transfer',
                            condition: 'Minus exchange fees'
                        });
                    }
                    else if (funcName.includes('create') || funcName.includes('offer')) {
                        transfers.push({
                            from: 'Seller',
                            to: contract.name,
                            asset: 'NFT (Loan Position)',
                            viaFunction: funcName,
                            contractName: contract.name,
                            type: 'approve',
                            condition: 'Must own the NFT'
                        });
                    }
                }
                else if (isVault) {
                    transfers.push({
                        from: 'Seller',
                        to: 'Buyer (via Vault)',
                        asset: 'Loan NFT + Payment',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'swap',
                        condition: 'Secondary market operation'
                    });
                }
            }
            if ((funcName.toLowerCase().includes('approve') || funcName.toLowerCase().includes('allowance')) && !isTokenContract) {
                transfers.push({
                    from: 'Owner',
                    to: 'Spender/Operator',
                    asset: 'Allowance',
                    viaFunction: funcName,
                    contractName: contract.name,
                    type: 'approve',
                    condition: 'Sets spending limit'
                });
            }
            // Detect ETH transfers in payable functions
            if (hasETH && func.stateMutability === 'payable') {
                if (!transfers.find(t => t.viaFunction === funcName && t.contractName === contract.name)) {
                    transfers.push({
                        from: 'User (msg.sender)',
                        to: contract.name,
                        asset: 'ETH',
                        viaFunction: funcName,
                        contractName: contract.name,
                        type: 'deposit',
                        condition: `Payable - receives ETH`
                    });
                }
            }
            // Detect external calls that might be transfers
            if (hasExternalCall || hasTransfer) {
                for (const call of calls) {
                    if (call === 'transfer' || call === 'transferFrom' || call === 'safeTransferFrom') {
                        // Already captured above, skip duplicates
                    }
                }
            }
        }
        // Special handling for TrustedSpender and TrustedCalls
        if (contract.name === 'TrustedSpender') {
            transfers.push({
                from: 'Vault/User',
                to: 'TrustedSpender',
                asset: 'Allowance (ERC20)',
                viaFunction: 'setAllowance',
                contractName: 'TrustedSpender',
                type: 'approve',
                condition: 'Delegate must be set first'
            });
            transfers.push({
                from: 'TrustedSpender',
                to: 'Recipient',
                asset: 'ERC20 Tokens',
                viaFunction: 'executeTransfer',
                contractName: 'TrustedSpender',
                type: 'transfer',
                condition: 'Requires valid delegate + allowance'
            });
            transfers.push({
                from: 'Owner',
                to: 'TrustedSpender',
                asset: 'NFT Allowance',
                viaFunction: 'setNFTAllowance',
                contractName: 'TrustedSpender',
                type: 'approve',
                condition: 'Sets NFT spending limit'
            });
            transfers.push({
                from: 'TrustedSpender',
                to: 'Recipient',
                asset: 'NFT (ERC721)',
                viaFunction: 'executeNFTTransfer',
                contractName: 'TrustedSpender',
                type: 'transfer',
                condition: 'Requires valid NFT allowance'
            });
        }
        if (contract.name === 'TrustedCalls') {
            transfers.push({
                from: 'Safe Account Owner',
                to: 'TrustedCalls',
                asset: 'Call Authorization',
                viaFunction: 'addTrustedCall',
                contractName: 'TrustedCalls',
                type: 'approve',
                condition: 'Adds trusted call hash'
            });
            transfers.push({
                from: 'TrustedCalls',
                to: 'Target Contract',
                asset: 'Function Execution',
                viaFunction: 'executeTrustedCall',
                contractName: 'TrustedCalls',
                type: 'transfer',
                condition: 'Must be pre-authorized call'
            });
        }
        // NavCalculator doesn't move value directly but affects pricing
        if (isCalculator) {
            transfers.push({
                from: 'Price Feed / Oracle',
                to: contract.name,
                asset: 'Price Data',
                viaFunction: 'getLoansValue',
                contractName: contract.name,
                type: 'collect',
                condition: 'Reads external prices'
            });
            transfers.push({
                from: contract.name,
                to: 'PortfolioVault',
                asset: 'NAV Calculation Result',
                viaFunction: 'applyPortfolioAdjustment',
                contractName: contract.name,
                type: 'transfer',
                condition: 'Returns adjusted values'
            });
        }
    }
    return transfers;
}
/**
 * Generate protocol-level value flow diagram showing all asset movements
 */
function generateProtocolValueFlows(contracts, registry) {
    const diagrams = [];
    // Detect all value transfers
    const transfers = detectValueTransfers(contracts, registry);
    if (transfers.length === 0) {
        diagrams.push({
            type: 'flowchart',
            title: 'Value Flow Diagram',
            code: 'graph LR\n  NoValueFlow["No significant value flows detected"]\n  style NoValueFlow fill:#e1f5fe',
            description: 'No asset movements detected in this protocol'
        });
        return diagrams;
    }
    // 1. Main Protocol Value Flow Diagram
    diagrams.push(generateMainValueFlowDiagram(transfers, contracts));
    // 2. Deposit/Withdrawal Cycle Diagram
    diagrams.push(generateDepositWithdrawalCycle(transfers));
    // 3. Secondary Market Flow (if exchange exists)
    const hasExchange = contracts.some(c => c.name.toLowerCase().includes('exchange'));
    if (hasExchange) {
        diagrams.push(generateSecondaryMarketFlow(transfers));
    }
    // 4. Per-contract value flow summaries
    const contractsWithValueMovement = new Set(transfers.map(t => t.contractName));
    for (const contractName of Array.from(contractsWithValueMovement).slice(0, 5)) {
        diagrams.push(generateContractValueFlow(contractName, transfers));
    }
    return diagrams;
}
/**
 * Generate main protocol value flow diagram
 */
function generateMainValueFlowDiagram(transfers, contracts) {
    const lines = ['graph LR'];
    lines.push('');
    lines.push('  %% ==================================================');
    lines.push('  %% PROTOCOL VALUE FLOW - ASSET MOVEMENTS');
    lines.push('  %% ==================================================');
    lines.push('');
    // Define external entities
    lines.push('  subgraph External [External Entities]');
    lines.push('    User(("[User]"))');
    lines.push('    Borrower(("[Borrower]"))');
    lines.push('    Investor(("[Investor]"))');
    lines.push('    Originator(("[Originator]"))');
    lines.push('    Servicer(("[Servicer]"))');
    lines.push('    Buyer(("[Buyer]"))');
    lines.push('    Seller(("[Seller]"))');
    lines.push('    Oracle(("[Oracle/PriceFeed]"))');
    lines.push('  end');
    lines.push('');
    // Group protocol contracts by role
    const coreContracts = ['PortfolioVault', 'Loans', 'LoansNFT', 'LoansExchange', 'LoansLedger'];
    const tokenContracts = ['VaultShareToken'];
    const accessContracts = ['TrustedSpender', 'TrustedCalls', 'GuardianAccessControl'];
    const calcContracts = ['NavCalculator'];
    lines.push('  subgraph Core [Core Protocol Contracts]');
    for (const name of coreContracts) {
        if (contracts.find(c => c.name === name)) {
            lines.push(`    ${name}["${name}"]`);
        }
    }
    lines.push('  end');
    lines.push('');
    lines.push('  subgraph Tokens [Token Contracts]');
    for (const name of tokenContracts) {
        if (contracts.find(c => c.name === name)) {
            lines.push(`    ${name}["${name}"]`);
        }
    }
    lines.push('  end');
    lines.push('');
    lines.push('  subgraph Access [Access Control]');
    for (const name of accessContracts) {
        if (contracts.find(c => c.name === name)) {
            lines.push(`    ${name}["${name}"]`);
        }
    }
    lines.push('  end');
    lines.push('');
    lines.push('  subgraph Calc [Pricing]');
    for (const name of calcContracts) {
        if (contracts.find(c => c.name === name)) {
            lines.push(`    ${name}["${name}"]`);
        }
    }
    lines.push('  end');
    lines.push('');
    // Draw value flows with labels
    lines.push('  %% VALUE FLOWS');
    lines.push('');
    // Deduplicate and draw unique flows
    const drawnFlows = new Set();
    for (const transfer of transfers) {
        const flowKey = `${transfer.from}->${transfer.to}:${transfer.asset}`;
        if (drawnFlows.has(flowKey))
            continue;
        drawnFlows.add(flowKey);
        // Style based on asset type
        let style = '';
        let label = transfer.asset;
        switch (transfer.type) {
            case 'deposit':
                style = 'stroke:#2e7d32,stroke-width:2px'; // Green
                label = `[DEPOSIT] ${label}`;
                break;
            case 'withdraw':
                style = 'stroke:#1565c0,stroke-width:2px'; // Blue
                label = `[WITHDRAW] ${label}`;
                break;
            case 'mint':
                style = 'stroke:#6a1b9a,stroke-width:2px'; // Purple
                label = `[MINT] ${label}`;
                break;
            case 'burn':
                style = 'stroke:#c62828,stroke-width:2px'; // Red
                label = `[BURN] ${label}`;
                break;
            case 'pay':
                style = '#ef6c00';
                label = `[PAYMENT] ${label}`;
                break;
            case 'fund':
                style = '#00838f';
                label = `[FUND] ${label}`;
                break;
            case 'collect':
                style = '#558b2f';
                label = `[COLLECT] ${label}`;
                break;
            case 'swap':
                style = '#ad1457';
                label = `[TRADE/SWAP] ${label}`;
                break;
            case 'transfer':
                style = '#4527a0';
                label = `[TRANSFER] ${label}`;
                break;
            case 'approve':
                style = '#f9a825';
                label = `[APPROVE] ${label}`;
                break;
            default:
                style = '#37474f';
        }
        // Sanitize all values for Mermaid compatibility
        const safeFrom = sanitizeMermaidString(transfer.from);
        const safeTo = sanitizeMermaidString(transfer.to);
        const safeLabel = sanitizeMermaidString(label);
        lines.push(`  "${safeFrom}" -->|"${safeLabel}"| "${safeTo}"`);
    }
    // Add styling
    lines.push('');
    lines.push('  %% STYLING');
    lines.push('  classDef userStyle fill:#e3f2fd,stroke:#1565c0');
    lines.push('  classDef contractStyle fill:#fff3e0,stroke:#e65100');
    lines.push('  classDef tokenStyle fill:#f3e5f5,stroke:#7b1fa2');
    lines.push('  classDef riskStyle fill:#ffebee,stroke:#c62828');
    lines.push('');
    lines.push('  class User,Borrower,Investor,Originator,Servicer,Buyer,Seller userStyle');
    for (const name of coreContracts) {
        if (contracts.find(c => c.name === name)) {
            lines.push(`  class ${name} contractStyle`);
        }
    }
    for (const name of tokenContracts) {
        if (contracts.find(c => c.name === name)) {
            lines.push(`  class ${name} tokenStyle`);
        }
    }
    // Sanitize the complete diagram code
    const finalCode = sanitizeMermaidCode(lines.join('\n'));
    return {
        type: 'flowchart',
        title: 'Protocol Value Flow Diagram',
        code: finalCode,
        description: 'Complete map of all asset movements through the protocol including deposits, withdrawals, lending, trading, and fee collection'
    };
}
/**
 * Generate deposit/withdrawal cycle diagram
 */
function generateDepositWithdrawalCycle(transfers) {
    const lines = ['sequenceDiagram'];
    lines.push('');
    lines.push('  Note over User,PortfolioVault: [DEPOSIT CYCLE]');
    lines.push('');
    // Deposit flow
    const deposits = transfers.filter(t => t.type === 'deposit' && t.to.includes('Vault'));
    if (deposits.length > 0) {
        lines.push('  User->>PortfolioVault: 1. Deposit Assets (ERC20/ETH)');
        lines.push('  PortfolioVault->>VaultShareToken: 2. Mint Shares');
        lines.push('  VaultShareToken-->>User: 3. Receive Vault Shares');
        lines.push('');
    }
    // Lending flow
    const funds = transfers.filter(t => t.type === 'fund');
    if (funds.length > 0) {
        lines.push('  Note over User,Loans: [LENDING FLOW]');
        lines.push('');
        lines.push('  PortfolioVault->>Loans: 4. Fund Loans (Capital Deployment)');
        lines.push('  Loans->>LoansNFT: 5. Mint Loan NFTs');
        lines.push('  LoansNFT-->>Lenders: 6. Receive Loan NFTs (Proof of Position)');
        lines.push('');
    }
    // Repayment flow
    const payments = transfers.filter(t => t.type === 'pay');
    if (payments.length > 0) {
        lines.push('  Note over Borrower,Loans: [REPAYMENT FLOW]');
        lines.push('');
        lines.push('  Borrower->>Loans: 7. Repay Principal + Interest');
        lines.push('  Loans-->>PortfolioVault: 8. Collect Cashflows');
        lines.push('');
    }
    // Withdrawal flow
    const withdrawals = transfers.filter(t => t.type === 'withdraw' && t.from.includes('Vault'));
    if (withdrawals.length > 0) {
        lines.push('  Note over User,PortfolioVault: [WITHDRAWAL CYCLE]');
        lines.push('');
        lines.push('  User->>PortfolioVault: 9. Redeem/Burn Shares');
        lines.push('  PortfolioVault->>User: 10. Return Assets (+ Yield)');
    }
    return {
        type: 'sequenceDiagram',
        title: 'Deposit/Lending/Withdrawal Lifecycle',
        code: sanitizeMermaidCode(lines.join('\n')),
        description: 'Complete lifecycle showing how assets enter, are deployed, earn returns, and exit the protocol'
    };
}
/**
 * Generate secondary market (exchange) flow diagram
 */
function generateSecondaryMarketFlow(transfers) {
    const lines = ['sequenceDiagram'];
    const exchangeTransfers = transfers.filter(t => t.contractName.toLowerCase().includes('exchange') ||
        t.asset.includes('NFT') ||
        t.type === 'swap');
    if (exchangeTransfers.length === 0) {
        return {
            type: 'sequenceDiagram',
            title: 'Secondary Market Flow',
            code: 'Note right of User: No secondary market detected',
            description: 'No exchange/trading functionality found'
        };
    }
    lines.push('');
    lines.push('  Note over Seller,Buyer: [SECONDARY MARKET (Loan Trading)]');
    lines.push('');
    lines.push('  Seller->>LoansExchange: 1. Create Sale Offer (Lock NFT)');
    lines.push('  LoansExchange->>LoansNFT: 2. Lock/Escrow NFT');
    lines.push('  Note right of LoansExchange: Offer ID created');
    lines.push('');
    lines.push('  Buyer->>LoansExchange: 3. Accept Offer + Pay Price');
    lines.push('  LoansExchange->>Seller: 4. Transfer Proceeds (minus fees)');
    lines.push('  LoansExchange->>Buyer: 5. Transfer Loan NFT');
    lines.push('  Note right of Buyer: Now owns loan position + rights');
    lines.push('');
    lines.push('  Note over Seller,Buyer: [Trade Complete]');
    return {
        type: 'sequenceDiagram',
        title: 'Secondary Market (Loan Trading) Flow',
        code: sanitizeMermaidCode(lines.join('\n')),
        description: 'How loan positions are traded on the secondary market via the exchange'
    };
}
/**
 * Generate per-contract value flow summary
 */
function generateContractValueFlow(contractName, transfers) {
    const lines = ['graph TD'];
    const contractTransfers = transfers.filter(t => t.contractName === contractName);
    lines.push(`  subgraph ${contractName} [Value Flows: ${contractName}]`);
    lines.push('');
    // Group by direction
    const incoming = contractTransfers.filter(t => t.to === contractName || t.to.includes(contractName));
    const outgoing = contractTransfers.filter(t => t.from === contractName || t.from.includes(contractName));
    if (incoming.length > 0) {
        lines.push('    subgraph Inflows [Asset Inflows]');
        for (const t of incoming.slice(0, 5)) {
            lines.push(`      IN_${t.viaFunction}["${t.asset}\\nvia ${t.viaFunction}()\\nfrom ${t.from}"]`);
        }
        lines.push('    end');
        lines.push('');
    }
    if (outgoing.length > 0) {
        lines.push('    subgraph Outflows [Asset Outflows]');
        for (const t of outgoing.slice(0, 5)) {
            lines.push(`      OUT_${t.viaFunction}["${t.asset}\\nvia ${t.viaFunction}()\\nto ${t.to}"]`);
        }
        lines.push('    end');
        lines.push('');
    }
    if (incoming.length === 0 && outgoing.length === 0) {
        lines.push('    NoFlows["No direct value movements"]');
    }
    lines.push('  end');
    // Styling
    lines.push('');
    lines.push('  classDef inflow fill:#c8e6c9,stroke:#2e7d32');
    lines.push('  classDef outflow fill:#ffcdd2,stroke:#c62828');
    lines.push('  class IN_* inflow');
    lines.push('  class OUT_* outflow');
    return {
        type: 'flowchart',
        title: `Value Flows: ${contractName}`,
        code: sanitizeMermaidCode(lines.join('\n')),
        description: `Summary of all asset movements into and out of ${contractName}`
    };
}
/**
 * Export function for getting raw value transfer data
 * Useful for other modules that need access to detected flows
 */
function getValueTransfers(contracts, registry) {
    const reg = registry || (0, function_registry_1.buildFunctionRegistry)(contracts);
    return detectValueTransfers(contracts, reg);
}
// ============================================================
// END OF VALUE FLOW DIAGRAM GENERATION
// ============================================================
// ============================================================
// HELPER FUNCTIONS
// ============================================================
function getVisibilityIcon(visibility) {
    switch (visibility) {
        case 'public': return '+';
        case 'external': return '*';
        case 'private': return '-';
        case 'internal': return '#';
        case 'constant': return '$';
        case 'immutable': return '!';
        default: return '?';
    }
}
function getMutabilityBadge(mutability) {
    switch (mutability) {
        case 'view': return '[VIEW]';
        case 'pure': return '[PURE]';
        case 'payable': return '[PAYABLE]';
        default: return '';
    }
}
function getRiskColor(risk) {
    switch (risk) {
        case 'critical': return '#ff0000';
        case 'high': return '#ff6b6b';
        case 'medium': return '#ffa726';
        case 'low': return '#ffee58';
        case 'safe': return '#66bb6a';
        default: return '#9e9e9e';
    }
}
//# sourceMappingURL=diagram-generator.js.map