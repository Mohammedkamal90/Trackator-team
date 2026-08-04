"use strict";
// ============================================================
// TRACKATOR Tier 2 - Breakdown Ingestor
// Parses and ingests Protocol Breakdown behavioral analysis
// ============================================================
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ingestBreakdown = ingestBreakdown;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const yaml = __importStar(require("js-yaml"));
/**
 * Main entry point for Breakdown ingestion
 */
function ingestBreakdown(options) {
    const { breakdownFile, contracts = [], verbose = false } = options;
    // Try to load from file if provided
    let rawData = null;
    if (breakdownFile && fs.existsSync(breakdownFile)) {
        if (verbose)
            console.log(`Loading Breakdown data from ${breakdownFile}`);
        rawData = loadBreakdownFile(breakdownFile);
    }
    // If no file, generate from contracts using built-in analysis
    if (!rawData && contracts.length > 0) {
        if (verbose)
            console.log('Generating Breakdown analysis from contracts');
        rawData = generateBreakdownFromContracts(contracts);
    }
    // If still no data, return empty output
    if (!rawData) {
        return createEmptyBreakdownOutput();
    }
    // Parse and structure the raw data
    return parseBreakdownData(rawData, contracts);
}
/**
 * Load Breakdown data from file (JSON or YAML)
 */
function loadBreakdownFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const ext = path.extname(filePath).toLowerCase();
    try {
        if (ext === '.yaml' || ext === '.yml') {
            return yaml.load(content);
        }
        else {
            return JSON.parse(content);
        }
    }
    catch (error) {
        throw new Error(`Failed to parse Breakdown file: ${error.message}`);
    }
}
/**
 * Generate Breakdown analysis from contracts using built-in heuristics
 */
function generateBreakdownFromContracts(contracts) {
    // Analyze components
    const components = analyzeComponents(contracts);
    // Extract money flows
    const moneyFlows = extractMoneyFlows(contracts);
    // Analyze numeric behaviors
    const numericBehaviors = analyzeNumericBehaviors(contracts);
    // Map state authority
    const stateAuthority = mapStateAuthority(contracts);
    // Generate expected behaviors
    const expectedBehaviors = generateExpectedBehaviors(contracts);
    return {
        components,
        moneyFlows,
        numericBehaviors,
        stateAuthority,
        expectedBehaviors,
        generatedAt: new Date().toISOString()
    };
}
/**
 * Parse raw Breakdown data into structured format
 */
function parseBreakdownData(rawData, contracts = []) {
    return {
        components: parseComponents(rawData.components || [], contracts),
        moneyFlows: parseMoneyFlows(rawData.moneyFlows || rawData.flows || []),
        numericBehaviors: parseNumericBehaviors(rawData.numericBehaviors || rawData.numeric || []),
        stateAuthority: parseStateAuthority(rawData.stateAuthority || rawData.authority || []),
        expectedBehaviors: parseExpectedBehaviors(rawData.expectedBehaviors || rawData.behaviors || []),
        generatedAt: rawData.generatedAt || new Date().toISOString()
    };
}
// ============================================================
// COMPONENT ANALYSIS
// ============================================================
function analyzeComponents(contracts) {
    const components = [];
    for (const contract of contracts) {
        const component = analyzeSingleComponent(contract, contracts);
        components.push(component);
    }
    return components;
}
function analyzeSingleComponent(contract, allContracts) {
    // Determine component type based on patterns
    const type = determineComponentType(contract, allContracts);
    // Determine responsibility
    const responsibility = determineResponsibility(contract);
    // Find dependencies (contracts this one imports/uses)
    const dependencies = findDependencies(contract, allContracts);
    // Identify owned state variables (not inherited)
    const stateOwned = contract.stateVariables.map(sv => sv.name);
    // Identify interfaces (external-facing functions)
    const interfaces = extractInterfaces(contract);
    // Assess risk level
    const riskLevel = assessComponentRisk(contract);
    return {
        name: contract.name,
        type,
        responsibility,
        dependencies,
        stateOwned,
        interfaces,
        riskLevel
    };
}
function determineComponentType(contract, _allContracts) {
    const nameLower = contract.name.toLowerCase();
    const funcNames = contract.functions.map(f => f.name.toLowerCase());
    // Interface detection
    if (contract.abstract && contract.functions.every(f => f.body.statements === undefined)) {
        return 'integration';
    }
    // Library detection
    if (funcNames.some(f => f.startsWith('_')) &&
        contract.functions.every(f => f.visibility === 'internal' || f.visibility === 'private')) {
        return 'utility';
    }
    // Core contract detection
    if (['pool', 'vault', 'lending', 'protocol', 'core'].some(p => nameLower.includes(p))) {
        return 'core';
    }
    // Peripheral/peripheral contract detection
    if (['proxy', 'admin', 'governance', 'token', 'reward'].some(p => nameLower.includes(p))) {
        return 'peripheral';
    }
    // Default to core if has many functions
    return contract.functions.length > 5 ? 'core' : 'peripheral';
}
function determineResponsibility(contract) {
    const responsibilities = [];
    const funcNames = contract.functions.map(f => f.name.toLowerCase());
    const varNames = contract.stateVariables.map(v => v.name.toLowerCase());
    // Token-related
    if (varNames.some(v => v.includes('balance') || v.includes('total') || v.includes('supply'))) {
        responsibilities.push('Token accounting');
    }
    // Access control
    if (funcNames.some(f => f.includes('grant') || f.includes('revoke') || f.includes('role'))) {
        responsibilities.push('Access control management');
    }
    // Asset management
    if (funcNames.some(f => ['deposit', 'withdraw', 'transfer', 'mint', 'burn'].some(p => f.includes(p)))) {
        responsibilities.push('Asset custody and transfers');
    }
    // Oracle/price feeds
    if (funcNames.some(f => f.includes('price') || f.includes('oracle') || f.includes('feed'))) {
        responsibilities.push('Price discovery and oracle integration');
    }
    // Governance
    if (funcNames.some(f => f.includes('vote') || f.includes('propose') || f.includes('execute'))) {
        responsibilities.push('Governance operations');
    }
    // Interest/rate calculations
    if (funcNames.some(f => f.includes('rate') || f.includes('interest') || f.includes('accrue'))) {
        responsibilities.push('Interest rate calculation and accrual');
    }
    // Liquidation
    if (funcNames.some(f => f.includes('liquidate'))) {
        responsibilities.push('Liquidation processing');
    }
    // Swap/trading
    if (funcNames.some(f => f.includes('swap') || f.includes('trade') || f.includes('exchange'))) {
        responsibilities.push('Swap/trading execution');
    }
    return responsibilities.length > 0 ? responsibilities.join(', ') : 'General contract functionality';
}
function findDependencies(contract, _allContracts) {
    const dependencies = [];
    // From imports
    dependencies.push(...contract.imports.map(imp => path.basename(imp, '.sol')));
    // From inheritance
    dependencies.push(...contract.inherited);
    // From state variable types that reference other contracts
    for (const sv of contract.stateVariables) {
        if (sv.type.match(/^[A-Z][a-zA-Z0-9]*$/) && !isPrimitiveType(sv.type)) {
            dependencies.push(sv.type);
        }
    }
    // From function parameter types
    for (const func of contract.functions) {
        for (const param of [...func.parameters, ...func.returnParameters]) {
            if (param.type.match(/^[A-Z][a-zA-Z0-9]*$/) && !isPrimitiveType(param.type)) {
                if (!dependencies.includes(param.type)) {
                    dependencies.push(param.type);
                }
            }
        }
    }
    return [...new Set(dependencies)];
}
function isPrimitiveType(type) {
    const primitives = [
        'uint', 'uint8', 'uint16', 'uint24', 'uint32', 'uint40', 'uint48',
        'uint56', 'uint64', 'uint72', 'uint80', 'uint88', 'uint96', 'uint104',
        'uint112', 'uint120', 'uint128', 'uint136', 'uint144', 'uint152',
        'uint160', 'uint168', 'uint176', 'uint184', 'uint192', 'uint200',
        'uint208', 'uint216', 'uint224', 'uint232', 'uint240', 'uint248',
        'uint256', 'int', 'int8', 'int16', 'int24', 'int32', 'int40', 'int48',
        'int56', 'int64', 'int72', 'int80', 'int88', 'int96', 'int104',
        'int112', 'int120', 'int128', 'int136', 'int144', 'int152', 'int160',
        'int168', 'int176', 'int184', 'int192', 'int200', 'int208', 'int216',
        'int224', 'int232', 'int240', 'int248', 'int256',
        'bool', 'address', 'string', 'bytes', 'bytes1', 'bytes2', 'bytes3',
        'bytes4', 'bytes5', 'bytes6', 'bytes7', 'bytes8', 'bytes9', 'bytes10',
        'bytes11', 'bytes12', 'bytes13', 'bytes14', 'bytes15', 'bytes16',
        'bytes17', 'bytes18', 'bytes19', 'bytes20', 'bytes21', 'bytes22',
        'bytes23', 'bytes24', 'bytes25', 'bytes26', 'bytes27', 'bytes28',
        'bytes29', 'bytes30', 'bytes31', 'bytes32'
    ];
    return primitives.includes(type.toLowerCase()) ||
        type.startsWith('mapping(') ||
        type.startsWith('uint') ||
        type.startsWith('int') ||
        type.startsWith('bytes');
}
function extractInterfaces(contract) {
    const interfaces = [];
    for (const func of contract.functions) {
        if (func.visibility === 'external' || func.visibility === 'public') {
            // Determine side effects
            const sideEffects = [];
            if (func.stateVariablesWritten.length > 0) {
                sideEffects.push(`Writes: ${func.stateVariablesWritten.join(', ')}`);
            }
            if (func.body.hasExternalCall) {
                sideEffects.push('Makes external calls');
            }
            if (func.body.hasTransfer) {
                sideEffects.push('Transfers ETH/tokens');
            }
            if (func.eventsEmitted?.length > 0 || func.name.toLowerCase().includes('emit')) {
                sideEffects.push('Emits events');
            }
            interfaces.push({
                name: func.name,
                inputs: func.parameters,
                outputs: func.returnParameters,
                accessControl: func.modifiers.join(', ') || 'None',
                sideEffects
            });
        }
    }
    return interfaces;
}
function assessComponentRisk(contract) {
    let riskScore = 0;
    // Check for high-risk patterns
    for (const func of contract.functions) {
        if (func.body.ceiPattern === 'violated')
            riskScore += 30;
        if (func.body.hasDelegateCall)
            riskScore += 25;
        if (func.body.hasExternalCall && func.stateVariablesWritten.length > 0)
            riskScore += 15;
        if (func.body.hasLoop)
            riskScore += 10;
        if (func.visibility === 'public' && func.modifiers.length === 0 &&
            func.stateMutability !== 'view' && func.stateMutability !== 'pure') {
            riskScore += 20;
        }
    }
    // Check for ETH handling
    if (contract.functions.some(f => f.stateMutability === 'payable')) {
        riskScore += 10;
    }
    if (riskScore >= 50)
        return 'critical';
    if (riskScore >= 35)
        return 'high';
    if (riskScore >= 20)
        return 'medium';
    return 'low';
}
// ============================================================
// MONEY FLOW ANALYSIS
// ============================================================
function extractMoneyFlows(contracts) {
    const flows = [];
    let flowCounter = 1;
    for (const contract of contracts) {
        for (const func of contract.functions) {
            const functionFlows = extractFunctionMoneyFlows(contract, func, flowCounter);
            flows.push(...functionFlows);
            flowCounter += functionFlows.length;
        }
    }
    return flows;
}
function extractFunctionMoneyFlows(contract, func, startId) {
    const flows = [];
    const name = func.name.toLowerCase();
    // Detect common DeFi money flow patterns
    // Deposit pattern
    if (['deposit', 'mint', 'stake', 'supply', 'addliquidity', 'provide'].some(p => name.includes(p))) {
        flows.push({
            id: `MF_${startId}`,
            name: `Deposit via ${func.name}()`,
            trigger: `User calls ${contract.name}.${func.name}()`,
            steps: [
                { order: 1, action: 'Transfer tokens/ETH', from: 'User', to: contract.name, asset: 'Input token', amount: '_amount' },
                { order: 2, action: 'Update user balance/shares', from: contract.name, to: 'User', asset: 'LP/staked tokens', amount: '_shares' },
                { order: 3, action: 'Emit Deposit event', from: contract.name, to: 'Event Log', asset: 'Event', amount: '-' }
            ],
            conditions: ['Contract not paused', 'Amount > 0', 'Allowance sufficient (for ERC20)'],
            edgeCases: ['Zero amount deposit', 'Max uint256 amount', 'Reentrant call']
        });
    }
    // Withdrawal pattern
    if (['withdraw', 'redeem', 'unstake', 'removeliquidity', 'remove'].some(p => name.includes(p))) {
        flows.push({
            id: `MF_${startId + (flows.length > 0 ? 1 : 0)}`,
            name: `Withdrawal via ${func.name}()`,
            trigger: `User calls ${contract.name}.${func.name}()`,
            steps: [
                { order: 1, action: 'Burn/transfer shares', from: 'User', to: contract.name, asset: 'LP/staked tokens', amount: '_shares' },
                { order: 2, action: 'Transfer assets', from: contract.name, to: 'User', asset: 'Underlying token', amount: '_amount' },
                { order: 3, action: 'Emit Withdraw event', from: contract.name, to: 'Event Log', asset: 'Event', amount: '-' }
            ],
            conditions: ['User has sufficient balance/shares', 'Contract has enough liquidity'],
            edgeCases: ['Withdraw full balance', 'Withdraw zero', 'Insufficient liquidity']
        });
    }
    // Swap pattern
    if (['swap', 'trade', 'exchange', 'exactinput', 'exactoutput'].some(p => name.includes(p))) {
        flows.push({
            id: `MF_${startId + (flows.length > 0 ? 1 : 0)}`,
            name: `Swap via ${func.name}()`,
            trigger: `User calls ${contract.name}.${func.name}()`,
            steps: [
                { order: 1, action: 'Transfer input token', from: 'User', to: contract.name, asset: 'Token In', amount: 'amountIn' },
                { order: 2, action: 'Calculate output (AMM formula)', from: contract.name, to: contract.name, asset: 'Calculation', amount: 'amountOut' },
                { order: 3, action: 'Transfer output token', from: contract.name, to: 'User', asset: 'Token Out', amount: 'amountOut' },
                { order: 4, action: 'Emit Swap event', from: contract.name, to: 'Event Log', asset: 'Event', amount: '-' }
            ],
            conditions: ['Sufficient liquidity', 'Within slippage tolerance', 'Not expired (if deadline)'],
            edgeCases: ['Large trade impact', 'Zero output amount', 'Deadlines hit']
        });
    }
    // Liquidation pattern
    if (name.includes('liquidate')) {
        flows.push({
            id: `MF_${startId + (flows.length > 0 ? 1 : 0)}`,
            name: `Liquidation via ${func.name}()`,
            trigger: `Liquidator calls ${contract.name}.${func.name}()`,
            steps: [
                { order: 1, action: 'Verify unhealthy position', from: 'Liquidator', to: contract.name, asset: 'Check', amount: '-' },
                { order: 2, action: 'Seize collateral', from: 'Borrower/Vault', to: 'Liquidator', asset: 'Collateral', amount: '_collateral' },
                { order: 3, action: 'Repay borrow', from: 'Liquidator', to: 'Protocol', asset: 'Underlying', amount: '_repay' },
                { order: 4, action: 'Pay liquidation reward', from: 'Protocol', to: 'Liquidator', asset: 'Reward', amount: '_reward' },
                { order: 5, action: 'Emit Liquidation event', from: contract.name, to: 'Event Log', asset: 'Event', amount: '-' }
            ],
            conditions: ['Position is below threshold', 'Close factor respected', 'Not paused'],
            edgeCases: ['Self-liquidation', 'Partial liquidation', 'Oracle manipulation during']
        });
    }
    // Borrow pattern
    if (name.includes('borrow')) {
        flows.push({
            id: `MF_${startId + (flows.length > 0 ? 1 : 0)}`,
            name: `Borrow via ${func.name}()`,
            trigger: `User calls ${contract.name}.${func.name}()`,
            steps: [
                { order: 1, action: 'Check collateral sufficiency', from: contract.name, to: contract.name, asset: 'Check', amount: '-' },
                { order: 2, action: 'Transfer borrowed assets', from: contract.name, to: 'User', asset: 'Borrowed token', amount: '_amount' },
                { order: 3, action: 'Update borrow balance', from: 'User', to: contract.name, asset: 'Debt', amount: '_amount' },
                { order: 4, action: 'Emit Borrow event', from: contract.name, to: 'Event Log', asset: 'Event', amount: '-' }
            ],
            conditions: ['Sufficient collateral', 'Account healthy after borrow', 'Not paused'],
            edgeCases: ['Borrow max', 'Borrow zero', 'Edge of liquidation']
        });
    }
    return flows;
}
// ============================================================
// NUMERIC BEHAVIOR ANALYSIS
// ============================================================
function analyzeNumericBehaviors(contracts) {
    const behaviors = [];
    for (const contract of contracts) {
        for (const sv of contract.stateVariables) {
            // Focus on numeric state variables
            if (sv.type.toLowerCase().includes('uint') ||
                sv.type.toLowerCase().includes('int') ||
                sv.name.toLowerCase().includes('balance') ||
                sv.name.toLowerCase().includes('total') ||
                sv.name.toLowerCase().includes('price') ||
                sv.name.toLowerCase().includes('rate')) {
                const behavior = inferNumericBehavior(contract.name, sv);
                behaviors.push(behavior);
            }
        }
    }
    return behaviors;
}
function inferNumericBehavior(contractName, sv) {
    const nameLower = sv.name.toLowerCase();
    const typeLower = sv.type.toLowerCase();
    // Infer expected range and behavior based on naming conventions
    if (nameLower.includes('total') && nameLower.includes('supply')) {
        return {
            variable: sv.name,
            contract: contractName,
            expectedRange: { min: 0, max: typeLower.includes('256') ? 1.1579e77 : 65535 },
            unit: 'tokens',
            normalPattern: 'Monotonically increasing with mints, decreasing with burns',
            anomalyThreshold: 10, // % change considered anomalous
            examples: [
                { scenario: 'Mint 100 tokens', input: '+100', expectedOutput: 'totalSupply += 100', explanation: 'Standard mint increases supply' },
                { scenario: 'Burn 50 tokens', input: '-50', expectedOutput: 'totalSupply -= 50', explanation: 'Standard burn decreases supply' }
            ]
        };
    }
    if (nameLower.includes('balance')) {
        return {
            variable: sv.name,
            contract: contractName,
            expectedRange: { min: 0, max: typeLower.includes('256') ? 1.1579e77 : 65535 },
            unit: 'tokens',
            normalPattern: 'Changes on deposits, withdrawals, transfers',
            anomalyThreshold: 50, // Higher threshold as balances can change a lot
            examples: [
                { scenario: 'User deposits 1000', input: '+1000', expectedOutput: 'balance[user] += 1000', explanation: 'Deposit adds to balance' },
                { scenario: 'User withdraws all', input: '-balance', expectedOutput: 'balance[user] = 0', explanation: 'Full withdrawal zeros balance' }
            ]
        };
    }
    if (nameLower.includes('interest') || nameLower.includes('rate')) {
        return {
            variable: sv.name,
            contract: contractName,
            expectedRange: { min: 0, max: 1 }, // Usually represented as ray/wad (1e27/1e18)
            unit: 'rate per period',
            normalPattern: 'Adjusts slowly based on utilization or governance',
            anomalyThreshold: 5, // Small changes are significant for rates
            examples: [
                { scenario: 'Utilization increases', input: 'utilization up 10%', expectedOutput: 'rate += small delta', explanation: 'Rate adjusts upward' },
                { scenario: 'Governance sets rate', input: 'newRate param', expectedOutput: 'rate = newRate', explanation: 'Direct governance control' }
            ]
        };
    }
    if (nameLower.includes('price') || nameLower.includes('oracle')) {
        return {
            variable: sv.name,
            contract: contractName,
            expectedRange: { min: 0, max: 1e12 }, // Wide range for different assets
            unit: 'price (USD/base)',
            normalPattern: 'Updates on oracle calls, should follow market',
            anomalyThreshold: 5, // Price deviations >5% are suspicious
            examples: [
                { scenario: 'Normal oracle update', input: 'new price feed', expectedOutput: 'price ~= previous * (1 +/- 0.01)', explanation: 'Small price movements' },
                { scenario: 'Flash loan attack', input: 'manipulated price', expectedOutput: 'price deviates >> 5%', explanation: 'Potential manipulation' }
            ]
        };
    }
    // Default behavior
    return {
        variable: sv.name,
        contract: contractName,
        expectedRange: { min: 0, max: typeLower.includes('256') ? 1.1579e77 : 65535 },
        unit: 'unknown',
        normalPattern: 'Unknown - requires manual analysis',
        anomalyThreshold: 20,
        examples: []
    };
}
// ============================================================
// STATE AUTHORITY MAPPING
// ============================================================
function mapStateAuthority(contracts) {
    const authorities = [];
    for (const contract of contracts) {
        for (const sv of contract.stateVariables) {
            // Find who can write to this variable
            const writers = findVariableWriters(sv.name, contract);
            // Determine how it changes
            const changePatterns = inferChangePatterns(sv.name, contract);
            // Find constraints
            const constraints = findConstraints(sv.name, contract);
            // Check validation presence
            const validationPresent = checkValidationPresence(sv.name, contract);
            authorities.push({
                variable: sv.name,
                contract: contract.name,
                whoCanWrite: writers,
                howItChanges: changePatterns,
                constraints,
                validationPresent
            });
        }
    }
    return authorities;
}
function findVariableWriters(variableName, contract) {
    const writers = [];
    for (const func of contract.functions) {
        // Check if function writes to this variable
        if (func.stateVariablesWritten.includes(variableName)) {
            // Determine who can call this function
            if (func.modifiers.some(m => m.toLowerCase().includes('onlyowner'))) {
                writers.push(`${func.name}() [Owner only]`);
            }
            else if (func.modifiers.some(m => m.toLowerCase().includes('role'))) {
                writers.push(`${func.name}() [Role-restricted]`);
            }
            else if (func.visibility === 'internal' || func.visibility === 'private') {
                // Internal functions - find external callers
                const callers = findInternalCallers(func.name, contract);
                writers.push(`${func.name}() [Internal, called by: ${callers.join(', ')}]`);
            }
            else {
                writers.push(`${func.name}() [Public]`);
            }
        }
    }
    return writers;
}
function findInternalCallers(funcName, contract) {
    const callers = [];
    for (const func of contract.functions) {
        if (func.calls.includes(funcName) &&
            (func.visibility === 'external' || func.visibility === 'public')) {
            callers.push(func.name);
        }
    }
    return callers;
}
function inferChangePatterns(variableName, contract) {
    const patterns = [];
    const nameLower = variableName.toLowerCase();
    for (const func of contract.functions) {
        if (func.stateVariablesWritten.includes(variableName)) {
            const funcName = func.name.toLowerCase();
            if (funcName.includes('mint') || funcName.includes('deposit') || funcName.includes('add')) {
                patterns.push('Increases on mint/deposit/add');
            }
            else if (funcName.includes('burn') || funcName.includes('withdraw') || funcName.includes('remove')) {
                patterns.push('Decreases on burn/withdraw/remove');
            }
            else if (funcName.includes('set') || funcName.includes('update')) {
                patterns.push('Set directly by set/update function');
            }
            else if (funcName.includes('transfer')) {
                patterns.push('Modified during transfers (sender decrease, receiver increase)');
            }
            else if (funcName.includes('accrue') || funcName.includes('compound')) {
                patterns.push('Increases over time (interest/rewards)');
            }
        }
    }
    return patterns.length > 0 ? patterns.join('; ') : 'Unknown modification pattern';
}
function findConstraints(variableName, contract) {
    const constraints = [];
    // Look for require statements in functions that write to this variable
    for (const func of contract.functions) {
        if (func.stateVariablesWritten.includes(variableName)) {
            if (func.body.hasRequire) {
                constraints.push(`${func.name}() has require checks`);
            }
            // Check modifiers that might add constraints
            for (const mod of func.modifiers) {
                if (mod.toLowerCase().includes('onlyowner')) {
                    constraints.push('Owner-only restriction');
                }
                if (mod.toLowerCase().includes('whennotpaused')) {
                    constraints.push('Requires unpaused state');
                }
            }
        }
    }
    return constraints;
}
function checkValidationPresence(_variableName, _contract) {
    // Simplified - would need deeper AST analysis
    return true; // Assume validation present unless proven otherwise
}
// ============================================================
// EXPECTED BEHAVIOR GENERATION
// ============================================================
function generateExpectedBehaviors(contracts) {
    const behaviors = [];
    for (const contract of contracts) {
        for (const func of contract.functions) {
            if (func.visibility === 'external' || func.visibility === 'public') {
                const behavior = generateFunctionExpectedBehavior(func, contract);
                behaviors.push(behavior);
            }
        }
    }
    return behaviors;
}
function generateFunctionExpectedBehavior(func, _contract) {
    const name = func.name.toLowerCase();
    // Pre-conditions
    const preConditions = [];
    if (func.modifiers.some(m => m.toLowerCase().includes('onlyowner'))) {
        preConditions.push('msg.sender == owner');
    }
    if (func.modifiers.some(m => m.toLowerCase().includes('whennotpaused'))) {
        preConditions.push('!paused()');
    }
    if (func.parameters.some(p => p.type === 'address')) {
        preConditions.push('Valid address inputs (non-zero if required)');
    }
    if (func.parameters.some(p => p.type.toLowerCase().includes('uint'))) {
        preConditions.push('Positive amounts where applicable');
    }
    // Post-conditions
    const postConditions = [];
    if (func.stateVariablesWritten.length > 0) {
        postConditions.push(`State updated: ${func.stateVariablesWritten.join(', ')}`);
    }
    if (func.eventsEmitted?.length > 0 || name.includes('emit')) {
        postConditions.push('Appropriate events emitted');
    }
    if (func.returnParameters.length > 0) {
        postConditions.push('Return values match expected results');
    }
    // State changes
    const stateChanges = [];
    if (['deposit', 'mint', 'stake', 'supply'].some(p => name.includes(p))) {
        stateChanges.push({ variable: 'userBalance', direction: 'increase' });
        stateChanges.push({ variable: 'totalSupply', direction: 'increase' });
    }
    else if (['withdraw', 'redeem', 'unstake', 'burn'].some(p => name.includes(p))) {
        stateChanges.push({ variable: 'userBalance', direction: 'decrease' });
        stateChanges.push({ variable: 'totalSupply', direction: 'decrease' });
    }
    else if (name.includes('transfer')) {
        stateChanges.push({ variable: 'senderBalance', direction: 'decrease' });
        stateChanges.push({ variable: 'receiverBalance', direction: 'increase' });
    }
    // Revert conditions
    const revertConditions = [];
    if (func.body.hasRequire) {
        revertConditions.push('When require conditions fail');
    }
    if (func.body.hasRevert) {
        revertConditions.push('Custom revert conditions triggered');
    }
    if (name.includes('swap')) {
        revertConditions.push('Insufficient output amount (slippage)');
        revertConditions.push('Expired deadline');
    }
    if (name.includes('borrow')) {
        revertConditions.push('Insufficient collateral');
        revertConditions.push('Protocol paused');
    }
    return {
        functionSig: `${func.name}(${func.parameters.map(p => p.type).join(',')})`,
        preConditions,
        postConditions,
        stateChanges,
        revertConditions
    };
}
// ============================================================
// PARSING HELPERS
// ============================================================
function parseComponents(raw, contracts) {
    if (raw.length === 0 && contracts.length > 0) {
        return analyzeComponents(contracts);
    }
    return raw.map((c) => ({
        name: c.name || 'Unknown',
        type: c.type || 'peripheral',
        responsibility: c.responsibility || '',
        dependencies: c.dependencies || [],
        stateOwned: c.stateOwned || [],
        interfaces: (c.interfaces || []).map((i) => ({
            name: i.name || '',
            inputs: i.inputs || [],
            outputs: i.outputs || [],
            accessControl: i.accessControl || '',
            sideEffects: i.sideEffects || []
        })),
        riskLevel: c.riskLevel || 'medium'
    }));
}
function parseMoneyFlows(raw) {
    return raw.map((mf, index) => ({
        id: mf.id || `MF_${index + 1}`,
        name: mf.name || 'Unnamed Flow',
        trigger: mf.trigger || '',
        steps: (mf.steps || []).map((s) => ({
            order: s.order || 0,
            action: s.action || '',
            from: s.from || '',
            to: s.to || '',
            asset: s.asset || '',
            amount: s.amount || '',
            condition: s.condition
        })),
        conditions: mf.conditions || [],
        valueRange: mf.valueRange,
        edgeCases: mf.edgeCases || []
    }));
}
function parseNumericBehaviors(raw) {
    return raw.map((nb) => ({
        variable: nb.variable || '',
        contract: nb.contract || '',
        expectedRange: nb.expectedRange || { min: 0, max: 0 },
        unit: nb.unit || '',
        normalPattern: nb.normalPattern || '',
        anomalyThreshold: nb.anomalyThreshold || 20,
        examples: (nb.examples || []).map((ex) => ({
            scenario: ex.scenario || '',
            input: ex.input || '',
            expectedOutput: ex.expectedOutput || '',
            explanation: ex.explanation || ''
        }))
    }));
}
function parseStateAuthority(raw) {
    return raw.map((sa) => ({
        variable: sa.variable || '',
        contract: sa.contract || '',
        whoCanWrite: sa.whoCanWrite || [],
        howItChanges: sa.howItChanges || '',
        constraints: sa.constraints || [],
        validationPresent: sa.validationPresent ?? true
    }));
}
function parseExpectedBehaviors(raw) {
    return raw.map((eb) => ({
        functionSig: eb.functionSig || eb.signature || '',
        preConditions: eb.preConditions || [],
        postConditions: eb.postConditions || [],
        stateChanges: (eb.stateChanges || []).map((sc) => ({
            variable: sc.variable || '',
            direction: sc.direction || 'unchanged',
            bounds: sc.bounds
        })),
        revertConditions: eb.revertConditions || [],
        gasEstimate: eb.gasEstimate
    }));
}
function createEmptyBreakdownOutput() {
    return {
        components: [],
        moneyFlows: [],
        numericBehaviors: [],
        stateAuthority: [],
        expectedBehaviors: [],
        generatedAt: new Date().toISOString()
    };
}
//# sourceMappingURL=breakdown-ingestor.js.map