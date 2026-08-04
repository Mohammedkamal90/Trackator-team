"use strict";
/**
 * Trackator Tier 1: Solidity AST Parser
 * ======================================
 * Parses .sol files and extracts complete protocol structure.
 * No AI required - pure static analysis.
 */
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
exports.SolidityParser = void 0;
const parser_1 = require("@solidity-parser/parser");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
class SolidityParser {
    constructor(rootPath) {
        this.contracts = new Map();
        this.rootPath = path.resolve(rootPath);
    }
    /**
     * Main entry point - parses entire codebase
     */
    async parseCodebase() {
        const solFiles = this.findSolidityFiles(this.rootPath);
        console.log(`🔍 Found ${solFiles.length} Solidity files`);
        for (const file of solFiles) {
            try {
                this.parseFile(file);
            }
            catch (error) {
                console.warn(`⚠️  Failed to parse ${file}:`, error instanceof Error ? error.message : error);
            }
        }
        return this.buildProtocolStructure();
    }
    /**
     * Find all .sol files in directory
     */
    findSolidityFiles(dir) {
        const files = [];
        const traverse = (currentPath) => {
            if (!fs.existsSync(currentPath))
                return;
            const entries = fs.readdirSync(currentPath, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(currentPath, entry.name);
                // Skip node_modules, lib (unless it's own code), artifacts
                if (entry.isDirectory()) {
                    if (['node_modules', 'artifacts', 'cache', 'lib'].includes(entry.name)) {
                        continue;
                    }
                    traverse(fullPath);
                }
                else if (entry.isFile() && entry.name.endsWith('.sol')) {
                    files.push(fullPath);
                }
            }
        };
        traverse(dir);
        return files;
    }
    /**
     * Parse single Solidity file
     */
    parseFile(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8');
        try {
            const ast = (0, parser_1.parse)(content, { loc: true, range: true });
            // Extract all top-level contract/interface/library definitions
            if (ast.children) {
                for (const child of ast.children) {
                    const childType = child.type;
                    if (childType === 'ContractDefinition' ||
                        childType === 'InterfaceDefinition' ||
                        childType === 'LibraryDefinition') {
                        const contract = this.extractContract(child, filePath);
                        this.contracts.set(`${contract.name}:${filePath}`, contract);
                    }
                }
            }
        }
        catch (parseError) {
            throw new Error(`Parse error in ${filePath}: ${parseError}`);
        }
    }
    /**
     * Extract complete contract information from AST node
     */
    extractContract(node, filePath) {
        const kind = this.getContractKind(node);
        const contract = {
            name: node.name || 'Unknown',
            sourcePath: filePath,
            abstract: node.abstract || false,
            inherited: this.extractInheritance(node),
            inherits: this.extractInheritance(node),
            imports: [], // Will be populated during structure building
            stateVariables: [],
            functions: [],
            modifiers: [],
            events: [],
            structs: [],
            enums: [],
            usingFor: [],
            errors: [],
            lineCount: node.loc?.end?.line || 0,
            kind
        };
        // Process sub-nodes
        if (node.subNodes) {
            for (const subNode of node.subNodes) {
                switch (subNode.type) {
                    case 'StateVariableDeclaration':
                        contract.stateVariables.push(...this.extractStateVariables(subNode));
                        break;
                    case 'FunctionDefinition':
                    case 'ConstructorDefinition':
                        contract.functions.push(this.extractFunction(subNode));
                        break;
                    case 'ModifierDefinition':
                        contract.modifiers.push(this.extractModifier(subNode));
                        break;
                    case 'EventDefinition':
                        contract.events.push(this.extractEvent(subNode));
                        break;
                    case 'UsingForDeclaration':
                        contract.usingFor.push(this.extractUsingFor(subNode));
                        break;
                    case 'CustomErrorDefinition':
                        contract.errors.push(this.extractError(subNode));
                        break;
                }
            }
        }
        // Extract external calls within functions
        for (const func of contract.functions) {
            func.externalCalls = this.findExternalCalls(func.body);
        }
        return contract;
    }
    getContractKind(node) {
        if (node.kind === 'interface')
            return 'interface';
        if (node.kind === 'library')
            return 'library';
        if (node.abstract)
            return 'abstract';
        return 'contract';
    }
    extractInheritance(node) {
        return (node.baseContracts || []).map((bc) => bc.baseName.name);
    }
    /**
     * Extract state variables from declaration
     */
    extractStateVariables(node) {
        const variables = [];
        for (const varDecl of node.variables || []) {
            const isConst = varDecl.isDeclaredConst || false;
            const isImmut = varDecl.isImmutable || false;
            variables.push({
                name: varDecl.name || '(unnamed)',
                type: this.getTypeString(varDecl.typeName),
                visibility: (isConst ? 'constant' : isImmut ? 'immutable' : varDecl.visibility) || 'internal',
                mutability: isConst ? 'constant' : isImmut ? 'immutable' : 'mutable',
                slot: undefined,
                offset: undefined,
                overridden: false,
                initialized: !!varDecl.expression,
                isConstant: isConst || undefined,
                isStateVar: !isConst && !isImmut,
                defaultValue: varDecl.expression ? this.extractDefaultValue(varDecl.expression) : undefined
            });
        }
        return variables;
    }
    /**
     * Extract function definition
     */
    extractFunction(node) {
        return {
            name: node.name || (node.isConstructor ? 'constructor' :
                node.isReceiveEther ? 'receive' :
                    node.isFallback ? 'fallback' : 'unknown'),
            kind: node.isConstructor ? 'constructor' :
                node.isReceiveEther ? 'receive' :
                    node.isFallback ? 'fallback' : 'function',
            visibility: node.visibility || 'public',
            stateMutability: node.stateMutability || 'nonpayable',
            virtual: node.virtual || false,
            override: node.override || false,
            modifiers: (node.modifiers || []).map((m) => m.name),
            parameters: this.extractParameters(node.parameters),
            returnParameters: this.extractParameters(node.returnParameters),
            body: {
                statements: 0,
                hasRequire: false,
                hasRevert: false,
                hasExternalCall: false,
                hasLoop: false,
                hasTransfer: false,
                hasDelegateCall: false,
                ceiPattern: 'unknown'
            },
            calls: [],
            externalCalls: [],
            eventsEmitted: [],
            stateVariablesRead: [],
            stateVariablesWritten: [],
            lineStart: node.loc?.start?.line || 0,
            lineEnd: node.loc?.end?.line || 0,
            complexity: 0
        };
    }
    /**
     * Extract modifier definition
     */
    extractModifier(node) {
        return {
            name: node.name || 'unknown',
            parameters: this.extractParameters(node.parameters),
            visibility: node.visibility || 'internal',
            appliedTo: [],
            lineDeclared: node.loc?.start?.line || 0
        };
    }
    /**
     * Extract event definition
     */
    extractEvent(node) {
        return {
            name: node.name || 'unknown',
            parameters: this.extractParameters(node.parameters, true),
            anonymous: node.anonymous || false,
            emittedBy: [],
            lineDeclared: node.loc?.start?.line || 0
        };
    }
    extractUsingFor(node) {
        return {
            type: node.typeName ? this.getTypeString(node.typeName) : '*',
            library: node.libraryNames || [node.libraryName || ''].filter(Boolean)
        };
    }
    extractError(node) {
        return {
            name: node.name || 'unknown',
            parameters: this.extractParameters(node.parameters)
        };
    }
    /**
     * Extract parameters from function/event definition
     */
    extractParameters(paramsNode, includeIndexed = false) {
        const params = [];
        if (!paramsNode || !paramsNode.params)
            return params;
        for (const param of paramsNode.params) {
            params.push({
                name: param.name || null,
                type: this.getTypeString(param.typeName),
                indexed: includeIndexed ? param.indexed || false : undefined
            });
        }
        return params;
    }
    /**
     * Convert type AST node to string representation
     */
    getTypeString(typeName) {
        if (!typeName)
            return 'undefined';
        switch (typeName.type) {
            case 'ElementaryTypeName':
                return typeName.name || 'unknown';
            case 'UserDefinedTypeName':
                return typeName.namePath || 'unknown';
            case 'ArrayTypeName':
                const baseType = this.getTypeString(typeName.baseTypeName);
                const length = typeName.length ? `[${typeName.length}]` : '[]';
                return `${baseType}${length}`;
            case 'Mapping':
                return `mapping(${this.getTypeString(typeName.keyType)} => ${this.getTypeString(typeName.valueType)})`;
            case 'FunctionTypeName':
                return 'function';
            case 'TupleExpression':
                return 'tuple';
            default:
                return typeName.name || typeName.type || 'unknown';
        }
    }
    /**
     * Find all external calls in function body
     */
    findExternalCalls(body) {
        const calls = [];
        if (!body)
            return calls;
        this.traverseAST(body, (node) => {
            // Function call expression
            if (node.type === 'FunctionCall') {
                const callInfo = this.analyzeExternalCall(node);
                if (callInfo) {
                    calls.push(callInfo);
                }
            }
            // Send/Transfer
            if (node.type === 'Send' || node.type === 'Transfer') {
                calls.push({
                    functionName: node.type,
                    contractName: this.getTargetContract(node.arguments?.[0]),
                    arguments: node.arguments || [],
                    line: node.loc?.start?.line || 0,
                    isSendOrTransfer: true,
                    isDelegateCall: false,
                    isStaticCall: false
                });
            }
        });
        return calls;
    }
    analyzeExternalCall(node) {
        // Check for external call patterns
        let functionName = '';
        let contractName = '';
        if (node.expression?.type === 'MemberAccess') {
            functionName = node.expression.memberName || '';
            contractName = this.getTargetContract(node.expression.object);
        }
        else if (node.expression?.type === 'Identifier') {
            functionName = node.expression.name || '';
            contractName = 'this'; // Internal or inherited
        }
        // Skip if no meaningful target
        if (!functionName && !contractName)
            return null;
        return {
            functionName,
            contractName,
            arguments: node.arguments || [],
            line: node.loc?.start?.line || 0,
            isSendOrTransfer: false,
            isDelegateCall: functionName.toLowerCase() === 'delegatecall',
            isStaticCall: functionName.toLowerCase() === 'staticcall' ||
                functionName.toLowerCase() === 'callstatic'
        };
    }
    getTargetContract(object) {
        if (!object)
            return 'unknown';
        if (object.type === 'Identifier') {
            return object.name || 'unknown';
        }
        if (object.type === 'MemberAccess') {
            return object.name || 'unknown';
        }
        if (object.type === 'IndexAccess') {
            return this.getTargetContract(object.base);
        }
        return 'external';
    }
    /**
     * Traverse AST and call visitor on each node
     */
    traverseAST(node, visitor) {
        if (!node || typeof node !== 'object')
            return;
        visitor(node);
        // Recurse into children
        for (const key of Object.keys(node)) {
            if (key === 'loc' || key === 'range')
                continue; // Skip metadata
            const value = node[key];
            if (Array.isArray(value)) {
                for (const item of value) {
                    if (item && typeof item === 'object') {
                        this.traverseAST(item, visitor);
                    }
                }
            }
            else if (value && typeof value === 'object') {
                this.traverseAST(value, visitor);
            }
        }
    }
    extractDefaultValue(expression) {
        if (!expression)
            return undefined;
        switch (expression.type) {
            case 'NumberLiteral':
                return Number(expression.number);
            case 'StringLiteral':
                return expression.value;
            case 'BooleanLiteral':
                return expression.value;
            case 'HexLiteral':
                return expression.value;
            default:
                return undefined;
        }
    }
    /**
     * Build complete ProtocolStructure from parsed contracts
     */
    buildProtocolStructure() {
        const contracts = Array.from(this.contracts.values());
        return {
            name: this.extractProtocolName(),
            sourcePath: this.rootPath,
            abstract: false,
            inherited: [],
            contracts,
            inheritanceMap: this.buildInheritanceMap(),
            importGraph: this.buildImportGraph(),
            callGraph: this.buildCallGraph(),
            stateInventory: this.buildStateInventory(),
            functionRegistry: this.buildFunctionRegistry(),
            modifierMap: this.buildModifierMap(),
            eventCatalog: this.buildEventCatalog(),
            accessControl: this.buildAccessControlMatrix(),
            externalCallMap: this.buildExternalCallSummary()
        };
    }
    extractProtocolName() {
        // Try to get name from package.json or foundry.toml
        try {
            const pkgPath = path.join(this.rootPath, 'package.json');
            if (fs.existsSync(pkgPath)) {
                const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
                return pkg.name || path.basename(this.rootPath);
            }
        }
        catch { }
        try {
            const foundryPath = path.join(this.rootPath, 'foundry.toml');
            if (fs.existsSync(foundryPath)) {
                const content = fs.readFileSync(foundryPath, 'utf-8');
                const match = content.match(/\s*=\s*["']([^"']+)["']/);
                if (match)
                    return match[1];
            }
        }
        catch { }
        return path.basename(this.rootPath);
    }
    buildInheritanceMap() {
        const map = new Map();
        for (const contract of Array.from(this.contracts.values())) {
            if (contract.inherits.length > 0) {
                map.set(contract.name, contract.inherits);
            }
        }
        return map;
    }
    buildImportGraph() {
        const map = new Map();
        // Simplified import tracking - would need preprocessor for full accuracy
        for (const [key, contract] of Array.from(this.contracts.entries())) {
            // Look for imports in file
            try {
                const content = fs.readFileSync(contract.sourcePath, 'utf-8');
                const imports = [];
                const importRegex = /import\s+[^;]+;/g;
                let match;
                while ((match = importRegex.exec(content)) !== null) {
                    imports.push(match[0].trim());
                }
                if (imports.length > 0) {
                    map.set(contract.name, imports);
                }
            }
            catch { }
        }
        return map;
    }
    buildCallGraph() {
        const nodes = [];
        for (const contract of Array.from(this.contracts.values())) {
            for (const func of contract.functions) {
                const externalCalls = (func.externalCalls || []);
                for (const call of externalCalls) {
                    const callType = call.isDelegateCall ? 'delegatecall' :
                        call.isSendOrTransfer ? (call.functionName === 'transfer' ? 'transfer' : 'send') :
                            call.isStaticCall ? 'external' :
                                contract.name === call.contractName || this.hasInheritanceRelation(contract.name, call.contractName) ? 'internal' : 'external';
                    nodes.push({
                        contract: contract.name,
                        function: func.name,
                        from: { contract: contract.name, function: func.name },
                        calls: [{
                                from: { contract: contract.name, function: func.name },
                                to: { contract: call.contractName, function: call.functionName },
                                type: callType
                            }],
                        calledBy: [],
                        visibility: func.visibility,
                        isExternal: callType === 'external',
                        isEntry: func.visibility === 'external' || func.visibility === 'public'
                    });
                }
            }
        }
        return nodes;
    }
    hasInheritanceRelation(child, parent) {
        const childContract = Array.from(this.contracts.values()).find(c => c.name === child);
        if (!childContract)
            return false;
        const inherits = childContract.inherits || childContract.inherited || [];
        return inherits.includes(parent);
    }
    buildStateInventory() {
        const variables = [];
        let totalSlotsUsed = 0;
        let currentSlot = 0;
        for (const contract of Array.from(this.contracts.values())) {
            const stateVars = contract.stateVariables.filter(v => v.isStateVar);
            // Calculate storage slots (simplified EVM layout)
            for (const v of stateVars) {
                variables.push({
                    variable: v,
                    computedSlot: currentSlot,
                    computedOffset: 0,
                    typeSize: this.estimateSlotsForType(v.type),
                    encoding: 'single'
                });
                // Advance slot (simplified - doesn't handle packing)
                currentSlot += this.estimateSlotsForType(v.type);
            }
        }
        totalSlotsUsed = currentSlot;
        return {
            contractName: this.extractProtocolName(),
            variables: variables,
            totalSlotsUsed,
            totalVariables: variables.length,
            valueBearing: variables.filter((vi) => this.isValueBearingVariable(vi.variable)).length
        };
    }
    estimateSlotsForType(typeStr) {
        // Very simplified slot estimation
        if (typeStr.includes('mapping'))
            return 32; // Mappings use many slots
        if (typeStr.includes('struct'))
            return 1; // Depends on struct size
        if (typeStr.includes('string') || typeStr.includes('bytes'))
            return 1;
        if (typeStr.includes('int256') || typeStr.includes('uint256') || typeStr.includes('address') || typeStr.includes('bytes32'))
            return 1;
        return 1; // Default
    }
    isValueBearingVariable(v) {
        const nameLower = v.name.toLowerCase();
        const typeLower = v.type.toLowerCase();
        // Heuristics for value-bearing variables
        const valuePatterns = [
            'balance', 'total', 'supply', 'reserve', 'collateral', 'debt',
            'borrow', 'deposit', 'withdraw', 'amount', 'value', 'asset',
            'liability', 'share', 'token', 'fund', 'treasury', 'vault',
            'staked', 'locked', 'reward', 'fee', 'interest', 'principal'
        ];
        return valuePatterns.some(p => nameLower.includes(p) || typeLower.includes(p));
    }
    buildFunctionRegistry() {
        const entries = [];
        const byContract = new Map();
        const byCategory = new Map();
        for (const contract of Array.from(this.contracts.values())) {
            const registeredFuncs = [];
            for (const func of contract.functions) {
                const entry = {
                    id: `${contract.name}.${func.name}`,
                    contract: contract.name,
                    signature: `${func.name}(${func.parameters.map((p) => p.type).join(',')})`,
                    name: func.name,
                    function: func.name,
                    category: 'core-logic',
                    accessControl: {
                        level: (func.visibility === 'public' || func.visibility === 'external') ? 'public' : 'internal',
                        rolesRequired: [],
                        modifiers: func.modifiers,
                        ownerOnly: func.modifiers.some((m) => m.includes('Owner')),
                        length: func.modifiers.length
                    },
                    risk: { score: 50, overall: 'medium', factors: [] },
                    stateReads: func.stateVariablesRead || [],
                    stateWrites: func.stateVariablesWritten || [],
                    externalCalls: (func.externalCalls || []).map((c) => c.functionName || c.function || ''),
                    lineDeclared: func.lineStart
                };
                entries.push(entry);
                registeredFuncs.push(entry);
            }
            byContract.set(contract.name, registeredFuncs);
            byCategory.set('all', [...(byCategory.get('all') || []), ...registeredFuncs]);
        }
        const externalFunctions = entries.filter((e) => {
            for (const c of Array.from(this.contracts.values())) {
                const found = c.functions.find((f) => f.name === e.name);
                if (found && (found.visibility === 'external' || found.visibility === 'public')) {
                    return true;
                }
            }
            return false;
        });
        return {
            entries,
            totalFunctions: entries.length,
            byContract: byContract,
            byCategory: byCategory
        };
    }
    buildModifierMap() {
        const result = {};
        for (const contract of Array.from(this.contracts.values())) {
            // Collect definitions and applications
            for (const mod of contract.modifiers) {
                if (!result[mod.name]) {
                    result[mod.name] = {
                        appliedTo: [],
                        parameters: (mod.parameters || []).map((p) => p.type),
                        conditions: []
                    };
                }
            }
            // Collect applications
            for (const func of contract.functions) {
                for (const modName of func.modifiers) {
                    if (result[modName]) {
                        result[modName].appliedTo.push(`${contract.name}.${func.name}`);
                    }
                }
            }
        }
        return result;
    }
    buildEventCatalog() {
        const result = {};
        for (const contract of Array.from(this.contracts.values())) {
            for (const event of contract.events) {
                result[event.name] = {
                    ...event,
                    emittedByFunctions: event.emittedBy || []
                };
            }
        }
        return result;
    }
    buildAccessControlMatrix() {
        const result = {};
        const roleToFunctions = new Map();
        const unprotectedFunctions = [];
        // Common access control patterns
        const acPatterns = [
            { regex: /onlyOwner|onlyRole\(_?owner\)|msg\.sender\s*==\s*owner/i, role: 'Owner', trustLevel: 'critical' },
            { regex: /onlyAdmin|isAdmin|hasRole\(ADMIN\)/i, role: 'Admin', trustLevel: 'high' },
            { regex: /onlyGuardian|isGuardian|hasRole\(GUARDIAN\)/i, role: 'Guardian', trustLevel: 'high' },
            { regex: /onlyManager|isManager|hasRole\(MANAGER\)/i, role: 'Manager', trustLevel: 'medium' },
            { regex: /onlyOperator|isOperator|hasRole\(OPERATOR\)/i, role: 'Operator', trustLevel: 'medium' },
            { regex: /onlyPauser|isPauser/i, role: 'Pauser', trustLevel: 'medium' },
            { regex: /whenNotPaused|whenPaused/i, role: 'PauseGuard', trustLevel: 'low' },
            { regex: /nonReentrant|ReentrancyGuard/i, role: 'ReentrancyGuard', trustLevel: 'low' }
        ];
        for (const contract of Array.from(this.contracts.values())) {
            for (const func of contract.functions) {
                const fullFuncName = `${contract.name}.${func.name}`;
                const appliedRoles = [];
                let hasAnyProtection = false;
                for (const pattern of acPatterns) {
                    if (func.modifiers.some(m => pattern.regex.test(m))) {
                        appliedRoles.push(pattern.role);
                        hasAnyProtection = true;
                        if (!roleToFunctions.has(pattern.role)) {
                            roleToFunctions.set(pattern.role, []);
                        }
                        roleToFunctions.get(pattern.role).push(fullFuncName);
                    }
                }
                result[fullFuncName] = {
                    roles: appliedRoles,
                    modifiers: func.modifiers,
                    visibility: func.visibility,
                    restrictions: []
                };
                if (!hasAnyProtection && (func.visibility === 'public' || func.visibility === 'external')) {
                    if (func.stateMutability !== 'view' && func.stateMutability !== 'pure') {
                        unprotectedFunctions.push(fullFuncName);
                    }
                }
            }
        }
        return result;
    }
    generateRoleDescription(role) {
        const descriptions = {
            'Owner': 'Full administrative control over protocol parameters and funds',
            'Admin': 'Elevated privileges for operational management',
            'Guardian': 'Emergency response capabilities (pause, emergency actions)',
            'Manager': 'Day-to-day operational control',
            'Operator': 'Execution of specific automated tasks',
            'Pauser': 'Ability to pause protocol operations',
            'PauseGuard': 'Pause state enforcement modifier',
            'ReentrancyGuard': 'Protection against reentrancy attacks'
        };
        return descriptions[role] || 'Custom role with elevated permissions';
    }
    buildExternalCallSummary() {
        const byTarget = new Map();
        const bySource = new Map();
        const dangerousPatterns = [];
        let totalCalls = 0;
        for (const contract of Array.from(this.contracts.values())) {
            for (const func of contract.functions) {
                const externalCalls = func.externalCalls || [];
                for (const call of externalCalls) {
                    const fullFuncName = `${contract.name}.${func.name}`;
                    totalCalls++;
                    // By target
                    if (!byTarget.has(call.contractName)) {
                        byTarget.set(call.contractName, []);
                    }
                    byTarget.get(call.contractName).push({ ...call, contractName: contract.name });
                    // By source
                    if (!bySource.has(fullFuncName)) {
                        bySource.set(fullFuncName, []);
                    }
                    bySource.get(fullFuncName).push(call);
                    // Check for dangerous patterns
                    const danger = this.detectDangerousPattern(contract.name, func.name, call);
                    if (danger) {
                        dangerousPatterns.push(danger);
                    }
                }
            }
        }
        // Return first/primary target summary or a summary object
        const primaryTarget = byTarget.keys().next().value || 'unknown';
        const primaryCall = byTarget.get(primaryTarget)?.[0];
        return {
            target: primaryTarget,
            function: primaryCall?.functionName || '',
            valueSent: primaryCall?.isSendOrTransfer || false,
            trustAssumption: 'unknown',
            riskLevel: dangerousPatterns.length > 0 ? 'high' : 'low',
            totalCalls,
            byTarget: byTarget,
            bySource: bySource,
            dangerousPatterns: dangerousPatterns
        };
    }
    detectDangerousPattern(contract, func, call) {
        // Reentrancy detection: external call before state update would need deeper analysis
        // Here we flag potential vectors
        if (call.isDelegateCall) {
            return {
                id: `delegate-${contract}-${func}-${call.line}`,
                name: 'Delegate Call Risk',
                category: 'security',
                patternType: 'delegate-call',
                severity: 'critical',
                description: `Delegate call to ${call.contractName}.${call.functionName} - arbitrary code execution risk`,
                location: { file: contract, line: call.line },
                recommendation: 'Avoid delegate calls to untrusted addresses or validate caller thoroughly'
            };
        }
        if (call.functionName.toLowerCase() === 'call' && !call.isStaticCall) {
            return {
                id: `unchecked-${contract}-${func}-${call.line}`,
                name: 'Unchecked Low-level Call',
                category: 'security',
                patternType: 'unchecked-call',
                severity: 'high',
                description: `Low-level call to ${call.contractName} - check return value`,
                location: { file: contract, line: call.line },
                recommendation: 'Always check the return value of low-level calls'
            };
        }
        if (call.isSendOrTransfer) {
            return {
                id: `reentrancy-${contract}-${func}-${call.line}`,
                name: 'Potential Reentrancy',
                category: 'security',
                patternType: 'reentrancy',
                severity: 'medium',
                description: `${call.functionName} may enable reentrancy if state not updated first`,
                location: { file: contract, line: call.line },
                recommendation: 'Use checks-effects-interactions pattern to prevent reentrancy'
            };
        }
        return null;
    }
    /**
     * Get parsed contracts (for testing/debugging)
     */
    getParsedContracts() {
        return Array.from(this.contracts.values());
    }
}
exports.SolidityParser = SolidityParser;
exports.default = SolidityParser;
//# sourceMappingURL=SolidityParser.js.map