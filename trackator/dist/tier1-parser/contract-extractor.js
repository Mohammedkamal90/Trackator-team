"use strict";
// ============================================================
// TRACKATOR Tier 1 - Contract Extractor
// Parses Solidity source files and extracts contract definitions
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
exports.extractContracts = extractContracts;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const glob_1 = require("glob");
// Try to use solidity-parser, fallback to regex if not available
let parser = null;
try {
    parser = require('@solidity-parser/parser');
}
catch (e) {
    // Will use fallback parser
}
/**
 * Main entry point for parsing Solidity sources
 */
async function extractContracts(sourcePattern, options = {}) {
    const { includeNodeModules = false, verbose = false } = options;
    const files = await resolveSourceFiles(sourcePattern, includeNodeModules);
    if (verbose) {
        console.log(`Found ${files.length} Solidity files to parse`);
    }
    const contracts = [];
    const errors = [];
    const warnings = [];
    for (const file of files) {
        try {
            const result = parseFile(file);
            contracts.push(...result.contracts);
            errors.push(...result.errors);
            warnings.push(...result.warnings);
            if (verbose) {
                console.log(`  Parsed ${file}: ${result.contracts.length} contracts found`);
            }
        }
        catch (error) {
            errors.push(`Failed to parse ${file}: ${error.message}`);
        }
    }
    return {
        contracts,
        errors,
        warnings,
        filesProcessed: files.length
    };
}
/**
 * Resolve glob pattern or single file to list of .sol files
 */
async function resolveSourceFiles(pattern, includeNodeModules) {
    // Check if it's a directory
    if (fs.existsSync(pattern) && fs.statSync(pattern).isDirectory()) {
        pattern = path.join(pattern, '**/*.sol');
    }
    // Check if it's a single file
    if (fs.existsSync(pattern) && pattern.endsWith('.sol')) {
        return [pattern];
    }
    // Use glob for pattern matching
    const files = await (0, glob_1.glob)(pattern, {
        ignore: includeNodeModules ? [] : ['**/node_modules/**', '**/lib/**/*'],
        absolute: true
    });
    return files.filter(f => f.endsWith('.sol'));
}
/**
 * Parse a single Solidity file
 */
function parseFile(filePath) {
    const source = fs.readFileSync(filePath, 'utf-8');
    const contracts = [];
    const errors = [];
    const warnings = [];
    if (parser) {
        // Use proper AST parser
        try {
            const ast = parser.parse(source, { loc: true, range: true });
            contracts.push(...extractFromAST(ast, filePath));
        }
        catch (parseError) {
            errors.push(`AST parse error in ${filePath}: ${parseError.message}`);
            // Fallback to regex-based extraction
            contracts.push(...extractWithRegex(source, filePath));
        }
    }
    else {
        // Use regex-based extraction
        warnings.push(`Using regex parser for ${filePath}. Install @solidity-parser/parser for better results.`);
        contracts.push(...extractWithRegex(source, filePath));
    }
    return { contracts, errors, warnings };
}
/**
 * Extract contracts using proper AST parser
 */
function extractFromAST(ast, filePath) {
    const contracts = [];
    if (!ast || !ast.children)
        return contracts;
    // Extract imports first
    const imports = [];
    for (const node of ast.children) {
        if (node.type === 'ImportDirective') {
            imports.push(node.path || 'unknown');
        }
    }
    // Extract contracts, interfaces, libraries, abstract contracts
    for (const node of ast.children) {
        if (['ContractDefinition', 'LibraryDefinition'].includes(node.type)) {
            const contract = extractContractNode(node, filePath, imports);
            if (contract) {
                contracts.push(contract);
            }
        }
    }
    return contracts;
}
/**
 * Extract a single contract from AST node
 */
function extractContractNode(node, filePath, imports) {
    const name = node.name || 'Unknown';
    // Extract base contracts
    const inherited = [];
    if (node.baseContracts) {
        for (const base of node.baseContracts) {
            inherited.push(base.baseName?.namePath || base.baseName || 'unknown');
        }
    }
    // Extract state variables
    const stateVariables = extractStateVariables(node);
    // Extract functions
    const functions = extractFunctions(node, name);
    // Extract events
    const events = extractEvents(node);
    // Extract modifiers
    const modifiers = extractModifiers(node);
    // Extract structs
    const structs = extractStructs(node);
    // Extract enums
    const enums = extractEnums(node);
    // Extract custom errors
    const errors = extractCustomErrors(node);
    // Extract using-for declarations
    const usingFor = extractUsingFor(node);
    return {
        name,
        sourcePath: filePath,
        abstract: node.kind === 'abstract',
        inherited,
        imports,
        stateVariables,
        functions,
        events,
        modifiers,
        structs,
        enums,
        errors,
        usingFor,
        lineCount: node.loc ? node.loc.end.line - node.loc.start.line + 1 : 0
    };
}
/**
 * Extract state variables from contract node
 */
function extractStateVariables(contractNode) {
    const variables = [];
    if (!contractNode.subNodes)
        return variables;
    let slotCounter = 0;
    for (const node of contractNode.subNodes) {
        if (node.type === 'StateVariableDeclaration') {
            for (const varDecl of node.variables) {
                const variable = {
                    name: varDecl.name || 'unnamed',
                    type: typeToString(varDecl.typeName),
                    visibility: varDecl.visibility || 'internal',
                    mutability: varDecl.mutability || 'nonpayable',
                    slot: slotCounter++,
                    overridden: !!varDecl.isDeclaredConst,
                    initialized: varDecl.defaultValue !== null && varDecl.defaultValue !== undefined,
                    comments: extractComments(varDecl)
                };
                if (varDecl.defaultValue) {
                    variable.defaultValue = exprToString(varDecl.defaultValue);
                }
                // Handle constant/immutable special cases
                if (variable.mutability === 'constant') {
                    variable.visibility = 'constant';
                }
                else if (variable.mutability === 'immutable') {
                    variable.visibility = 'immutable';
                }
                variables.push(variable);
            }
        }
    }
    return variables;
}
/**
 * Extract functions from contract node
 */
function extractFunctions(contractNode, contractName) {
    const functions = [];
    if (!contractNode.subNodes)
        return functions;
    for (const node of contractNode.subNodes) {
        if (['FunctionDefinition', 'ConstructorDefinition'].includes(node.type)) {
            const func = extractFunctionNode(node, contractName);
            if (func) {
                functions.push(func);
            }
        }
    }
    // Link events to their emitting functions
    return functions;
}
/**
 * Extract a single function from AST node
 */
function extractFunctionNode(node, contractName) {
    const name = node.name || (node.isConstructor ? 'constructor' :
        node.kind === 'receive' ? 'receive' :
            node.kind === 'fallback' ? 'fallback' : 'anonymous');
    const parameters = extractParameters(node.parameters);
    const returnParameters = extractParameters(node.returnParameters);
    // Extract modifiers applied to this function
    const modifiers = [];
    if (node.modifiers) {
        for (const mod of node.modifiers) {
            modifiers.push(mod.name?.namePath || mod.name || 'unknown');
        }
    }
    // Analyze function body
    const body = analyzeFunctionBody(node.body);
    // Extract calls made by this function
    const calls = extractCallsFromBody(node.body);
    // Extract state variable reads/writes
    const { read: stateVarsRead, written: stateVarsWritten } = extractStateAccess(node.body);
    return {
        name,
        kind: node.type === 'ConstructorDefinition' ? 'constructor' : 'function',
        visibility: node.visibility || 'public',
        stateMutability: node.stateMutability || 'nonpayable',
        virtual: !!node.isVirtual,
        override: !!node.overrideSpec,
        parameters,
        returnParameters,
        modifiers,
        body,
        calls,
        eventsEmitted: [], // Will be populated during event linking
        stateVariablesRead: stateVarsRead,
        stateVariablesWritten: stateVarsWritten,
        lineStart: node.loc?.start.line || 0,
        lineEnd: node.loc?.end.line || 0,
        complexity: estimateComplexity(node.body)
    };
}
/**
 * Analyze function body for CEI pattern and other properties
 */
function analyzeFunctionBody(body) {
    const defaultBody = {
        statements: 0,
        hasRequire: false,
        hasRevert: false,
        hasExternalCall: false,
        hasLoop: false,
        hasTransfer: false,
        hasDelegateCall: false,
        ceiPattern: 'not-applicable'
    };
    if (!body || !body.statements)
        return defaultBody;
    let statements = 0;
    let lastEffectIndex = -1;
    let firstInteractionIndex = -1;
    const analyzeStatement = (stmt, index) => {
        statements++;
        // Check for require/revert
        if (stmt.type === 'ExpressionStatement') {
            const expr = stmt.expression;
            if (expr) {
                if (expr.type === 'FunctionCall') {
                    const funcName = getFunctionCallName(expr);
                    if (funcName === 'require' || funcName === 'assert') {
                        defaultBody.hasRequire = true;
                    }
                    else if (funcName === 'revert') {
                        defaultBody.hasRevert = true;
                    }
                    else if (['call', 'delegatecall', 'staticcall'].includes(funcName)) {
                        defaultBody.hasExternalCall = true;
                        if (funcName === 'delegatecall') {
                            defaultBody.hasDelegateCall = true;
                        }
                        if (firstInteractionIndex === -1)
                            firstInteractionIndex = index;
                    }
                    else if (['transfer', 'send'].includes(funcName)) {
                        defaultBody.hasTransfer = true;
                        if (firstInteractionIndex === -1)
                            firstInteractionIndex = index;
                    }
                    else if (isExternalCall(expr)) {
                        defaultBody.hasExternalCall = true;
                        if (firstInteractionIndex === -1)
                            firstInteractionIndex = index;
                    }
                    // Check for effects (state changes)
                    if (isStateChange(expr)) {
                        lastEffectIndex = index;
                    }
                }
            }
        }
        // Check for loops
        if (['ForStatement', 'WhileStatement', 'DoWhileStatement'].includes(stmt.type)) {
            defaultBody.hasLoop = true;
        }
        // Recurse into nested blocks/statements
        if (stmt.body) {
            if (Array.isArray(stmt.body)) {
                stmt.body.forEach((s, i) => analyzeStatement(s, i));
            }
            else {
                analyzeStatement(stmt.body, index);
            }
        }
        if (stmt.trueBody)
            analyzeStatement(stmt.trueBody, index);
        if (stmt.falseBody)
            analyzeStatement(stmt.falseBody, index);
        if (stmt.statements) {
            stmt.statements.forEach((s, i) => analyzeStatement(s, i));
        }
    };
    body.statements.forEach((stmt, index) => analyzeStatement(stmt, index));
    defaultBody.statements = statements;
    // Determine CEI pattern compliance
    if (defaultBody.hasExternalCall) {
        if (lastEffectIndex === -1 || lastEffectIndex < firstInteractionIndex) {
            defaultBody.ceiPattern = 'valid'; // No effects before interactions
        }
        else {
            defaultBody.ceiPattern = 'violated'; // Effects before interactions detected
        }
    }
    else if (statements > 0) {
        defaultBody.ceiPattern = 'not-applicable'; // No external calls to check
    }
    return defaultBody;
}
/**
 * Estimate cyclomatic complexity of function
 */
function estimateComplexity(body) {
    let complexity = 1; // Base complexity
    if (!body || !body.statements)
        return complexity;
    const countDecisions = (node) => {
        if (!node)
            return;
        switch (node.type) {
            case 'IfStatement':
                complexity++;
                if (node.falseBody)
                    complexity++;
                break;
            case 'ForStatement':
            case 'WhileStatement':
            case 'DoWhileStatement':
                complexity++;
                break;
            case 'Conditional':
                complexity += 2;
                break;
            case 'BinaryOperation':
                if (['&&', '||', '??'].includes(node.operator)) {
                    complexity++;
                }
                break;
            case 'SwitchStatement':
                complexity += node.cases?.length || 1;
                break;
        }
        // Recurse into children
        for (const key of Object.keys(node)) {
            const value = node[key];
            if (Array.isArray(value)) {
                value.forEach(v => {
                    if (v && typeof v === 'object' && v.type)
                        countDecisions(v);
                });
            }
            else if (value && typeof value === 'object' && value.type) {
                countDecisions(value);
            }
        }
    };
    body.statements.forEach(stmt => countDecisions(stmt));
    return complexity;
}
/**
 * Extract function calls from body
 */
function extractCallsFromBody(body) {
    const calls = [];
    if (!body || !body.statements)
        return calls;
    const extractCalls = (node) => {
        if (!node)
            return;
        if (node.type === 'FunctionCall') {
            const callName = getFunctionCallName(node);
            if (callName && !['require', 'revert', 'assert', 'transfer', 'send', 'call', 'delegatecall', 'staticcall'].includes(callName)) {
                calls.push(callName);
            }
        }
        // Recurse
        for (const key of Object.keys(node)) {
            const value = node[key];
            if (Array.isArray(value)) {
                value.forEach(v => {
                    if (v && typeof v === 'object' && v.type)
                        extractCalls(v);
                });
            }
            else if (value && typeof value === 'object' && value.type) {
                extractCalls(value);
            }
        }
    };
    body.statements.forEach(stmt => extractCalls(stmt));
    return [...new Set(calls)]; // Deduplicate
}
/**
 * Extract state variable access (reads/writes)
 */
function extractStateAccess(body) {
    const read = [];
    const written = [];
    if (!body || !body.statements)
        return { read, written };
    const extractAccess = (node) => {
        if (!node)
            return;
        if (node.type === 'MemberAccess' && node.memberName) {
            // This is a simplified check - full implementation would track assignment context
            if (isStateMemberAccess(node)) {
                read.push(node.memberName);
            }
        }
        // Recurse
        for (const key of Object.keys(node)) {
            const value = node[key];
            if (Array.isArray(value)) {
                value.forEach(v => {
                    if (v && typeof v === 'object' && v.type)
                        extractAccess(v);
                });
            }
            else if (value && typeof value === 'object' && value.type) {
                extractAccess(value);
            }
        }
    };
    body.statements.forEach(stmt => extractAccess(stmt));
    return { read: [...new Set(read)], written: [...new Set(written)] };
}
/**
 * Extract events from contract node
 */
function extractEvents(contractNode) {
    const events = [];
    if (!contractNode.subNodes)
        return events;
    for (const node of contractNode.subNodes) {
        if (node.type === 'EventDefinition') {
            const parameters = extractParameters(node.parameters);
            events.push({
                name: node.name || 'UnknownEvent',
                parameters,
                anonymous: !!node.isAnonymous,
                emittedBy: [], // Will be populated later
                lineDeclared: node.loc?.start.line || 0
            });
        }
    }
    return events;
}
/**
 * Extract modifiers from contract node
 */
function extractModifiers(contractNode) {
    const modifiers = [];
    if (!contractNode.subNodes)
        return modifiers;
    for (const node of contractNode.subNodes) {
        if (node.type === 'ModifierDefinition') {
            const parameters = extractParameters(node.parameters);
            modifiers.push({
                name: node.name || 'UnknownModifier',
                parameters,
                appliedTo: [], // Will be populated later
                lineDeclared: node.loc?.start.line || 0
            });
        }
    }
    return modifiers;
}
/**
 * Extract structs from contract node
 */
function extractStructs(contractNode) {
    const structs = [];
    if (!contractNode.subNodes)
        return structs;
    for (const node of contractNode.subNodes) {
        if (node.type === 'StructDefinition') {
            const members = [];
            if (node.members) {
                for (const member of node.members) {
                    members.push({
                        name: member.name || 'unknown',
                        type: typeToString(member.typeName)
                    });
                }
            }
            structs.push({
                name: node.name || 'UnknownStruct',
                members
            });
        }
    }
    return structs;
}
/**
 * Extract enums from contract node
 */
function extractEnums(contractNode) {
    const enums = [];
    if (!contractNode.subNodes)
        return enums;
    for (const node of contractNode.subNodes) {
        if (node.type === 'EnumDefinition') {
            const members = [];
            if (node.members) {
                for (const member of node.members) {
                    members.push(member.name || 'unknown');
                }
            }
            enums.push({
                name: node.name || 'UnknownEnum',
                members
            });
        }
    }
    return enums;
}
/**
 * Extract custom errors from contract node
 */
function extractCustomErrors(contractNode) {
    const errors = [];
    if (!contractNode.subNodes)
        return errors;
    for (const node of contractNode.subNodes) {
        if (node.type === 'ErrorDefinition') {
            const parameters = extractParameters(node.parameters);
            errors.push({
                name: node.name || 'UnknownError',
                parameters
            });
        }
    }
    return errors;
}
/**
 * Extract using-for declarations
 */
function extractUsingFor(contractNode) {
    const usingFor = [];
    if (!contractNode.subNodes)
        return usingFor;
    for (const node of contractNode.subNodes) {
        if (node.type === 'UsingForDeclaration') {
            const libraries = [];
            if (node.libraryNames) {
                for (const lib of node.libraryNames) {
                    libraries.push(lib.name || 'unknown');
                }
            }
            usingFor.push({
                type: node.typeName ? typeToString(node.typeName) : '*',
                library: libraries.length > 0 ? libraries : ['*']
            });
        }
    }
    return usingFor;
}
// ============================================================
// HELPER FUNCTIONS
// ============================================================
function extractParameters(paramsNode) {
    const params = [];
    if (!paramsNode || !paramsNode.params)
        return params;
    for (const param of paramsNode.params) {
        params.push({
            name: param.name || null,
            type: typeToString(param.typeName),
            indexed: param.isIndexed || false
        });
    }
    return params;
}
function typeToString(typeNode) {
    if (!typeNode)
        return 'unknown';
    switch (typeNode.type) {
        case 'ElementaryTypeName':
            return typeNode.name || 'unknown';
        case 'UserDefinedTypeName':
            return typeNode.namePath || 'unknown';
        case 'ArrayTypeName':
            const baseType = typeToString(typeNode.baseType);
            const length = typeNode.length ? exprToString(typeNode.length) : '';
            return length ? `${baseType}[${length}]` : `${baseType}[]`;
        case 'Mapping':
            const keyType = typeToString(typeNode.keyType);
            const valueType = typeToString(typeNode.valueType);
            return `mapping(${keyType} => ${valueType})`;
        case 'FunctionTypeName':
            return 'function';
        case 'TupleExpression':
            return 'tuple';
        default:
            return typeNode.name || typeNode.type || 'unknown';
    }
}
function exprToString(expr) {
    if (!expr)
        return '';
    switch (expr.type) {
        case 'NumberLiteral':
            return expr.number || '0';
        case 'StringLiteral':
            return `"${expr.string || ''}"`;
        case 'BooleanLiteral':
            return String(expr.value || false);
        case 'Identifier':
            return expr.name || 'unknown';
        case 'TupleExpression':
            return '(' + (expr.components?.map((c) => exprToString(c)).join(',') || '') + ')';
        default:
            return '<expression>';
    }
}
function getFunctionCallName(callNode) {
    if (!callNode || callNode.type !== 'FunctionCall')
        return '';
    const expr = callNode.expression;
    if (!expr)
        return '';
    if (expr.type === 'Identifier') {
        return expr.name || '';
    }
    if (expr.type === 'MemberAccess') {
        return expr.memberName || '';
    }
    return '';
}
function isExternalCall(callNode) {
    if (!callNode || callNode.type !== 'FunctionCall')
        return false;
    const expr = callNode.expression;
    if (!expr)
        return false;
    // External calls typically have MemberAccess expression
    if (expr.type === 'MemberAccess') {
        const name = expr.memberName?.toLowerCase() || '';
        // Common external call patterns
        return ['call', 'transfer', 'send', 'delegatecall', 'staticcall'].includes(name) ||
            // Any call on address-like object
            (expr.expression && expr.expression.type === 'Identifier');
    }
    return false;
}
function isStateChange(expr) {
    // Simplified check - would need full dataflow analysis for accuracy
    if (!expr || expr.type !== 'FunctionCall')
        return false;
    const name = getFunctionCallName(expr)?.toLowerCase() || '';
    return ['push', 'pop', 'transfer', 'mint', 'burn', 'approve', 'transferfrom',
        '_mint', '_burn', '_transfer', 'set', 'add', 'sub', 'mul', 'div'].some(n => name.includes(n));
}
function isStateMemberAccess(node) {
    // Simplified - would need symbol table for accuracy
    return false; // Placeholder
}
function extractComments(node) {
    // Comments would need to be extracted from source using location info
    return undefined;
}
// ============================================================
// REGEX FALLBACK PARSER (when @solidity-parser/parser unavailable)
// ============================================================
function extractWithRegex(source, filePath) {
    const contracts = [];
    // Extract contract definitions
    const contractRegex = /(abstract\s+)?(contract|interface|library)\s+(\w+)(?:\s+is\s+([\w,\s]+))?/g;
    let match;
    while ((match = contractRegex.exec(source)) !== null) {
        const name = match[3];
        const kind = match[2];
        const abstract = match[1] === 'abstract';
        const bases = match[4] ? match[4].split(",").map(function (s) { return s.trim(); }) : [];
        // Extract state variables within this contract
        const stateVars = extractStateVarsRegex(source, match.index);
        // Extract functions within this contract
        const functions = extractFunctionsRegex(source, match.index, name);
        // Extract events
        const events = extractEventsRegex(source, match.index);
        // Extract modifiers
        const modifiers = extractModifiersRegex(source, match.index);
        contracts.push({
            name,
            sourcePath: filePath,
            abstract,
            inherited: bases,
            imports: [],
            stateVariables: stateVars,
            functions,
            events,
            modifiers,
            structs: [],
            enums: [],
            errors: [],
            usingFor: [],
            lineCount: 0
        });
    }
    return contracts;
}
function extractStateVarsRegex(source, startIndex) {
    const vars = [];
    // Simplified regex extraction
    const varRegex = /(\w+)\s+(public|private|internal|constant|immutable)?\s*(\w[\w\[\]]*)\s*(?:=.*?)?;/g;
    // Find the contract body scope and search within it
    // This is a simplified version - real implementation needs scope tracking
    return vars;
}
function extractFunctionsRegex(source, startIndex, contractName) {
    const funcs = [];
    // Simplified regex extraction
    return funcs;
}
function extractEventsRegex(source, startIndex) {
    return [];
}
function extractModifiersRegex(source, startIndex) {
    return [];
}
// Functions are already exported above
// export { extractContracts, parseFile, extractFromAST };
//# sourceMappingURL=contract-extractor.js.map