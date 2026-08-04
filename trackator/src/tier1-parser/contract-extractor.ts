// ============================================================
// TRACKATOR Tier 1 - Contract Extractor
// Parses Solidity source files and extracts contract definitions
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import {
  SolidityContract,
  StateVariable,
  FunctionDef,
  EventDef,
  ModifierDef,
  StructDef,
  EnumDef,
  ErrorDef,
  UsingForDecl,
  VariableDecl,
  FunctionBodyInfo,
  CEIPattern
} from '../types';

// Try to use solidity-parser, fallback to regex if not available
let parser: any = null;
try {
  parser = require('@solidity-parser/parser');
} catch (e) {
  // Will use fallback parser
}

export interface ParseResult {
  contracts: SolidityContract[];
  errors: string[];
  warnings: string[];
  filesProcessed: number;
}

/**
 * Main entry point for parsing Solidity sources
 */
export async function extractContracts(
  sourcePattern: string,
  options: { includeNodeModules?: boolean; verbose?: boolean } = {}
): Promise<ParseResult> {
  const { includeNodeModules = false, verbose = false } = options;
  
  const files = await resolveSourceFiles(sourcePattern, includeNodeModules);
  
  if (verbose) {
    console.log(`Found ${files.length} Solidity files to parse`);
  }
  
  const contracts: SolidityContract[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  
  for (const file of files) {
    try {
      const result = parseFile(file);
      contracts.push(...result.contracts);
      errors.push(...result.errors);
      warnings.push(...result.warnings);
      
      if (verbose) {
        console.log(`  Parsed ${file}: ${result.contracts.length} contracts found`);
      }
    } catch (error: any) {
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
async function resolveSourceFiles(
  pattern: string,
  includeNodeModules: boolean
): Promise<string[]> {
  // Check if it's a directory
  if (fs.existsSync(pattern) && fs.statSync(pattern).isDirectory()) {
    pattern = path.join(pattern, '**/*.sol');
  }
  
  // Check if it's a single file
  if (fs.existsSync(pattern) && pattern.endsWith('.sol')) {
    return [pattern];
  }
  
  // Use glob for pattern matching
  const files = await glob(pattern, {
    ignore: includeNodeModules ? [] : ['**/node_modules/**', '**/lib/**/*'],
    absolute: true
  });
  
  return files.filter(f => f.endsWith('.sol'));
}

/**
 * Parse a single Solidity file
 */
function parseFile(filePath: string): { contracts: SolidityContract[]; errors: string[]; warnings: string[] } {
  const source = fs.readFileSync(filePath, 'utf-8');
  const contracts: SolidityContract[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  
  if (parser) {
    // Use proper AST parser
    try {
      const ast = parser.parse(source, { loc: true, range: true });
      contracts.push(...extractFromAST(ast, filePath));
    } catch (parseError: any) {
      errors.push(`AST parse error in ${filePath}: ${parseError.message}`);
      // Fallback to regex-based extraction
      contracts.push(...extractWithRegex(source, filePath));
    }
  } else {
    // Use regex-based extraction
    warnings.push(`Using regex parser for ${filePath}. Install @solidity-parser/parser for better results.`);
    contracts.push(...extractWithRegex(source, filePath));
  }
  
  return { contracts, errors, warnings };
}

/**
 * Extract contracts using proper AST parser
 */
function extractFromAST(ast: any, filePath: string): SolidityContract[] {
  const contracts: SolidityContract[] = [];
  
  if (!ast || !ast.children) return contracts;
  
  // Extract imports first
  const imports: string[] = [];
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
function extractContractNode(
  node: any,
  filePath: string,
  imports: string[]
): SolidityContract | null {
  const name = node.name || 'Unknown';
  
  // Extract base contracts
  const inherited: string[] = [];
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
function extractStateVariables(contractNode: any): StateVariable[] {
  const variables: StateVariable[] = [];
  
  if (!contractNode.subNodes) return variables;
  
  let slotCounter = 0;
  
  for (const node of contractNode.subNodes) {
    if (node.type === 'StateVariableDeclaration') {
      for (const varDecl of node.variables) {
        const variable: StateVariable = {
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
        } else if (variable.mutability === 'immutable') {
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
function extractFunctions(contractNode: any, contractName: string): FunctionDef[] {
  const functions: FunctionDef[] = [];
  
  if (!contractNode.subNodes) return functions;
  
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
function extractFunctionNode(node: any, contractName: string): FunctionDef | null {
  const name = node.name || (node.isConstructor ? 'constructor' : 
              node.kind === 'receive' ? 'receive' : 
              node.kind === 'fallback' ? 'fallback' : 'anonymous');
  
  const parameters = extractParameters(node.parameters);
  const returnParameters = extractParameters(node.returnParameters);
  
  // Extract modifiers applied to this function
  const modifiers: string[] = [];
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
    eventsEmitted: [],  // Will be populated during event linking
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
function analyzeFunctionBody(body: any): FunctionBodyInfo {
  const defaultBody: FunctionBodyInfo = {
    statements: 0,
    hasRequire: false,
    hasRevert: false,
    hasExternalCall: false,
    hasLoop: false,
    hasTransfer: false,
    hasDelegateCall: false,
    ceiPattern: 'not-applicable'
  };
  
  if (!body || !body.statements) return defaultBody;
  
  let statements = 0;
  let lastEffectIndex = -1;
  let firstInteractionIndex = -1;
  
  const analyzeStatement = (stmt: any, index: number): void => {
    statements++;
    
    // Check for require/revert
    if (stmt.type === 'ExpressionStatement') {
      const expr = stmt.expression;
      if (expr) {
        if (expr.type === 'FunctionCall') {
          const funcName = getFunctionCallName(expr);
          if (funcName === 'require' || funcName === 'assert') {
            defaultBody.hasRequire = true;
          } else if (funcName === 'revert') {
            defaultBody.hasRevert = true;
          } else if (['call', 'delegatecall', 'staticcall'].includes(funcName)) {
            defaultBody.hasExternalCall = true;
            if (funcName === 'delegatecall') {
              defaultBody.hasDelegateCall = true;
            }
            if (firstInteractionIndex === -1) firstInteractionIndex = index;
          } else if (['transfer', 'send'].includes(funcName)) {
            defaultBody.hasTransfer = true;
            if (firstInteractionIndex === -1) firstInteractionIndex = index;
          } else if (isExternalCall(expr)) {
            defaultBody.hasExternalCall = true;
            if (firstInteractionIndex === -1) firstInteractionIndex = index;
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
        stmt.body.forEach((s: any, i: number) => analyzeStatement(s, i));
      } else {
        analyzeStatement(stmt.body, index);
      }
    }
    if (stmt.trueBody) analyzeStatement(stmt.trueBody, index);
    if (stmt.falseBody) analyzeStatement(stmt.falseBody, index);
    if (stmt.statements) {
      stmt.statements.forEach((s: any, i: number) => analyzeStatement(s, i));
    }
  };
  
  body.statements.forEach((stmt: any, index: number) => analyzeStatement(stmt, index));
  
  defaultBody.statements = statements;
  
  // Determine CEI pattern compliance
  if (defaultBody.hasExternalCall) {
    if (lastEffectIndex === -1 || lastEffectIndex < firstInteractionIndex) {
      defaultBody.ceiPattern = 'valid';  // No effects before interactions
    } else {
      defaultBody.ceiPattern = 'violated';  // Effects before interactions detected
    }
  } else if (statements > 0) {
    defaultBody.ceiPattern = 'not-applicable';  // No external calls to check
  }
  
  return defaultBody;
}

/**
 * Estimate cyclomatic complexity of function
 */
function estimateComplexity(body: any): number {
  let complexity = 1; // Base complexity
  
  if (!body || !body.statements) return complexity;
  
  const countDecisions = (node: any): void => {
    if (!node) return;
    
    switch (node.type) {
      case 'IfStatement':
        complexity++;
        if (node.falseBody) complexity++;
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
          if (v && typeof v === 'object' && v.type) countDecisions(v);
        });
      } else if (value && typeof value === 'object' && value.type) {
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
function extractCallsFromBody(body: any): string[] {
  const calls: string[] = [];
  
  if (!body || !body.statements) return calls;
  
  const extractCalls = (node: any): void => {
    if (!node) return;
    
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
          if (v && typeof v === 'object' && v.type) extractCalls(v);
        });
      } else if (value && typeof value === 'object' && value.type) {
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
function extractStateAccess(body: any): { read: string[]; written: string[] } {
  const read: string[] = [];
  const written: string[] = [];
  
  if (!body || !body.statements) return { read, written };
  
  const extractAccess = (node: any): void => {
    if (!node) return;
    
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
          if (v && typeof v === 'object' && v.type) extractAccess(v);
        });
      } else if (value && typeof value === 'object' && value.type) {
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
function extractEvents(contractNode: any): EventDef[] {
  const events: EventDef[] = [];
  
  if (!contractNode.subNodes) return events;
  
  for (const node of contractNode.subNodes) {
    if (node.type === 'EventDefinition') {
      const parameters = extractParameters(node.parameters);
      events.push({
        name: node.name || 'UnknownEvent',
        parameters,
        anonymous: !!node.isAnonymous,
        emittedBy: [],  // Will be populated later
        lineDeclared: node.loc?.start.line || 0
      });
    }
  }
  
  return events;
}

/**
 * Extract modifiers from contract node
 */
function extractModifiers(contractNode: any): ModifierDef[] {
  const modifiers: ModifierDef[] = [];
  
  if (!contractNode.subNodes) return modifiers;
  
  for (const node of contractNode.subNodes) {
    if (node.type === 'ModifierDefinition') {
      const parameters = extractParameters(node.parameters);
      modifiers.push({
        name: node.name || 'UnknownModifier',
        parameters,
        appliedTo: [],  // Will be populated later
        lineDeclared: node.loc?.start.line || 0
      });
    }
  }
  
  return modifiers;
}

/**
 * Extract structs from contract node
 */
function extractStructs(contractNode: any): StructDef[] {
  const structs: StructDef[] = [];
  
  if (!contractNode.subNodes) return structs;
  
  for (const node of contractNode.subNodes) {
    if (node.type === 'StructDefinition') {
      const members: VariableDecl[] = [];
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
function extractEnums(contractNode: any): EnumDef[] {
  const enums: EnumDef[] = [];
  
  if (!contractNode.subNodes) return enums;
  
  for (const node of contractNode.subNodes) {
    if (node.type === 'EnumDefinition') {
      const members: string[] = [];
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
function extractCustomErrors(contractNode: any): ErrorDef[] {
  const errors: ErrorDef[] = [];
  
  if (!contractNode.subNodes) return errors;
  
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
function extractUsingFor(contractNode: any): UsingForDecl[] {
  const usingFor: UsingForDecl[] = [];
  
  if (!contractNode.subNodes) return usingFor;
  
  for (const node of contractNode.subNodes) {
    if (node.type === 'UsingForDeclaration') {
      const libraries: string[] = [];
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

function extractParameters(paramsNode: any): VariableDecl[] {
  const params: VariableDecl[] = [];
  
  if (!paramsNode || !paramsNode.params) return params;
  
  for (const param of paramsNode.params) {
    params.push({
      name: param.name || null,
      type: typeToString(param.typeName),
      indexed: param.isIndexed || false
    });
  }
  
  return params;
}

function typeToString(typeNode: any): string {
  if (!typeNode) return 'unknown';
  
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

function exprToString(expr: any): string {
  if (!expr) return '';
  
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
      return '(' + (expr.components?.map((c: any) => exprToString(c)).join(',') || '') + ')';
    default:
      return '<expression>';
  }
}

function getFunctionCallName(callNode: any): string {
  if (!callNode || callNode.type !== 'FunctionCall') return '';
  
  const expr = callNode.expression;
  
  if (!expr) return '';
  
  if (expr.type === 'Identifier') {
    return expr.name || '';
  }
  
  if (expr.type === 'MemberAccess') {
    return expr.memberName || '';
  }
  
  return '';
}

function isExternalCall(callNode: any): boolean {
  if (!callNode || callNode.type !== 'FunctionCall') return false;
  
  const expr = callNode.expression;
  if (!expr) return false;
  
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

function isStateChange(expr: any): boolean {
  // Simplified check - would need full dataflow analysis for accuracy
  if (!expr || expr.type !== 'FunctionCall') return false;
  
  const name = getFunctionCallName(expr)?.toLowerCase() || '';
  return ['push', 'pop', 'transfer', 'mint', 'burn', 'approve', 'transferfrom', 
          '_mint', '_burn', '_transfer', 'set', 'add', 'sub', 'mul', 'div'].some(
    n => name.includes(n)
  );
}

function isStateMemberAccess(node: any): boolean {
  // Simplified - would need symbol table for accuracy
  return false; // Placeholder
}

function extractComments(node: any): string | undefined {
  // Comments would need to be extracted from source using location info
  return undefined;
}

// ============================================================
// REGEX FALLBACK PARSER (when @solidity-parser/parser unavailable)
// ============================================================

function extractWithRegex(source: string, filePath: string): SolidityContract[] {
  const contracts: SolidityContract[] = [];
  
  // Extract contract definitions
  const contractRegex = /(abstract\s+)?(contract|interface|library)\s+(\w+)(?:\s+is\s+([\w,\s]+))?/g;
  let match;
  
  while ((match = contractRegex.exec(source)) !== null) {
    const name = match[3];
    const kind = match[2];
    const abstract = match[1] === 'abstract';
    const bases = match[4] ? match[4].split(",").map(function(s) { return s.trim(); }) : [];
    
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

function extractStateVarsRegex(source: string, startIndex: number): StateVariable[] {
  const vars: StateVariable[] = [];
  // Simplified regex extraction
  const varRegex = /(\w+)\s+(public|private|internal|constant|immutable)?\s*(\w[\w\[\]]*)\s*(?:=.*?)?;/g;
  
  // Find the contract body scope and search within it
  // This is a simplified version - real implementation needs scope tracking
  
  return vars;
}

function extractFunctionsRegex(source: string, startIndex: number, contractName: string): FunctionDef[] {
  const funcs: FunctionDef[] = [];
  // Simplified regex extraction
  return funcs;
}

function extractEventsRegex(source: string, startIndex: number): EventDef[] {
  return [];
}

function extractModifiersRegex(source: string, startIndex: number): ModifierDef[] {
  return [];
}

// Functions are already exported above
// export { extractContracts, parseFile, extractFromAST };
