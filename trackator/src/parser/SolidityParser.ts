/**
 * Trackator Tier 1: Solidity AST Parser
 * ======================================
 * Parses .sol files and extracts complete protocol structure.
 * No AI required - pure static analysis.
 */

import { parse } from '@solidity-parser/parser';
import { 
  ParsedContract, 
  StateVariable, 
  FunctionDef, 
  ModifierDef, 
  EventDef, 
  Parameter,
  UsingForDef,
  ErrorDef,
  ProtocolStructure,
  CallGraphNode,
  StateInventory,
  FunctionRegistry,
  ModifierMap,
  EventCatalog,
  AccessControlMatrix,
  RoleDefinition,
  ExternalCallSummary,
  DangerousPattern
} from '../types';

// Local type for external calls used during parsing (simplified version)
interface ExternalCall {
  functionName: string;
  contractName: string;
  arguments: any[];
  line: number;
  isSendOrTransfer: boolean;
  isDelegateCall: boolean;
  isStaticCall: boolean;
}
import * as fs from 'fs';
import * as path from 'path';

export class SolidityParser {
  private contracts: Map<string, ParsedContract> = new Map();
  private rootPath: string;
  
  constructor(rootPath: string) {
    this.rootPath = path.resolve(rootPath);
  }

  /**
   * Main entry point - parses entire codebase
   */
  async parseCodebase(): Promise<ProtocolStructure> {
    const solFiles = this.findSolidityFiles(this.rootPath);
    
    console.log(`🔍 Found ${solFiles.length} Solidity files`);
    
    for (const file of solFiles) {
      try {
        this.parseFile(file);
      } catch (error) {
        console.warn(`⚠️  Failed to parse ${file}:`, error instanceof Error ? error.message : error);
      }
    }

    return this.buildProtocolStructure();
  }

  /**
   * Find all .sol files in directory
   */
  private findSolidityFiles(dir: string): string[] {
    const files: string[] = [];
    
    const traverse = (currentPath: string) => {
      if (!fs.existsSync(currentPath)) return;
      
      const entries = fs.readdirSync(currentPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(currentPath, entry.name);
        
        // Skip node_modules, lib (unless it's own code), artifacts
        if (entry.isDirectory()) {
          if (['node_modules', 'artifacts', 'cache', 'lib'].includes(entry.name)) {
            continue;
          }
          traverse(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.sol')) {
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
  private parseFile(filePath: string): void {
    const content = fs.readFileSync(filePath, 'utf-8');
    
    try {
      const ast = parse(content, { loc: true, range: true });
      
      // Extract all top-level contract/interface/library definitions
      if (ast.children) {
        for (const child of ast.children) {
          const childType = (child as any).type;
          if (
            childType === 'ContractDefinition' ||
            childType === 'InterfaceDefinition' ||
            childType === 'LibraryDefinition'
          ) {
            const contract = this.extractContract(child as any, filePath);
            this.contracts.set(`${contract.name}:${filePath}`, contract);
          }
        }
      }
    } catch (parseError) {
      throw new Error(`Parse error in ${filePath}: ${parseError}`);
    }
  }

  /**
   * Extract complete contract information from AST node
   */
  private extractContract(node: any, filePath: string): ParsedContract {
    const kind = this.getContractKind(node);
    
    const contract: ParsedContract = {
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
    } as ParsedContract;

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
      (func as any).externalCalls = this.findExternalCalls((func as any).body);
    }

    return contract;
  }

  private getContractKind(node: any): ParsedContract['kind'] {
    if (node.kind === 'interface') return 'interface';
    if (node.kind === 'library') return 'library';
    if (node.abstract) return 'abstract';
    return 'contract';
  }

  private extractInheritance(node: any): string[] {
    return (node.baseContracts || []).map((bc: any) => bc.baseName.name);
  }

  /**
   * Extract state variables from declaration
   */
  private extractStateVariables(node: any): StateVariable[] {
    const variables: StateVariable[] = [];
    
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
      } as StateVariable);
    }
    
    return variables;
  }

  /**
   * Extract function definition
   */
  private extractFunction(node: any): FunctionDef {
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
      modifiers: (node.modifiers || []).map((m: any) => m.name),
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
    } as FunctionDef;
  }

  /**
   * Extract modifier definition
   */
  private extractModifier(node: any): ModifierDef {
    return {
      name: node.name || 'unknown',
      parameters: this.extractParameters(node.parameters),
      visibility: node.visibility || 'internal',
      appliedTo: [],
      lineDeclared: node.loc?.start?.line || 0
    } as ModifierDef;
  }

  /**
   * Extract event definition
   */
  private extractEvent(node: any): EventDef {
    return {
      name: node.name || 'unknown',
      parameters: this.extractParameters(node.parameters, true),
      anonymous: node.anonymous || false,
      emittedBy: [],
      lineDeclared: node.loc?.start?.line || 0
    } as EventDef;
  }

  private extractUsingFor(node: any): UsingForDef {
    return {
      type: node.typeName ? this.getTypeString(node.typeName) : '*',
      library: node.libraryNames || [node.libraryName || ''].filter(Boolean)
    } as UsingForDef;
  }

  private extractError(node: any): ErrorDef {
    return {
      name: node.name || 'unknown',
      parameters: this.extractParameters(node.parameters)
    };
  }

  /**
   * Extract parameters from function/event definition
   */
  private extractParameters(paramsNode: any | null, includeIndexed = false): Parameter[] {
    const params: Parameter[] = [];
    
    if (!paramsNode || !paramsNode.params) return params;
    
    for (const param of paramsNode.params) {
      params.push({
        name: param.name || null,
        type: this.getTypeString(param.typeName),
        indexed: includeIndexed ? param.indexed || false : undefined
      } as Parameter);
    }
    
    return params;
  }

  /**
   * Convert type AST node to string representation
   */
  private getTypeString(typeName: any): string {
    if (!typeName) return 'undefined';
    
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
  private findExternalCalls(body: any): ExternalCall[] {
    const calls: ExternalCall[] = [];
    
    if (!body) return calls;
    
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

  private analyzeExternalCall(node: any): ExternalCall | null {
    // Check for external call patterns
    let functionName = '';
    let contractName = '';
    
    if (node.expression?.type === 'MemberAccess') {
      functionName = node.expression.memberName || '';
      contractName = this.getTargetContract(node.expression.object);
    } else if (node.expression?.type === 'Identifier') {
      functionName = node.expression.name || '';
      contractName = 'this'; // Internal or inherited
    }
    
    // Skip if no meaningful target
    if (!functionName && !contractName) return null;
    
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

  private getTargetContract(object: any): string {
    if (!object) return 'unknown';
    
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
  private traverseAST(node: any, visitor: (node: any) => void): void {
    if (!node || typeof node !== 'object') return;
    
    visitor(node);
    
    // Recurse into children
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range') continue; // Skip metadata
      
      const value = node[key];
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item && typeof item === 'object') {
            this.traverseAST(item, visitor);
          }
        }
      } else if (value && typeof value === 'object') {
        this.traverseAST(value, visitor);
      }
    }
  }

  private extractDefaultValue(expression: any): any {
    if (!expression) return undefined;
    
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
  private buildProtocolStructure(): ProtocolStructure {
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
      externalCallMap: this.buildExternalCallSummary() as any
    } as unknown as ProtocolStructure;
  }

  private extractProtocolName(): string {
    // Try to get name from package.json or foundry.toml
    try {
      const pkgPath = path.join(this.rootPath, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        return pkg.name || path.basename(this.rootPath);
      }
    } catch {}
    
    try {
      const foundryPath = path.join(this.rootPath, 'foundry.toml');
      if (fs.existsSync(foundryPath)) {
        const content = fs.readFileSync(foundryPath, 'utf-8');
        const match = content.match(/\s*=\s*["']([^"']+)["']/);
        if (match) return match[1];
      }
    } catch {}
    
    return path.basename(this.rootPath);
  }

  private buildInheritanceMap(): Map<string, string[]> {
    const map = new Map<string, string[]>();
    
    for (const contract of Array.from(this.contracts.values())) {
      if (contract.inherits.length > 0) {
        map.set(contract.name, contract.inherits);
      }
    }
    
    return map;
  }

  private buildImportGraph(): Map<string, string[]> {
    const map = new Map<string, string[]>();
    
    // Simplified import tracking - would need preprocessor for full accuracy
    for (const [key, contract] of Array.from(this.contracts.entries())) {
      // Look for imports in file
      try {
        const content = fs.readFileSync(contract.sourcePath, 'utf-8');
        const imports: string[] = [];
        const importRegex = /import\s+[^;]+;/g;
        let match;
        while ((match = importRegex.exec(content)) !== null) {
          imports.push(match[0].trim());
        }
        if (imports.length > 0) {
          map.set(contract.name, imports);
        }
      } catch {}
    }
    
    return map;
  }

  private buildCallGraph(): CallGraphNode[] {
    const nodes: CallGraphNode[] = [];
    
    for (const contract of Array.from(this.contracts.values())) {
      for (const func of contract.functions) {
        const externalCalls = (func.externalCalls || []) as any[];
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
              type: callType as any
            }],
            calledBy: [],
            visibility: func.visibility,
            isExternal: callType === 'external',
            isEntry: func.visibility === 'external' || func.visibility === 'public'
          } as CallGraphNode);
        }
      }
    }
    
    return nodes;
  }

  private hasInheritanceRelation(child: string, parent: string): boolean {
    const childContract = Array.from(this.contracts.values()).find(c => c.name === child);
    if (!childContract) return false;
    const inherits = childContract.inherits || childContract.inherited || [];
    return inherits.includes(parent);
  }

  private buildStateInventory(): StateInventory {
    const variables: any[] = [];
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
          encoding: 'single' as const
        });

        // Advance slot (simplified - doesn't handle packing)
        currentSlot += this.estimateSlotsForType(v.type);
      }
    }

    totalSlotsUsed = currentSlot;

    return {
      contractName: this.extractProtocolName(),
      variables: variables as any,
      totalSlotsUsed,
      totalVariables: variables.length,
      valueBearing: variables.filter((vi: any) => this.isValueBearingVariable(vi.variable)).length
    } as StateInventory;
  }

  private estimateSlotsForType(typeStr: string): number {
    // Very simplified slot estimation
    if (typeStr.includes('mapping')) return 32; // Mappings use many slots
    if (typeStr.includes('struct')) return 1; // Depends on struct size
    if (typeStr.includes('string') || typeStr.includes('bytes')) return 1;
    if (typeStr.includes('int256') || typeStr.includes('uint256') || typeStr.includes('address') || typeStr.includes('bytes32')) return 1;
    return 1; // Default
  }

  private isValueBearingVariable(v: StateVariable): boolean {
    const nameLower = v.name.toLowerCase();
    const typeLower = v.type.toLowerCase();
    
    // Heuristics for value-bearing variables
    const valuePatterns = [
      'balance', 'total', 'supply', 'reserve', 'collateral', 'debt',
      'borrow', 'deposit', 'withdraw', 'amount', 'value', 'asset',
      'liability', 'share', 'token', 'fund', 'treasury', 'vault',
      'staked', 'locked', 'reward', 'fee', 'interest', 'principal'
    ];
    
    return valuePatterns.some(p => 
      nameLower.includes(p) || typeLower.includes(p)
    );
  }

  private buildFunctionRegistry(): FunctionRegistry {
    const entries: any[] = [];
    const byContract = new Map<string, any[]>();
    const byCategory = new Map<string, any[]>();

    for (const contract of Array.from(this.contracts.values())) {
      const registeredFuncs: any[] = [];
      
      for (const func of contract.functions) {
        const entry = {
          id: `${contract.name}.${func.name}`,
          contract: contract.name,
          signature: `${func.name}(${func.parameters.map((p: any) => p.type).join(',')})`,
          name: func.name,
          function: func.name,
          category: 'core-logic' as const,
          accessControl: {
            level: (func.visibility === 'public' || func.visibility === 'external') ? 'public' : 'internal',
            rolesRequired: [],
            modifiers: func.modifiers,
            ownerOnly: func.modifiers.some((m: string) => m.includes('Owner')),
            length: func.modifiers.length
          },
          risk: { score: 50, overall: 'medium' as const, factors: [] },
          stateReads: func.stateVariablesRead || [],
          stateWrites: func.stateVariablesWritten || [],
          externalCalls: (func.externalCalls || []).map((c: any) => c.functionName || c.function || ''),
          lineDeclared: func.lineStart
        };
        entries.push(entry);
        registeredFuncs.push(entry);
      }
      
      byContract.set(contract.name, registeredFuncs);
      byCategory.set('all', [...(byCategory.get('all') || []), ...registeredFuncs]);
    }

    const externalFunctions = entries.filter((e: any) => {
      for (const c of Array.from(this.contracts.values())) {
        const found = c.functions.find((f: FunctionDef) => f.name === e.name);
        if (found && (found.visibility === 'external' || found.visibility === 'public')) {
          return true;
        }
      }
      return false;
    });

    return {
      entries,
      totalFunctions: entries.length,
      byContract: byContract as any,
      byCategory: byCategory as any
    } as FunctionRegistry;
  }

  private buildModifierMap(): ModifierMap {
    const result: any = {};

    for (const contract of Array.from(this.contracts.values())) {
      // Collect definitions and applications
      for (const mod of contract.modifiers) {
        if (!result[mod.name]) {
          result[mod.name] = {
            appliedTo: [],
            parameters: (mod.parameters || []).map((p: any) => p.type),
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

    return result as ModifierMap;
  }

  private buildEventCatalog(): EventCatalog {
    const result: any = {};

    for (const contract of Array.from(this.contracts.values())) {
      for (const event of contract.events) {
        result[event.name] = {
          ...event,
          emittedByFunctions: event.emittedBy || []
        };
      }
    }

    return result as EventCatalog;
  }

  private buildAccessControlMatrix(): AccessControlMatrix {
    const result: any = {};
    const roleToFunctions = new Map<string, string[]>();
    const unprotectedFunctions: string[] = [];

    // Common access control patterns
    const acPatterns = [
      { regex: /onlyOwner|onlyRole\(_?owner\)|msg\.sender\s*==\s*owner/i, role: 'Owner', trustLevel: 'critical' as const },
      { regex: /onlyAdmin|isAdmin|hasRole\(ADMIN\)/i, role: 'Admin', trustLevel: 'high' as const },
      { regex: /onlyGuardian|isGuardian|hasRole\(GUARDIAN\)/i, role: 'Guardian', trustLevel: 'high' as const },
      { regex: /onlyManager|isManager|hasRole\(MANAGER\)/i, role: 'Manager', trustLevel: 'medium' as const },
      { regex: /onlyOperator|isOperator|hasRole\(OPERATOR\)/i, role: 'Operator', trustLevel: 'medium' as const },
      { regex: /onlyPauser|isPauser/i, role: 'Pauser', trustLevel: 'medium' as const },
      { regex: /whenNotPaused|whenPaused/i, role: 'PauseGuard', trustLevel: 'low' as const },
      { regex: /nonReentrant|ReentrancyGuard/i, role: 'ReentrancyGuard', trustLevel: 'low' as const }
    ];

    for (const contract of Array.from(this.contracts.values())) {
      for (const func of contract.functions) {
        const fullFuncName = `${contract.name}.${func.name}`;
        const appliedRoles: string[] = [];
        let hasAnyProtection = false;

        for (const pattern of acPatterns) {
          if (func.modifiers.some(m => pattern.regex.test(m))) {
            appliedRoles.push(pattern.role);
            hasAnyProtection = true;

            if (!roleToFunctions.has(pattern.role)) {
              roleToFunctions.set(pattern.role, []);
            }
            roleToFunctions.get(pattern.role)!.push(fullFuncName);
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

    return result as AccessControlMatrix;
  }

  private generateRoleDescription(role: string): string {
    const descriptions: Record<string, string> = {
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

  private buildExternalCallSummary(): ExternalCallSummary {
    const byTarget = new Map<string, ExternalCall[]>();
    const bySource = new Map<string, ExternalCall[]>();
    const dangerousPatterns: DangerousPattern[] = [];
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
          byTarget.get(call.contractName)!.push({ ...call, contractName: contract.name } as any);

          // By source
          if (!bySource.has(fullFuncName)) {
            bySource.set(fullFuncName, []);
          }
          bySource.get(fullFuncName)!.push(call as any);

          // Check for dangerous patterns
          const danger = this.detectDangerousPattern(contract.name, func.name, call as any);
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
      byTarget: byTarget as any,
      bySource: bySource as any,
      dangerousPatterns: dangerousPatterns as any
    } as ExternalCallSummary;
  }

  private detectDangerousPattern(
    contract: string, 
    func: string, 
    call: ExternalCall
  ): DangerousPattern | null {
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
      } as DangerousPattern;
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
      } as DangerousPattern;
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
      } as DangerousPattern;
    }

    return null;
  }

  /**
   * Get parsed contracts (for testing/debugging)
   */
  getParsedContracts(): ParsedContract[] {
    return Array.from(this.contracts.values());
  }
}

export default SolidityParser;
