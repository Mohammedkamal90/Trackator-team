/**
 * Trackator Tier 1: Visualizer
 * ============================
 * Generates Mermaid diagrams, ASCII art, and terminal output.
 */

import chalk from 'chalk';
import { ProtocolStructure, ParsedContract, FunctionDef, StateVariable } from '../types/index';

export class Visualizer {
  private structure: ProtocolStructure;

  constructor(structure: ProtocolStructure) {
    this.structure = structure;
  }

  /**
   * Generate complete terminal output (instant ASCII view)
   */
  generateTerminalOutput(verbose = false): string {
    const lines: string[] = [];
    
    // Header
    lines.push(this.generateHeader());
    lines.push('');
    
    // Summary stats
    lines.push(this.generateSummaryStats());
    lines.push('');
    
    // Contract overview
    if (verbose) {
      lines.push(this.generateContractDetails());
      lines.push('');
    }
    
    // State inventory
    lines.push(this.generateStateInventoryASCII());
    lines.push('');
    
    // Function registry
    lines.push(this.generateFunctionRegistryASCII());
    lines.push('');
    
    // Access control
    lines.push(this.generateAccessControlASCII());
    lines.push('');
    
    // Dangerous patterns
    if (this.structure.externalCallMap.dangerousPatterns.length > 0) {
      lines.push(this.generateDangerousPatternsASCII());
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Generate header box
   */
  private generateHeader(): string {
    const name = this.structure.name.toUpperCase();
    const contracts = this.structure.contracts.length;
    const vars = this.structure.stateInventory.totalVariables;
    const funcs = this.structure.functionRegistry.totalFunctions;
    const calls = this.structure.externalCallMap.totalCalls;
    const alerts = this.structure.accessControl.unprotectedFunctions.length;
    
    return `
╭──────────────────────────────────────────────────╮
│  🪨 TRACKATOR  v0.1.0                            │
│                                                   │
│  Protocol: ${this.padRight(name, 34)}│
│  Contracts: ${this.padRight(String(contracts), 30)}│
│  State Vars: ${this.padRight(String(vars), 29)}│
│  Functions: ${this.padRight(String(funcs), 30)}│
│  External Calls: ${this.padRight(String(calls), 25)}│
│  Unprotected Funcs: ${this.padRight(String(alerts), 21)}│
╰──────────────────────────────────────────────────╯`;
  }

  private padRight(str: string, len: number): string {
    return str.length > len ? str.slice(0, len) : str.padEnd(len);
  }

  /**
   * Generate summary statistics
   */
  private generateSummaryStats(): string {
    const valueBearing = this.structure.stateInventory.valueBearing.length;
    const roles = this.structure.accessControl.roles.length;
    const dangerous = this.structure.externalCallMap.dangerousPatterns.length;
    
    let dangerLine = '';
    if (dangerous > 0) {
      dangerLine = `\n│  ⚠️  ${dangerous} dangerous pattern(s) detected        │`;
    }
    
    let alertLine = '';
    if (this.structure.accessControl.unprotectedFunctions.length > 3) {
      alertLine = `\n│  ⚠️  ${this.structure.accessControl.unprotectedFunctions.length} functions lack access control     │`;
    }

    return `┌─ SUMMARY ─────────────────────────────────────┐
│                                                  │
│  Value-bearing variables: ${chalk.green(String(valueBearing).padStart(4))}                 │
│  Access control roles: ${String(roles).padStart(4)}                      │
│  Events defined: ${String(this.structure.eventCatalog.totalEvents).padStart(4)}                          │${dangerLine}${alertLine}
└──────────────────────────────────────────────────┘`;
  }

  /**
   * Generate detailed contract information
   */
  private generateContractDetails(): string {
    const lines: string[] = ['┌─ CONTRACTS ─────────────────────────────────────┐'];
    
    for (const contract of this.structure.contracts) {
      if (contract.kind === 'contract' || contract.kind === 'abstract') {
        const kindIcon = contract.kind === 'abstract' ? '📋' : '📄';
        const stateVars = contract.stateVariables.filter(v => v.isStateVar).length;
        
        lines.push(`│                                                  │`);
        lines.push(`│  ${kindIcon} ${chalk.bold(contract.name)} (${contract.kind})`);
        lines.push(`│     ├─ Functions: ${String(contract.functions.length).padStart(3)}  State vars: ${String(stateVars).padStart(3)}`);
        
        if (contract.inherits.length > 0) {
          lines.push(`│     ├─ Inherits: ${contract.inherits.join(', ')}`);
        }
        
        if (contract.modifiers.length > 0) {
          lines.push(`│     ├─ Modifiers: ${contract.modifiers.map(m => m.name).join(', ')}`);
        }
      }
    }
    
    lines.push('└──────────────────────────────────────────────────┘');
    return lines.join('\n');
  }

  /**
   * Generate state inventory ASCII table
   */
  private generateStateInventoryASCII(): string {
    const lines: string[] = ['┌─ STATE INVENTORY ──────────────────────────────┐'];
    
    for (const [contract, vars] of Array.from(this.structure.stateInventory.byContract.entries())) {
      const stateVars = vars.filter(v => v.isStateVar);
      if (stateVars.length === 0) continue;
      
      lines.push(`│                                                  │`);
      lines.push(`│  ${chalk.bold(contract)}`);
      
      for (const v of stateVars.slice(0, 10)) { // Limit to first 10 per contract
        const isValueBearing = this.structure.stateInventory.valueBearing.includes(v);
        const icon = isValueBearing ? '💰' : '  ';
        const visibility = v.visibility === 'public' ? '👁' : '🔒';
        
        lines.push(`│  ${icon} ${visibility} ${v.name.padEnd(25)} ${v.type.padEnd(20)}`);
      }
      
      if (stateVars.length > 10) {
        lines.push(`│     ... +${stateVars.length - 10} more variables`);
      }
    }
    
    lines.push('└──────────────────────────────────────────────────┘');
    return lines.join('\n');
  }

  /**
   * Generate function registry ASCII
   */
  private generateFunctionRegistryASCII(): string {
    const lines: string[] = ['┌─ FUNCTION REGISTRY ───────────────────────────┐'];
    
    for (const contract of this.structure.contracts) {
      const extFuncs = contract.functions.filter(
        f => f.visibility === 'external' || f.visibility === 'public'
      );
      
      if (extFuncs.length === 0) continue;
      
      lines.push(`│                                                  │`);
      lines.push(`│  ${chalk.bold(contract.name)}`);
      
      for (const func of extFuncs) {
        const mutIcon = this.getMutabilityIcon(func.stateMutability);
        const hasExternalCalls = func.externalCalls.length > 0;
        const callIcon = hasExternalCalls ? '📞' : '  ';
        
        lines.push(`│  ${callIcon} ${mutIcon} ${func.name.padEnd(25)} ${func.stateMutability.padEnd(12)}`);
      }
    }
    
    lines.push('└──────────────────────────────────────────────────┘');
    return lines.join('\n');
  }

  private getMutabilityIcon(mutability: string): string {
    switch (mutability) {
      case 'payable': return '💵';
      case 'view': return '👀';
      case 'pure': return '⚪';
      default: return '✏️';
    }
  }

  /**
   * Generate access control matrix ASCII
   */
  private generateAccessControlASCII(): string {
    const lines: string[] = ['┌─ ACCESS CONTROL MATRIX ───────────────────────┐'];
    
    if (this.structure.accessControl.roles.length === 0) {
      lines.push('│  No explicit access control roles detected         │');
    } else {
      for (const role of this.structure.accessControl.roles) {
        const trustIcon = this.getTrustIcon(role.trustLevel);
        lines.push(`│                                                  │`);
        lines.push(`│  ${trustIcon} ${chalk.bold(role.name)} (${role.trustLevel.toUpperCase()})`);
        lines.push(`│     Functions: ${String(role.functions.length).padStart(3)} | ${role.description.substring(0, 40)}...`);
      }
    }
    
    if (this.structure.accessControl.unprotectedFunctions.length > 0) {
      lines.push(`│                                                  │`);
      lines.push(`│  ⚠️  UNPROTECTED FUNCTIONS:`);
      for (const func of this.structure.accessControl.unprotectedFunctions.slice(0, 5)) {
        lines.push(`│     • ${func}`);
      }
      if (this.structure.accessControl.unprotectedFunctions.length > 5) {
        lines.push(`     ... +${this.structure.accessControl.unprotectedFunctions.length - 5} more`);
      }
    }
    
    lines.push('└──────────────────────────────────────────────────┘');
    return lines.join('\n');
  }

  private getTrustIcon(level: string): string {
    switch (level) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '⚪';
    }
  }

  /**
   * Generate dangerous patterns warning
   */
  private generateDangerousPatternsASCII(): string {
    const lines: string[] = ['┌─ ⚠️  DANGEROUS PATTERDS ───────────────────────┐'];
    
    for (const pattern of this.structure.externalCallMap.dangerousPatterns) {
      const severityIcon = this.getSeverityIcon(pattern.severity);
      lines.push(`│                                                  │`);
      lines.push(`│  ${severityIcon} [${pattern.type.toUpperCase()}] ${pattern.contract}.${pattern.function}:${pattern.line}`);
      lines.push(`│     ${pattern.description}`);
    }
    
    lines.push('└──────────────────────────────────────────────────┘');
    return lines.join('\n');
  }

  private getSeverityIcon(severity: string): string {
    switch (severity) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🔵';
      default: return '⚪';
    }
  }

  // ==================== MERMAID DIAGRAM GENERATION ====================

  /**
   * Generate Mermaid architecture diagram
   */
  generateArchitectureDiagram(): string {
    const nodes: string[] = [];
    const edges: string[] = [];

    // Group contracts by type
    const coreContracts = this.structure.contracts.filter(c => 
      c.kind === 'contract' || c.kind === 'abstract'
    );
    const interfaces = this.structure.contracts.filter(c => c.kind === 'interface');
    const libraries = this.structure.contracts.filter(c => c.kind === 'library');

    // Create subgraphs
    if (coreContracts.length > 0) {
      nodes.push('    subgraph Core');
      for (const c of coreContracts) {
        nodes.push(`        ${this.sanitizeName(c.name)}["${c.name}"]`);
      }
      nodes.push('    end');
    }

    if (interfaces.length > 0) {
      nodes.push('    subgraph Interfaces');
      for (const i of interfaces) {
        nodes.push(`        ${this.sanitizeName(i.name)}["${i.name}"]`);
      }
      nodes.push('    end');
    }

    if (libraries.length > 0) {
      nodes.push('    subgraph Libraries');
      for (const l of libraries) {
        nodes.push(`        ${this.sanitizeName(l.name)}["${l.name}"]`);
      }
      nodes.push('    end');
    }

    // Add inheritance edges
    for (const contract of coreContracts) {
      for (const parent of contract.inherits) {
        edges.push(`    ${this.sanitizeName(parent)} --> ${this.sanitizeName(contract.name)}`);
      }
    }

    // Add call graph edges (external only)
    for (const edge of this.structure.callGraph) {
      if (edge.type === 'external') {
        edges.push(`    ${this.sanitizeName(edge.from)} -->|${edge.function}| ${this.sanitizeName(edge.to)}`);
      }
    }

    return [`graph TB`, ...nodes, ...edges, ''].join('\n');
  }

  /**
   * Generate Mermaid state variable diagram per contract
   */
  generateStateDiagrams(): { contract: string; mermaid: string }[] {
    const diagrams: { contract: string; mermaid: string }[] = [];

    for (const [contract, vars] of Array.from(this.structure.stateInventory.byContract.entries())) {
      const stateVars = vars.filter(v => v.isStateVar);
      if (stateVars.length === 0) continue;

      const lines: string[] = [
        `classDef stateVar fill:#f9f,stroke:#333,stroke-width:1px`,
        `classDef valueVar fill:#ff9,stroke:#333,stroke-width:2px`,
        ''
      ];

      lines.push(`subgraph ${contract}`);

      for (const v of stateVars) {
        const isValueBearing = this.structure.stateInventory.valueBearing.includes(v);
        const className = isValueBearing ? 'valueVar' : 'stateVar';
        lines.push(`    ${this.sanitizeName(v.name)}["${v.name}\\n${v.type}"]:::${className}`);
      }

      lines.push('end');

      diagrams.push({
        contract,
        mermaid: lines.join('\n')
      });
    }

    return diagrams;
  }

  /**
   * Generate Mermaid call graph
   */
  generateCallGraphDiagram(): string {
    const nodes = new Set<string>();
    const edges: string[] = [];

    for (const edge of this.structure.callGraph) {
      const fromNode = `${this.sanitizeName(edge.from)}_${this.sanitizeName(edge.function)}`;
      const toNode = `${this.sanitizeName(edge.to)}_${this.sanitizeName(edge.function)}`;

      nodes.add(`${fromNode}["${edge.from}.${edge.function}()"]`);
      nodes.add(`${toNode}["${edge.to}"]`);

      const style = edge.type === 'delegatecall' ? '.->' :
                    edge.type === 'send' || edge.type === 'transfer' ? '-.->' :
                    '-->';
      const label = edge.type !== 'internal' ? `|${edge.type}|` : '';

      edges.push(`    ${fromNode} ${style} ${toNode} ${label}`);
    }

    return [`graph LR`, ...Array.from(nodes), ...edges, ''].join('\n');
  }

  /**
   * Generate Mermaid flow diagram for user flows (requires breakdown data)
   */
  generateUserFlowDiagram(flowName: string, steps: Array<{actor: string; action: string; target: string}>): string {
    const lines: string[] = [`sequenceDiagram`];

    // Get unique actors
    const actors = new Set(steps.map(s => s.actor));
    for (const actor of Array.from(actors)) {
      lines.push(`    participant ${this.sanitizeName(actor)} as ${actor}`);
    }

    for (const step of steps) {
      lines.push(`    ${this.sanitizeName(step.actor)}->>${this.sanitizeName(step.target)}: ${step.action}`);
    }

    return lines.join('\n');
  }

  /**
   * Generate Mermaid access control diagram
   */
  generateAccessControlDiagram(): string {
    const lines: string[] = [
      `graph TB`,
      `classDef critical fill:#f66,stroke:#333,color:#fff`,
      `classDef high fill:#fa0,stroke:#333,color:#fff`,
      `classDef medium fill:#fd0,stroke:#333`,
      `classDef low fill:#6f6,stroke:#333`,
      ''
    ];

    if (this.structure.accessControl.roles.length === 0) {
      lines.push('    NoRoles["No explicit access control detected"]');
      return lines.join('\n');
    }

    // Role nodes
    for (const role of this.structure.accessControl.roles) {
      lines.push(`    ${this.sanitizeName(role.name)}["${role.name}\\n(${role.functions.length} funcs)"]:::${role.trustLevel}`);
    }

    // Function connections (sample)
    for (const role of this.structure.accessControl.roles) {
      for (const func of role.functions.slice(0, 3)) { // Limit to avoid huge diagrams
        const funcShort = func.split('.').pop() || func;
        lines.push(`    ${this.sanitizeName(role.name)} --> ${this.sanitizeName(funcShort)}["${funcShort}"]`);
      }
      if (role.functions.length > 3) {
        lines.push(`    ${this.sanitizeName(role.name)} --> More${this.sanitizeName(role.name)}["+${role.functions.length - 3} more..."]`);
      }
    }

    return lines.join('\n');
  }

  /**
   * Generate Mermaid money flow diagram
   */
  generateMoneyFlowDiagram(flows: Array<{
    type: string;
    source: string;
    destination: string;
    asset: string;
  }>): string {
    const lines: string[] = [
      `flowchart LR`,
      `classDef inflow fill:#4CAF50,color:#fff`,
      `classDef outflow fill:#f44336,color:#fff`,
      `classDef internal fill:#FF9800,color:#fff`,
      `classDef fee fill:#9C27B0,color:#fff`,
      ''
    ];

    // Group by type
    const inflows = flows.filter(f => f.type === 'inflow');
    const outflows = flows.filter(f => f.type === 'outflow');
    const internals = flows.filter(f => f.type === 'internal');
    const fees = flows.filter(f => f.type === 'fee');

    if (inflows.length > 0) {
      lines.push('    subgraph Inflows');
      for (const f of inflows) {
        lines.push(`        ${this.sanitizeName(f.source)}["${f.source}"]:::inflow -->|${f.asset}| Pool[(Pool Vault)]`);
      }
      lines.push('    end');
    }

    if (internals.length > 0) {
      lines.push('    subgraph Internal Movements');
      for (const f of internals) {
        lines.push(`        Pool -->|${f.asset}| ${this.sanitizeName(f.destination)}["${f.destination}"]:::internal`);
      }
      lines.push('    end');
    }

    if (fees.length > 0) {
      lines.push('    subgraph Fees');
      for (const f of fees) {
        lines.push(`        Pool -->|${f.asset}| ${this.sanitizeName(f.destination)}["${f.destination}"]:::fee`);
      }
      lines.push('    end');
    }

    if (outflows.length > 0) {
      lines.push('    subgraph Outflows');
      for (const f of outflows) {
        lines.push(`        Pool -->|${f.asset}| ${this.sanitizeName(f.destination)}["${f.destination}"]:::outflow`);
      }
      lines.push('    end');
    }

    return lines.join('\n');
  }

  /**
   * Sanitize name for Mermaid compatibility
   */
  private sanitizeName(name: string): string {
    return name
      .replace(/[^a-zA-Z0-9_]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '')
      .substring(0, 30); // Limit length
  }
}

export default Visualizer;
