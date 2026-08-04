// ============================================================
// TRACKATOR Tier 1 - Call Graph Generator
// Builds complete call graph of internal/external function calls
// ============================================================

import {
  SolidityContract,
  FunctionDef,
  CallGraphNode,
  CallEdge,
  ValueFlowInfo,
  TokenTransferInfo
} from '../types';

export interface CallGraph {
  nodes: Map<string, CallGraphNode>;  // key: "Contract.function"
  edges: CallEdge[];
  entryPoints: string[];              // External-facing functions
  cycles: CycleInfo[];                // Detected recursive calls
  depthMap: Map<string, number>;      // Max call depth from each node
}

export interface CycleInfo {
  path: string[];
  type: 'direct-recursion' | 'indirect-recursion' | 'mutual-recursion';
  risk: 'high' | 'medium' | 'low';
}

/**
 * Build complete call graph from parsed contracts
 */
export function buildCallGraph(contracts: SolidityContract[]): CallGraph {
  const nodes = new Map<string, CallGraphNode>();
  const edges: CallEdge[] = [];
  
  // Create nodes for all functions
  for (const contract of contracts) {
    for (const func of contract.functions) {
      const key = `${contract.name}.${func.name}`;
      const isExternal = func.visibility === 'external' || 
                        func.visibility === 'public';
      const isEntry = isExternal && 
                     func.stateMutability !== 'view' && 
                     func.stateMutability !== 'pure' &&
                     !['constructor', 'fallback', 'receive'].includes(func.kind);
      
      nodes.set(key, {
        contract: contract.name,
        function: func.name,
        calls: [],
        calledBy: [],
        visibility: func.visibility,
        isExternal,
        isEntry
      });
    }
  }
  
  // Build edges by analyzing function bodies and calls
  for (const contract of contracts) {
    for (const func of contract.functions) {
      const fromKey = `${contract.name}.${func.name}`;
      const fromNode = nodes.get(fromKey);
      
      if (!fromNode) continue;
      
      // Process each call this function makes
      for (const calledFuncName of func.calls) {
        const edge = resolveCallEdge(
          contract.name,
          func.name,
          calledFuncName,
          contracts,
          func
        );
        
        if (edge) {
          edges.push(edge);
          fromNode.calls.push(edge);
          
          // Update callee's calledBy
          const toKey = `${edge.to.contract}.${edge.to.function}`;
          const toNode = nodes.get(toKey);
          if (toNode) {
            toNode.calledBy.push(edge);
          }
        }
      }
      
      // Check for super() calls in inherited contracts
      if (contract.inherited.length > 0) {
        for (const baseName of contract.inherited) {
          // Look for super.functionName() patterns
          const superCalls = func.calls.filter(c => c.startsWith('super.'));
          for (const superCall of superCalls) {
            const baseFunc = superCall.replace('super.', '');
            const toKey = `${baseName}.${baseFunc}`;
            
            if (nodes.has(toKey)) {
              const edge: CallEdge = {
                from: { contract: contract.name, function: func.name },
                to: { contract: baseName, function: baseFunc },
                type: 'internal',
                condition: 'via super'
              };
              edges.push(edge);
              fromNode.calls.push(edge);
              
              const toNode = nodes.get(toKey);
              if (toNode) {
                toNode.calledBy.push(edge);
              }
            }
          }
        }
      }
      
      // Analyze external/interface calls (e.g., IERC20(token).transferFrom())
      analyzeExternalInterfaceCalls(contract, func, edges, nodes);
    }
  }
  
  // Find entry points
  const entryPoints: string[] = [];
  for (const [key, node] of nodes) {
    if (node.isEntry) {
      entryPoints.push(key);
    }
  }
  
  // Detect cycles
  const cycles = detectCycles(nodes, edges);
  
  // Compute max depths
  const depthMap = computeDepths(nodes);
  
  return { nodes, edges, entryPoints, cycles, depthMap };
}

/**
 * Resolve a function call to its target
 */
function resolveCallEdge(
  fromContract: string,
  fromFunction: string,
  calledName: string,
  contracts: SolidityContract[],
  callerFunc: FunctionDef
): CallEdge | null {
  // Internal call (this.function or just function)
  let targetType: CallEdge['type'] = 'internal';
  let toContract = fromContract;
  let toFunction = calledName;
  
  // Check if it's an external call pattern
  // e.g., externalContract.doSomething()
  const dotIndex = calledName.lastIndexOf('.');
  if (dotIndex > 0) {
    const potentialContract = calledName.substring(0, dotIndex);
    const potentialFunction = calledName.substring(dotIndex + 1);
    
    // Check if potentialContract is a known contract/interface
    const isExternalContract = contracts.some(c => 
      c.name === potentialContract || 
      c.stateVariables.some(v => v.type === potentialContract)
    );
    
    if (isExternalContract) {
      targetType = 'external';
      toContract = potentialContract;
      toFunction = potentialFunction;
    } else {
      // Might be a state variable used as contract reference
      // Keep as-is but mark as potential external
      targetType = 'external';
      toFunction = calledName;
    }
  }
  
  // Determine value flow
  let valueFlow: ValueFlowInfo | undefined;
  if (callerFunc.body.hasTransfer || callerFunc.body.hasExternalCall) {
    valueFlow = analyzeValueFlow(callerFunc, calledName);
  }
  
  return {
    from: { contract: fromContract, function: fromFunction },
    to: { contract: toContract, function: toFunction },
    type: targetType,
    valueFlow,
    condition: undefined
  };
}

/**
 * Analyze value flow through a call
 */
function analyzeValueFlow(callerFunc: FunctionDef, calledName: string): ValueFlowInfo | undefined {
  const name = callerFunc.name.toLowerCase();
  
  // Detect ETH transfers
  const ethSent = callerFunc.body.hasTransfer;
  
  // Detect token transfers based on common patterns
  const tokenTransfers: TokenTransferInfo[] = [];
  
  if (['transfer', 'transferfrom', 'mint', 'burn', '_mint', '_burn'].some(p => calledName.toLowerCase().includes(p))) {
    tokenTransfers.push({
      token: 'unknown',  // Would need deeper analysis
      direction: calledName.toLowerCase().includes('burn') ? 'burn' :
                 calledName.toLowerCase().includes('mint') ? 'mint' : 'send',
      amountExpr: 'unknown'
    });
  }
  
  return {
    ethSent,
    tokenTransfers,
    amountSource: ethSent ? 'msg.value' : 'unknown'
  };
}

/**
 * Analyze external interface calls (e.g., IERC20(token).transferFrom)
 */
function analyzeExternalInterfaceCalls(
  contract: SolidityContract,
  func: FunctionDef,
  edges: CallEdge[],
  nodes: Map<string, CallGraphNode>
): void {
  // This would require deeper AST analysis to find:
  // - Interface calls on state variables
  // - Address-typed parameters used for calls
  // - Low-level .call() invocations
  
  // Simplified version - look for common patterns in call names
  for (const call of func.calls) {
    // Low-level calls
    if (['call', 'delegatecall', 'staticcall'].includes(call.toLowerCase())) {
      const edge: CallEdge = {
        from: { contract: contract.name, function: func.name },
        to: { contract: 'external', function: call },
        type: call.toLowerCase() === 'delegatecall' ? 'delegatecall' : 
             call.toLowerCase() === 'staticcall' ? 'staticcall' : 'external'
      };
      edges.push(edge);
      
      const fromKey = `${contract.name}.${func.name}`;
      const fromNode = nodes.get(fromKey);
      if (fromNode) {
        fromNode.calls.push(edge);
      }
    }
  }
}

/**
 * Detect recursive calls (cycles in call graph)
 */
function detectCycles(
  nodes: Map<string, CallGraphNode>,
  edges: CallEdge[]
): CycleInfo[] {
  const cycles: CycleInfo[] = [];
  const visited = new Set<string>();
  const recursionStack = new Set<string>();
  
  const dfs = (nodeKey: string, path: string[]): void => {
    visited.add(nodeKey);
    recursionStack.add(nodeKey);
    
    const node = nodes.get(nodeKey);
    if (!node) return;
    
    for (const edge of node.calls) {
      const targetKey = `${edge.to.contract}.${edge.to.function}`;
      
      if (!visited.has(targetKey)) {
        dfs(targetKey, [...path, targetKey]);
      } else if (recursionStack.has(targetKey)) {
        // Found cycle
        const cycleStart = path.indexOf(targetKey);
        const cyclePath = cycleStart >= 0 ? [...path.slice(cycleStart), targetKey] : [targetKey, targetKey];
        
        let type: CycleInfo['type'];
        let risk: CycleInfo['risk'];
        
        if (cyclePath.length === 2 && cyclePath[0] === cyclePath[1]) {
          type = 'direct-recursion';
          risk = 'high';  // Direct recursion is usually intentional but risky
        } else if (cyclePath.length <= 4) {
          type = 'mutual-recursion';
          risk = 'medium';
        } else {
          type = 'indirect-recursion';
          risk = 'low';  // Long indirect cycles are often legitimate
        }
        
        cycles.push({ path: cyclePath, type, risk });
      }
    }
    
    recursionStack.delete(nodeKey);
  };
  
  // Start DFS from each unvisited node
  for (const [key] of nodes) {
    if (!visited.has(key)) {
      dfs(key, [key]);
    }
  }
  
  return cycles;
}

/**
 * Compute maximum call depth from each node
 */
function computeDepths(nodes: Map<string, CallGraphNode>): Map<string, number> {
  const depths = new Map<string, number>();
  
  const computeDepth = (nodeKey: string, visiting: Set<string>): number => {
    if (depths.has(nodeKey)) {
      return depths.get(nodeKey)!;
    }
    
    if (visiting.has(nodeKey)) {
      return 100; // Cycle detected - cap depth
    }
    
    const node = nodes.get(nodeKey);
    if (!node || node.calls.length === 0) {
      depths.set(nodeKey, 0);
      return 0;
    }
    
    visiting.add(nodeKey);
    let maxChildDepth = 0;
    
    for (const edge of node.calls) {
      const childKey = `${edge.to.contract}.${edge.to.function}`;
      const childDepth = computeDepth(childKey, new Set(visiting));
      maxChildDepth = Math.max(maxChildDepth, childDepth + 1);
    }
    
    visiting.delete(nodeKey);
    depths.set(nodeKey, maxChildDepth);
    return maxChildDepth;
  };
  
  for (const [key] of nodes) {
    if (!depths.has(key)) {
      computeDepth(key, new Set());
    }
  }
  
  return depths;
}

// ============================================================
// MERMAID DIAGRAM GENERATION
// ============================================================

/**
 * Generate Mermaid diagram code for call graph
 */
export function generateMermaidCallGraph(graph: CallGraph): string {
  const lines: string[] = ['graph TD'];
  
  // Add nodes with styling
  for (const [key, node] of graph.nodes) {
    const label = escapeMermaid(`${node.function}\\n(${node.contract})`);
    const shape = node.isEntry ? "[(" + label + ")]" : '("' + label + '")';
    lines.push(`  ${key}${shape}`);
  }
  
  // Add edges with labels
  for (const edge of graph.edges) {
    const fromKey = `${edge.from.contract}.${edge.from.function}`;
    const toKey = `${edge.to.contract}.${edge.to.function}`;
    
    let style = '-->';
    let label = '';
    
    switch (edge.type) {
      case 'external':
        style = '-.->';
        label = 'external';
        break;
      case 'delegatecall':
        style = '-=>';
        label = 'delegate';
        break;
      case 'value-transfer':
        style = '-->';
        label = '$$$';
        break;
      default:
        if (edge.valueFlow?.ethSent) {
          style = '-->';
          label = 'ETH';
        }
    }
    
    lines.push(`  "${fromKey}" ${style} "${toKey}"${label ? `|${label}|` : ''}`);
  }
  
  // Add subgraphs for contracts
  const contractGroups = groupNodesByContract(graph.nodes);
  for (const [contract, keys] of contractGroups) {
    lines.push(`  subgraph ${escapeMermaid(contract)}`);
    for (const key of keys) {
      lines.push(`    "${key}"`);
    }
    lines.push(`  end`);
  }
  
  // Style entry points
  lines.push('');
  lines.push('  %% Style entry points');
  for (const ep of graph.entryPoints) {
    lines.push(`  style "${ep}" fill:#f9d71c,stroke:#333,stroke-width:2px`);
  }
  
  // Style high-depth nodes
  for (const [key, depth] of graph.depthMap) {
    if (depth > 5) {
      lines.push(`  style "${key}" fill:#ff6b6b,stroke:#333,stroke-width:2px`);
    }
  }
  
  return lines.join('\n');
}

/**
 * Generate Mermaid sequence diagram for a specific execution path
 */
export function generateSequenceDiagram(
  graph: CallGraph,
  startNode: string,
  maxDepth: number = 5
): string {
  const lines: string[] = ['sequenceDiagram'];
  const participants = new Set<string>();
  const visited = new Set<string>();
  
  const addCalls = (nodeKey: string, depth: number): void => {
    if (depth > maxDepth || visited.has(nodeKey)) return;
    visited.add(nodeKey);
    
    const node = graph.nodes.get(nodeKey);
    if (!node) return;
    
    participants.add(node.contract);
    
    for (const edge of node.calls) {
      const targetNode = graph.nodes.get(`${edge.to.contract}.${edge.to.function}`);
      if (!targetNode) continue;
      
      participants.add(edge.to.contract);
      
      const actor = node.contract === edge.to.contract ? 
        `Note over ${node.contract}` : '';
      
      lines.push(`  ${actor}->>${edge.to.contract}: ${edge.to.function}${edge.type === 'external' ? ' [EXTERNAL]' : ''}${edge.valueFlow?.ethSent ? ' [$]' : ''}`);
      
      // Add return
      if (targetNode.visibility !== 'external') {
        lines.push(`  ${edge.to.contract}-->>${node.contract}: return`);
      }
      
      addCalls(`${edge.to.contract}.${edge.to.function}`, depth + 1);
    }
  };
  
  // Add participants
  for (const p of participants) {
    lines.push(`  participant ${p}`);
  }
  
  lines.push('');
  
  // Start traversal
  addCalls(startNode, 0);
  
  return lines.join('\n');
}

/**
 * Generate Mermaid class diagram showing contract structure
 */
export function generateClassDiagram(contracts: SolidityContract[]): string {
  const lines: string[] = ['classDiagram'];
  
  for (const contract of contracts) {
    // Class declaration with inheritance
    let classLine = `class ${contract.name}`;
    if (contract.inherited.length > 0) {
      classLine += ` <|-- ${contract.inherited.join(' & ')}`;
    }
    if (contract.abstract) {
      classLine += ' <<abstract>>';
    }
    lines.push(classLine);
    
    // State variables
    for (const sv of contract.stateVariables) {
      const visibility = sv.visibility === 'constant' || sv.visibility === 'immutable' ?
        `$${sv.visibility}$` : sv.visibility.charAt(0).toUpperCase();
      lines.push(`  ${contract.name}+${visibility} ${sv.name} : ${sv.type}`);
    }
    
    // Functions
    for (const func of contract.functions) {
      const visibility = func.visibility.charAt(0).toUpperCase();
      const mutability = func.stateMutability !== 'nonpayable' ? ` <<${func.stateMutability}>>` : '';
      const params = func.parameters.map(p => p.type).join(', ');
      const returns = func.returnParameters.length > 0 ? 
        ` ${func.returnParameters.map(p => p.type).join(', ')}` : '';
      lines.push(`  ${contract.name}${visibility}${func.name}(${params})${returns}${mutability}`);
    }
    
    // Events
    for (const event of contract.events) {
      const params = event.parameters.map(p => 
        p.indexed ? `${p.type} indexed ${p.name}` : p.type
      ).join(', ');
      lines.push(`  ${contract.name}..>${event.name} : ${params}`);
    }
    
    lines.push('');
  }
  
  return lines.join('\n');
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function groupNodesByContract(
  nodes: Map<string, CallGraphNode>
): Map<string, string[]> {
  const groups = new Map<string, string[]>();
  
  for (const [key, node] of nodes) {
    const existing = groups.get(node.contract) || [];
    existing.push(key);
    groups.set(node.contract, existing);
  }
  
  return groups;
}

function escapeMermaid(text: string): string {
  return text
    .replace(/"/g, "'")
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Export call graph to JSON-serializable format
 */
export function exportCallGraph(graph: CallGraph): any {
  const nodesArray: any[] = [];
  for (const [key, node] of graph.nodes) {
    nodesArray.push({
      key,
      ...node,
      calls: node.calls.map(e => ({
        to: e.to,
        type: e.type
      })),
      calledBy: node.calledBy.map(e => ({
        from: e.from,
        type: e.type
      }))
    });
  }
  
  return {
    nodes: nodesArray,
    edges: graph.edges,
    entryPoints: graph.entryPoints,
    cycles: graph.cycles,
    depthMap: Object.fromEntries(graph.depthMap)
  };
}
