// ============================================================
// TRACKATOR Tier 3 - Foundry Trace Parser
// Parses Foundry --trace output for runtime analysis
// ============================================================

import * as fs from 'fs';
import {
  FoundryTrace,
  TraceStep,
  TransactionInfo,
  Receipt,
  LogEntry,
  GasInfo,
  OpcodeExecution,
  MemorySnapshot,
  StorageSnapshot
} from '../types';

export interface ParseOptions {
  verbose?: boolean;
  maxDepth?: number;
  includeOpcodes?: boolean;
}

/**
 * Parse Foundry trace JSON file
 */
export function parseFoundryTrace(traceFilePath: string, options: ParseOptions = {}): FoundryTrace {
  const {
    verbose = false,
    maxDepth = 100,
    includeOpcodes = false
  } = options;
  
  if (verbose) console.log(`Parsing trace file: ${traceFilePath}`);
  
  // Read and parse JSON
  const rawContent = fs.readFileSync(traceFilePath, 'utf-8');
  let rawData: any;
  
  try {
    rawData = JSON.parse(rawContent);
  } catch (error: any) {
    throw new Error(`Failed to parse trace JSON: ${error.message}`);
  }
  
  if (verbose) console.log('Raw trace loaded, parsing structure...');
  
  // Normalize different Foundry trace formats
  const normalized = normalizeTraceFormat(rawData);
  
  // Parse transaction info
  const transaction = parseTransactionInfo(normalized);
  
  // Parse trace steps
  const trace = parseTraceSteps(normalized, { maxDepth, includeOpcodes });
  
  // Parse receipts
  const receipts = parseReceipts(normalized);
  
  // Parse logs
  const logs = parseLogs(normalized);
  
  // Compute gas info
  const gasInfo = computeGasInfo(trace, receipts[0]);
  
  return {
    trace,
    transaction,
    receipts,
    logs,
    gasInfo,
    timestamp: Date.now(),
    blockNumber: normalized.blockNumber || 0
  };
}

/**
 * Normalize different Foundry trace output formats
 * Foundry can output traces in various formats depending on version
 */
function normalizeTraceFormat(raw: any): any {
  // Check if it's already in expected format
  if (raw.trace && Array.isArray(raw.trace)) {
    return raw;
  }
  
  // Foundry --trace format (array of structures)
  if (Array.isArray(raw)) {
    return {
      trace: raw,
      transaction: extractTransactionFromArray(raw),
      blockNumber: 0
    };
  }
  
  // Foundry test result format
  if (raw.traces || raw.result?.traces) {
    return {
      traces: raw.traces || raw.result?.traces,
      transaction: raw.transactionInfo || {},
      blockNumber: raw.blockNumber || 0
    };
  }
  
  // Debug trace format (from forge --trace)
  if (raw.debug_trace || raw.structLogs) {
    return convertDebugTrace(raw);
  }
  
  // Return as-is with defaults
  return {
    trace: raw.trace || [],
    transaction: raw.transaction || {},
    receipts: raw.receipts || [],
    logs: raw.logs || [],
    blockNumber: raw.blockNumber || 0
  };
}

function extractTransactionFromArray(traceArray: any[]): any {
  // Try to find transaction info from first entry or common patterns
  for (const entry of traceArray) {
    if (entry.transaction) return entry.transaction;
    if (entry.from && entry.to && entry.input) {
      return {
        from: entry.from,
        to: entry.to,
        value: entry.value || '0x0',
        input: entry.input || '0x',
        gas: entry.gas || 0,
        gasPrice: entry.gasPrice || '0x0',
        nonce: entry.nonce || 0,
        chainId: entry.chainId || 1,
        type: entry.type || 0
      };
    }
  }
  
  return {
    from: '0x0000000000000000000000000000000000000000',
    to: null,
    value: '0x0',
    input: '0x',
    gas: 0,
    gasPrice: '0x0',
    nonce: 0,
    chainId: 1,
    type: 0
  };
}

function convertDebugTrace(debugTrace: any): any {
  const structLogs = debugTrace.structLogs || debugTrace.debug_trace?.structLogs || [];
  
  const trace: TraceStep[] = [];
  let stepIndex = 0;
  
  for (const log of structLogs) {
    // Convert Geth-style debug trace to our format
    trace.push({
      stepIndex: stepIndex++,
      depth: log.depth || 0,
      address: log.address || '0x0000000000000000000000000000000000000000',
      input: '',
      status: 'success',
      gasUsed: 0,
      gasRemaining: log.gas || 0,
      opcodes: [{
        pc: log.pc || 0,
        opcode: log.op || 'STOP',
        stackBefore: log.stack || [],
        stackAfter: [],
        gasCost: log.gasCost || 0,
        depth: log.depth || 0
      }],
      memoryBefore: log.memory ? { data: log.memory, size: (log.memory.length - 2) / 2 } : undefined,
      error: log.error
    });
  }
  
  return {
    trace,
    transaction: debugTrace.tx || {},
    receipts: [],
    logs: [],
    blockNumber: debugTrace.blockNumber || 0
  };
}

/**
 * Parse transaction information
 */
function parseTransactionInfo(normalized: any): TransactionInfo {
  const tx = normalized.transaction || {};
  
  return {
    from: tx.from || '0x0000000000000000000000000000000000000000',
    to: tx.to || null,
    value: tx.value || '0x0',
    input: tx.input || '0x',
    gas: tx.gas || 1000000,
    gasPrice: tx.gasPrice || tx.effectiveGasPrice || '0x0',
    nonce: tx.nonce || 0,
    chainId: tx.chainId || 1,
    type: tx.type || tx.transactionType || 0
  };
}

/**
 * Parse trace steps recursively
 */
function parseTraceSteps(
  normalized: any,
  options: { maxDepth: number; includeOpcodes: boolean }
): TraceStep[] {
  const traces = normalized.trace || normalized.traces || [];
  const steps: TraceStep[] = [];
  
  for (let i = 0; i < traces.length; i++) {
    const traceEntry = traces[i];
    
    try {
      const step = parseSingleStep(traceEntry, i, 0, options);
      if (step) {
        steps.push(step);
      }
    } catch (error: any) {
      // Skip malformed entries but continue parsing
      if ((options as ParseOptions).verbose !== false) {
        console.warn(`Warning: Failed to parse trace step ${i}: ${error.message}`);
      }
    }
  }
  
  return steps;
}

function parseSingleStep(
  entry: any,
  index: number,
  depth: number,
  options: { maxDepth: number; includeOpcodes: boolean }
): TraceStep | null {
  // Skip if beyond max depth
  if (depth > options.maxDepth) {
    return null;
  }
  
  // Determine address
  const address = entry.address || 
                  entry.to || 
                  (entry.action?.address) ||
                  '0x0000000000000000000000000000000000000000';
  
  // Determine input/calldata
  const input = entry.input || 
                 entry.action?.input || 
                 entry.calldata || 
                 '0x';
  
  // Determine output/return data
  const output = entry.output || 
                  entry.result?.returnData ||
                  entry.returnData ||
                  undefined;
  
  // Determine status
  let status: TraceStep['status'] = 'success';
  if (entry.error || entry.revert || entry.result?.revertReason) {
    status = 'revert';
  } else if (entry.success === false) {
    status = 'error';
  }
  
  // Determine gas usage
  const gasUsed = entry.gasUsed || 
                  entry.result?.gasUsed ||
                  calculateGasFromOpcodes(entry);
  
  const gasRemaining = entry.gas || 
                       entry.result?.gas ||
                       0;
  
  // Parse opcodes if present and requested
  let opcodes: OpcodeExecution[] = [];
  if (options.includeOpcodes && entry.structLogs) {
    opcodes = parseOpcodes(entry.structLogs, depth);
  } else if (options.includeOpcodes && entry.opcodes) {
    opcodes = entry.opcodes;
  }
  
  // Parse storage changes
  let storageBefore: StorageSnapshot | undefined;
  let storageAfter: StorageSnapshot | undefined;
  
  if (entry.storageChanges || entry.stateDiff) {
    const storageChanges = entry.storageChanges || entry.stateDiff;
    storageBefore = { slots: {} };
    storageAfter = { slots: storageChanges };
  }
  
  // Parse subcalls recursively
  let subcalls: TraceStep[] | undefined;
  if (entry.calls || entry.children || entry.traces) {
    const childTraces = entry.calls || entry.children || entry.traces;
    subcalls = [];
    
    for (let i = 0; i < childTraces.length; i++) {
      const childStep = parseSingleStep(childTraces[i], i, depth + 1, options);
      if (childStep) {
        subcalls.push(childStep);
      }
    }
  }
  
  // Extract contract name if available
  const contractName = entry.contractName || 
                       decodeFunctionSignature(input)?.name ||
                       undefined;
  
  return {
    stepIndex: index,
    depth,
    address: normalizeAddress(address),
    contractName,
    input,
    output,
    status,
    gasUsed,
    gasRemaining,
    opcodes,
    memoryBefore: undefined, // Would need pre-execution snapshot
    memoryAfter: undefined, // Would need post-execution snapshot
    storageBefore,
    storageAfter,
    subcalls,
    error: entry.error || entry.result?.revertReason || undefined
  };
}

/**
 * Parse opcode-level execution details
 */
function parseOpcodes(structLogs: any[], baseDepth: number): OpcodeExecution[] {
  return structLogs.map((log: any, idx: number) => ({
    pc: log.pc || 0,
    opcode: log.op || 'UNKNOWN',
    pushData: log.pushData ? `0x${log.pushData}` : undefined,
    stackBefore: log.stack || [],
    stackAfter: [], // Would need next log's stack
    memoryOffset: log.memoryOffset,
    gasCost: log.gasCost || 0,
    depth: baseDepth + (log.depth || 0)
  }));
}

/**
 * Calculate approximate gas usage from available data
 */
function calculateGasFromOpcodes(entry: any): number {
  if (!entry.structLogs) return 0;
  
  return entry.structLogs.reduce((total: number, log: any) => {
    return total + (log.gasCost || 0);
  }, 0);
}

/**
 * Parse receipt information
 */
function parseReceipts(normalized: any): Receipt[] {
  const receipts: Receipt[] = [];
  
  // Direct receipt field
  if (normalized.receipt) {
    receipts.push(parseSingleReceipt(normalized.receipt));
    return receipts;
  }
  
  // Array of receipts
  if (Array.isArray(normalized.receipts)) {
    return normalized.receipts.map(parseSingleReceipt);
  }
  
  // Build receipt from trace data
  if (normalized.trace) {
    const lastStep = normalized.trace[normalized.trace.length - 1];
    if (lastStep) {
      receipts.push({
        transactionHash: normalized.transactionHash || generateMockHash(),
        transactionIndex: 0,
        blockHash: normalized.blockHash || generateMockHash(),
        blockNumber: normalized.blockNumber || 0,
        from: normalized.transaction?.from || '0x0',
        to: normalized.transaction?.to || null,
        cumulativeGasUsed: lastStep.gasUsed || 0,
        gasUsed: lastStep.gasUsed || 0,
        contractAddress: lastStep.address, // Simplified
        status: lastStep.status === 'success' ? 1 : 0,
        logs: [],
        logsBloom: ''
      });
    }
  }
  
  return receipts;
}

function parseSingleReceipt(receipt: any): Receipt {
  return {
    transactionHash: receipt.transactionHash || generateMockHash(),
    transactionIndex: receipt.transactionIndex || 0,
    blockHash: receipt.blockHash || generateMockHash(),
    blockNumber: receipt.blockNumber || 0,
    from: receipt.from || '0x0',
    to: receipt.to || null,
    cumulativeGasUsed: receipt.cumulativeGasUsed || 0,
    gasUsed: receipt.gasUsed || 0,
    contractAddress: receipt.contractAddress || undefined,
    status: receipt.status ?? 1,
    logs: (receipt.logs || []).map(parseLogEntry),
    logsBloom: receipt.logsBloom || ''
  };
}

/**
 * Parse log entries
 */
function parseLogs(normalized: any): LogEntry[] {
  const logs: LogEntry[] = [];
  
  // Direct logs array
  if (normalized.logs) {
    return normalized.logs.map(parseLogEntry);
  }
  
  // Logs from receipts
  if (normalized.receipts) {
    for (const receipt of normalized.receipts) {
      if (receipt.logs) {
        logs.push(...receipt.logs.map(parseLogEntry));
      }
    }
  }
  
  // Extract logs from trace steps
  if (normalized.trace) {
    extractLogsFromTrace(normalized.trace, logs);
  }
  
  return logs;
}

function parseLogEntry(log: any): LogEntry {
  return {
    address: log.address || log.log?.address || '0x0',
    topics: log.topics || log.log?.topics || [],
    data: log.data || log.log?.data || '0x',
    logIndex: log.logIndex || log.index || 0,
    transactionIndex: log.transactionIndex || 0,
    blockNumber: log.blockNumber || 0,
    transactionHash: log.transactionHash || generateMockHash(),
    decoded: log.decoded || attemptLogDecoding(log)
  };
}

function extractLogsFromTrace(traces: any[], logs: LogEntry[]): void {
  for (const trace of traces) {
    // Check for logs at this level
    if (trace.logs) {
      for (const log of trace.logs) {
        logs.push(parseLogEntry(log));
      }
    }
    if (trace.events) {
      for (const event of trace.events) {
        logs.push({
          address: event.address || trace.address || '0x0',
          topics: event.topics || [],
          data: event.data || '0x',
          logIndex: logs.length,
          transactionIndex: 0,
          blockNumber: 0,
          transactionHash: generateMockHash(),
          decoded: event.decoded || {
            name: event.name || 'UnknownEvent',
            signature: event.signature || '',
            args: event.args || {},
            contract: event.contractName || ''
          }
        });
      }
    }
    
    // Recurse into subcalls
    if (trace.calls || trace.children || trace.traces) {
      const children = trace.calls || trace.children || trace.traces;
      extractLogsFromTrace(children, logs);
    }
  }
}

/**
 * Attempt basic log decoding using common ERC20/ERC721 signatures
 */
function attemptLogDecoding(log: LogEntry): LogEntry['decoded'] | undefined {
  if (!log.topics || log.topics.length === 0) return undefined;
  
  const topic0 = log.topics[0];
  
  // Common event signatures
  const knownEvents: Record<string, { name: string; args: Record<string, any> }> = {
    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef': {
      name: 'Transfer',
      args: {
        from: `0x${(log.topics[1] || '').slice(26)}`,
        to: `0x${(log.topics[2] || '').slice(26)}`,
        value: log.data ? BigInt(log.data).toString() : '0'
      }
    },
    '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925': {
      name: 'Approval',
      args: {
        owner: `0x${(log.topics[1] || '').slice(26)}`,
        spender: `0x${(log.topics[2] || '').slice(26)}`,
        value: log.data ? BigInt(log.data).toString() : '0'
      }
    },
    '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67a': {
      name: 'OwnershipTransferred',
      args: {
        previousOwner: `0x${(log.topics[1] || '').slice(26)}`,
        newOwner: `0x${(log.topics[2] || '').slice(26)}`
      }
    }
  };
  
  const known = knownEvents[topic0.toLowerCase()];
  if (known) {
    return {
      name: known.name,
      signature: topic0,
      args: known.args,
      contract: '' // Would need ABI to determine
    };
  }
  
  return undefined;
}

/**
 * Compute gas information summary
 */
function computeGasInfo(_trace: TraceStep[], receipt?: Receipt): GasInfo {
  const gasLimit = receipt?.cumulativeGasUsed || 0;
  const gasUsed = receipt?.gasUsed || 0;
  
  // Estimate breakdown (simplified)
  const executionGas = Math.floor(gasUsed * 0.7);
  const storageGas = Math.floor(gasUsed * 0.2);
  const calldataGas = gasUsed - executionGas - storageGas;
  
  return {
    gasLimit,
    gasUsed,
    effectiveGasPrice: 0, // Would need from transaction
    refund: 0, // Would need calculation
    breakdown: [
      { category: 'execution', amount: executionGas, percentage: 70 },
      { category: 'storage', amount: storageGas, percentage: 20 },
      { category: 'calldata', amount: calldataGas, percentage: 10 }
    ]
  };
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function normalizeAddress(address: string): string {
  if (!address) return '0x0000000000000000000000000000000000000000';
  return address.startsWith('0x') ? address : `0x${address}`;
}

function generateMockHash(): string {
  return `0x${Math.random().toString(16).substr(2, 64).padEnd(64, '0')}`;
}

interface DecodedSignature {
  name: string;
  inputs: { type: string; name?: string }[];
}

function decodeFunctionSignature(calldata: string): DecodedSignature | null {
  if (!calldata || calldata.length < 10) return null;
  
  // Common function selectors
  const selectors: Record<string, DecodedSignature> = {
    '0xa9059cbb': { name: 'transfer', inputs: [{ type: 'address', name: 'to' }, { type: 'uint256', name: 'amount' }] },
    '0x23b872dd': { name: 'transferFrom', inputs: [{ type: 'address', name: 'from' }, { type: 'address', name: 'to' }, { type: 'uint256', name: 'amount' }] },
    '0x095ea7b3': { name: 'approve', inputs: [{ type: 'address', name: 'spender' }, { type: 'uint256', name: 'amount' }] },
    '0x70a08231': { name: 'balanceOf', inputs: [{ type: 'address', name: 'account' }] },
    '0x18160ddd': { name: 'totalSupply', inputs: [] },
    '0x313ce567': { name: 'decimals', inputs: [] },
    '0x06fdde03': { name: 'name', inputs: [] },
    '0x95d89b41': { name: 'symbol', inputs: [] },
    '0x8da5cb5b': { name: 'owner', inputs: [] },
    '0xf2fde38b': { name: 'transferOwnership', inputs: [{ type: 'address', name: 'newOwner' }] },
    '0x715018a6': { name: 'renounceOwnership', inputs: [] },
    '0xa457c2d7': { name: 'pause', inputs: [] },
    '0x3f4ba83a': { name: 'unpause', inputs: [] },
    '0xd0e30db0': { name: 'deposit', inputs: [] },
    '0x2e1a7d4d': { name: 'withdraw', inputs: [{ type: 'uint256', name: 'amount' }] },
    '0x1f00390c': { name: 'swapExactTokensForTokens', inputs: [
      { type: 'uint256', name: 'amountIn' },
      { type: 'uint256', name: 'amountOutMin' },
      { type: 'address[]', name: 'path' },
      { type: 'address', name: 'to' },
      { type: 'uint256', name: 'deadline' }
    ]},
    '0x7ff36ab5': { name: 'swapExactETHForTokens', inputs: [
      { type: 'uint256', name: 'amountOutMin' },
      { type: 'address[]', name: 'path' },
      { type: 'address', name: 'to' },
      { type: 'uint256', name: 'deadline' }
    ]},
    '0x18cbafe5': { name: 'swapExactTokensForETH', inputs: [
      { type: 'uint256', name: 'amountIn' },
      { type: 'uint256', name: 'amountOutMin' },
      { type: 'address[]', name: 'path' },
      { type: 'address', name: 'to' },
      { type: 'uint256', name: 'deadline' }
    ]}
  };
  
  const selector = calldata.slice(0, 10).toLowerCase();
  return selectors[selector] || null;
}

/**
 * Export utilities for other modules
 */
export {
  normalizeTraceFormat,
  parseTransactionInfo,
  parseTraceSteps,
  parseLogs,
  decodeFunctionSignature,
  attemptLogDecoding
};
