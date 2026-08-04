/**
 * Trackator Tier 3: Trace Analysis Engine
 * =======================================
 * Parses Foundry trace JSON, computes state diffs, detects anomalies.
 */

import * as fs from 'fs';
import {
  FoundryTrace,
  TraceStep,
  TransactionInfo,
  StateDiff,
  VariableChange,
  DecodedEvent,
  GasBreakdown,
  GasInfo,
  AlertRule,
  AlertResult,
  ProtocolStructure,
  FunctionCallInfo,
  StateReadInfo,
  StateWriteInfo,
  AlertCondition
} from '../types';

export class TraceAnalyzer {
  private structure?: ProtocolStructure;
  private alertRules: AlertRule[] = [];

  constructor(structure?: ProtocolStructure) {
    this.structure = structure;
  }

  /**
   * Set alert rules for anomaly detection
   */
  setAlertRules(rules: AlertRule[]): void {
    this.alertRules = rules;
  }

  /**
   * Parse Foundry trace JSON file
   */
  parseTraceFile(filePath: string): FoundryTrace {
    const content = fs.readFileSync(filePath, 'utf-8');
    
    let traceData: any;
    try {
      traceData = JSON.parse(content);
    } catch (e) {
      throw new Error(`Failed to parse trace JSON: ${e}`);
    }

    return this.parseTraceData(traceData);
  }

  /**
   * Parse trace data (from file or stdin)
   */
  parseTraceData(data: any): FoundryTrace {
    // Handle different Foundry trace formats
    const transaction = this.extractTransactionInfo(data);
    const steps = this.extractTraceSteps(data, 0);
    const stateDiffs = this.computeStateDiffs(steps);
    const events = this.extractEvents(steps);
    const gasUsage = this.computeGasInfo(steps);

    return {
      trace: steps,
      transaction,
      receipts: [],
      logs: [],
      gasInfo: gasUsage,
      timestamp: Date.now(),
      blockNumber: 0,
      steps,
      stateDiffs,
      events,
      gasUsage: gasUsage
    };
  }

  /**
   * Analyze trace against alert rules
   */
  analyzeTrace(trace: FoundryTrace): AnalysisResult {
    const alerts: AlertResult[] = [];
    
    // Check each state diff against rules
    for (const stateDiff of (trace.stateDiffs ?? [])) {
      for (const change of ((stateDiff as any).changes ?? [])) {
        const triggeredAlerts = this.checkAlertsForChange(stateDiff, change);
        alerts.push(...triggeredAlerts);
      }
    }

    // Check each step for function-level alerts
    for (const step of (trace.steps ?? trace.trace ?? [])) {
      const stepAlerts = this.checkAlertsForStep(step);
      alerts.push(...stepAlerts);
    }

    // Deduplicate and sort by severity
    const uniqueAlerts = this.deduplicateAlerts(alerts);

    return {
      trace,
      alerts: uniqueAlerts,
      summary: this.generateSummary(trace, uniqueAlerts)
    };
  }

  // ==================== TRACE PARSING ====================

  private extractTransactionInfo(data: any): TransactionInfo {
    // Try to extract transaction info from various formats
    // TransactionInfo expects: from, to, value (string), input, gas (number), gasPrice (string), nonce, chainId, type
    return {
      hash: data.transactionHash || data.hash || 'unknown',
      from: data.from || data.sender || 'unknown',
      to: data.to || data.address || data.contract || 'unknown',
      value: String(data.value || 0), // Convert to string as expected by TransactionInfo
      input: data.input || data.data || '',
      gas: Number(data.gasLimit || data.gas || 0),
      gasPrice: String(data.gasPrice || data.effectiveGasPrice || 0),
      nonce: Number(data.nonce || 0),
      chainId: Number(data.chainId || 1),
      type: Number(data.type || (data.maxFeePerHex ? 2 : 0)),
      blockNumber: data.blockNumber || data.block || 0,
      timestamp: data.timestamp || Date.now(),
      status: data.status === '0x0' || data.reverted ? 'revert' : 
             data.error ? 'error' : 'success'
    } as any;
  }

  private extractTraceSteps(data: any, depth: number): TraceStep[] {
    const steps: TraceStep[] = [];
    
    // Handle array of traces or single trace
    const traces = Array.isArray(data) ? data : [data];
    
    let stepIndex = 0;
    
    for (const entry of traces) {
      if (!entry) continue;

      // Different Foundry output formats
      if (entry.type === 'call' || entry.type === 'Call' || entry.action?.callType) {
        steps.push(this.parseCallEntry(entry, stepIndex++, depth));
      }
      
      // Recursive subcalls
      if (entry.calls || entry.children || entry.logs) {
        const subcalls = this.extractTraceSteps(
          entry.calls || entry.children || entry.logs, 
          depth + 1
        );
        steps.push(...subcalls);
      }
      
      // Decode events
      if (entry.type === 'event' || entry.event || entry.topics) {
        // Events handled separately
      }
    }

    return steps;
  }

  private parseCallEntry(entry: any, stepIndex: number, depth: number): TraceStep {
    // Extract function info
    const functionSig = entry.input || entry.data || '';
    const functionName = this.decodeFunctionSignature(functionSig) || 
                         entry.functionName ||
                         entry.methodId ||
                         entry.action?.input?.slice(0, 10) ||
                         'unknown';
    
    // Extract inputs/outputs
    const inputs = this.decodeInputs(entry.input || entry.data || '', entry.args || {});
    const outputs = this.decodeOutputs(entry.output || entry.result || '');

    // Extract gas info (convert to number as TraceStep.gasUsed is number type)
    const gasUsed = Number(entry.gasUsed || (entry.gas ?? 0));
    const gasRemaining = Number(entry.gasRemaining ?? 0);

    return {
      stepIndex,
      depth,
      address: entry.address || entry.to || entry.contract || 'unknown',
      input: entry.input || entry.data || '',
      contractName: entry.contractName || this.resolveContractName(entry.address),
      function: { name: functionName, signature: functionName, contract: entry.address || entry.to || 'unknown', isExternal: true, valueSent: BigInt(entry.value || 0) },
      inputs: Object.keys(inputs).length > 0 ? Object.values(inputs).map(String) : undefined,
      status: (!entry.error && entry.status !== 'revert') ? 'success' as const : ('revert' as const),
      success: !entry.error && entry.status !== 'revert' ? true : undefined,
      gasUsed,
      gasRemaining,
      opcodes: [], // Would be filled in post-processing
      error: entry.error || entry.revertReason || undefined,
      subcalls: [], // Would be filled in post-processing
      stateReads: this.extractStateReads(entry) as unknown as StateReadInfo[],
      stateWrites: this.extractStateWrites(entry) as unknown as StateWriteInfo[]
    };
  }

  private decodeFunctionSignature(data: string): string | null {
    if (!data || typeof data !== 'string') return null;
    
    // Common function signatures (4-byte selector)
    const selectors: Record<string, string> = {
      'a9059cbb': 'transfer(address,uint256)',
      '23b872dd': 'transferFrom(address,address,uint256)',
      '095ea7b3': 'approve(address,uint256)',
      '70a08231': 'balanceOf(address)',
      '18160ddd': 'totalSupply()',
      '40c10f19': 'mint(address,uint256)',
      '42966c68': 'burn(uint256)',
      'd0e30db0': 'deposit()',
      '2e1a7d4d': 'withdraw(uint256)'
    };

    const selector = data.slice(2, 10).toLowerCase();
    return selectors[selector] || null;
  }

  private decodeInputs(data: string | any, args: any): Record<string, any> {
    if (args && typeof args === 'object') return args;
    
    // Simplified ABI decoding - real implementation would use proper decoder
    return { rawInput: data?.slice(0, 100) || '' };
  }

  private decodeOutputs(output: string | any): Record<string, any> {
    if (typeof output !== 'string') return output || {};
    return { rawOutput: output?.slice(0, 100) || '' };
  }

  private resolveContractName(address: string): string {
    if (!this.structure) return address.substring(0, 10) + '...';
    
    // Look up contract name from known addresses
    for (const contract of this.structure.contracts) {
      // In real implementation, would map deployed addresses
      if (contract.name.toLowerCase().includes('pool')) return contract.name;
      if (contract.name.toLowerCase().includes('token')) return contract.name;
      if (contract.name.toLowerCase().includes('oracle')) return contract.name;
    }
    
    return address.substring(0, 10) + '...';
  }

  private extractStateReads(entry: any): Array<{ slot: string; variable?: string; value: string }> {
    // Would need storage layout mapping - return empty array matching StateReadInfo shape
    return [];
  }

  private extractStateWrites(entry: any): Array<{ slot: string; beforeValue: string; afterValue: string; variable?: string; value?: string }> {
    // Would need storage layout mapping - return empty array matching StateWriteInfo shape
    return [];
  }

  // ==================== STATE DIFF COMPUTATION ====================

  private computeStateDiffs(steps: TraceStep[]): StateDiff[] {
    const diffs: StateDiff[] = [];
    
    // Group changes by step
    for (const step of steps) {
      const changes: any[] = [];
      
      // Extract state writes with before/after values
      for (const write of (step.stateWrites ?? [])) {
        // Find previous value (would need pre-execution snapshot)
        const beforeValue = this.getPreviousValue(write.slot, step.address, steps, step.stepIndex);
        
        changes.push({
          variable: write.variable,
          contract: step.contractName || step.address,
          beforeValue: beforeValue,
          afterValue: write.afterValue || write.value,
          changeType: 'modified' as const,
          slot: write.slot,
          deltaPercent: this.computeDeltaPercent(beforeValue, write.afterValue || write.value)
        });
      }

      if (changes.length > 0) {
        diffs.push({
          address: step.address || 'unknown',
          contract: step.contractName || 'unknown',
          contractName: step.contractName || 'unknown',
          stepIndex: step.stepIndex,
          slotChanges: [],
          balanceChange: { before: '0', after: '0' },
          codeChanged: false,
          nonceChanged: false,
          changes: changes
        } as any);
      }
    }

    return diffs;
  }

  private getPreviousValue(
    slot: string, 
    contract: string, 
    steps: TraceStep[], 
    currentStep: number
  ): any {
    // Search backwards for last write to this slot
    for (let i = currentStep - 1; i >= 0; i--) {
      const prevWrites = (steps[i].stateWrites ?? []).filter(
        w => w.slot === slot
      );
      if (prevWrites.length > 0) {
        return prevWrites[prevWrites.length - 1].afterValue || prevWrites[prevWrites.length - 1].value;
      }
    }
    
    return null; // Unknown initial value
  }

  private computeDelta(before: any, after: any): any {
    if (before == null || after == null) return null;
    
    if (typeof before === 'bigint' && typeof after === 'bigint') {
      return after - before;
    }
    
    if (typeof before === 'number' && typeof after === 'number') {
      return after - before;
    }
    
    return `${before} → ${after}`;
  }

  private computeDeltaPercent(before: any, after: any): number | undefined {
    if (before == null || after == null || before === 0) return undefined;
    
    const beforeNum = typeof before === 'bigint' ? Number(before) : before;
    const afterNum = typeof after === 'bigint' ? Number(after) : after;
    
    if (typeof beforeNum !== 'number' || typeof afterNum !== 'number') return undefined;
    
    return ((afterNum - beforeNum) / Math.abs(Number(beforeNum))) * 100;
  }

  // ==================== EVENT EXTRACTION ====================

  private extractEvents(steps: TraceStep[]): DecodedEvent[] {
    const events: DecodedEvent[] = [];
    
    for (const step of steps) {
      // Events would be extracted from logs in full implementation
      // This is a placeholder that would use ABI decoding
    }

    return events;
  }

  // ==================== GAS ANALYSIS ====================

  private computeGasInfo(steps: TraceStep[]): GasInfo {
    let totalGas = 0;

    for (const step of steps) {
      totalGas += Number(step.gasUsed || 0);
    }

    // Return proper GasInfo structure
    return {
      gasLimit: totalGas + 100000, // Estimate
      gasUsed: totalGas,
      effectiveGasPrice: 0, // Would need from transaction
      refund: 0,
      breakdown: [{
        category: 'execution',
        amount: totalGas,
        percentage: 100
      }]
    };
  }

  // ==================== ALERT CHECKING ====================

  private checkAlertsForChange(stateDiff: StateDiff, change: any): AlertResult[] {
    const results: AlertResult[] = [];

    for (const rule of this.alertRules) {
      // Skip rules with specific triggers that don't match
      if (rule.trigger !== undefined && 
          rule.trigger !== 'per-state-change' && 
          rule.trigger !== 'periodic') {
        continue;
      }

      // Convert condition to string for evaluation
      const conditionStr = typeof rule.condition === 'string' 
        ? rule.condition 
        : JSON.stringify(rule.condition);

      if (this.evaluateCondition(conditionStr, change)) {
        results.push({
          id: `alert-${rule.id}-${Date.now()}`,
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          category: rule.category,
          title: `Invariant check: ${rule.name}`,
          description: `Variable ${change.variable || 'unknown'} changed`,
          location: { file: 'trace', line: stateDiff.stepIndex ?? 0, contract: stateDiff.contractName || 'unknown', function: '' },
          evidence: [{
            type: 'state-diff',
            description: `Variable ${change.variable || 'unknown'} changed from ${change.beforeValue} to ${change.afterValue}`,
            data: change
          }],
          suggestion: rule.remediation || rule.mitigation || 'Review the state change',
          falsePositiveRisk: 'medium' as const,
          timestamp: Date.now(),
          stepIndex: stateDiff.stepIndex ?? 0,
          suppressable: true
        });
      }
    }

    return results;
  }

  private checkAlertsForStep(step: TraceStep): AlertResult[] {
    const results: AlertResult[] = [];

    for (const rule of this.alertRules) {
      // Skip rules with specific triggers that don't match
      if (rule.trigger !== undefined && 
          rule.trigger !== 'on-function-call' && 
          rule.trigger !== 'on-transfer' && 
          rule.trigger !== 'on-oracle-read') {
        continue;
      }

      // Convert condition to string for evaluation
      const conditionStr = typeof rule.condition === 'string' 
        ? rule.condition 
        : JSON.stringify(rule.condition);

      // Check function-specific conditions
      if (this.evaluateStepCondition(conditionStr, step)) {
        const funcName = (step.function as FunctionCallInfo | undefined)?.name || 'unknown';
        results.push({
          id: `alert-${rule.id}-${Date.now()}`,
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          category: rule.category,
          title: `Function check: ${rule.name}`,
          description: `Call to ${funcName} at depth ${step.depth}`,
          location: { file: 'trace', line: step.stepIndex, contract: step.contractName || 'unknown', function: funcName },
          evidence: [{
            type: 'call-stack',
            description: `Call to ${funcName} at depth ${step.depth}`,
            data: { depth: step.depth, success: step.success }
          }],
          suggestion: rule.remediation || rule.mitigation || 'Review the function call',
          falsePositiveRisk: 'low' as const,
          timestamp: Date.now(),
          stepIndex: step.stepIndex,
          suppressable: true
        });
      }
    }

    return results;
  }

  /**
   * Simple condition evaluator (would be more sophisticated in production)
   */
  private evaluateCondition(condition: string, change: any): boolean {
    // Simplified condition evaluation
    const condLower = condition.toLowerCase();
    
    // Delta percent checks
    if (condLower.includes('delta_percent')) {
      const match = condLower.match(/delta_percent\s*([><=]+)\s*(\d+)/);
      if (match && change.deltaPercent !== undefined) {
        const threshold = parseFloat(match[2]);
        switch (match[1]) {
          case '>': return Number(change.deltaPercent) > threshold;
          case '<': return Number(change.deltaPercent) < threshold;
          case '>=': return Number(change.deltaPercent) >= threshold;
          case '<=': return Number(change.deltaPercent) <= threshold;
        }
      }
    }

    // Oracle deviation checks
    if (condLower.includes('spot') && condLower.includes('twap')) {
      // Would need actual oracle data comparison
      return false; // Placeholder
    }

    return false;
  }

  private evaluateStepCondition(condition: string, step: TraceStep): boolean {
    const condLower = condition.toLowerCase();

    // Access control checks
    if (condLower.includes('unauthorized') || condLower.includes('access_breach')) {
      // Would need caller identity verification
      return false; // Placeholder
    }

    // Reentrancy pattern detection
    if (condLower.includes('external_call') && condLower.includes('state_update')) {
      // Check if external calls exist in this step
      return (step.stateReads ?? []).length > 0; // Simplified check
    }

    return false;
  }

  private deduplicateAlerts(alerts: AlertResult[]): AlertResult[] {
    const seen = new Set<string>();
    return alerts.filter(alert => {
      const key = `${alert.ruleId}-${alert.stepIndex}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).sort((a, b) => {
      // Use valid AlertSeverity values: critical, high, medium, low, info, informational
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 5 };
      return (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99);
    });
  }

  private generateSummary(trace: FoundryTrace, alerts: AlertResult[]): AnalysisSummary {
    const criticalCount = alerts.filter(a => a.severity === 'critical').length;
    const highCount = alerts.filter(a => a.severity === 'high').length;
    const mediumCount = alerts.filter(a => a.severity === 'medium').length;

    const steps = trace.steps ?? trace.trace ?? [];
    const stateDiffs = trace.stateDiffs ?? [];
    const events = trace.events ?? [];
    const gasInfo = trace.gasUsage ?? trace.gasInfo;

    return {
      totalSteps: steps.length,
      totalStateChanges: stateDiffs.reduce((sum: number, d: any) => sum + ((d.changes ?? d.slotChanges ?? []) as any[]).length, 0),
      totalEvents: events.length,
      totalGasUsed: gasInfo ? String(gasInfo.gasUsed) : '0',
      alertsBySeverity: {
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        warning: alerts.filter(a => a.severity === 'low').length, // Map 'low' to 'warning' for summary
        info: alerts.filter(a => a.severity === 'info' || a.severity === 'informational').length
      },
      riskAssessment: criticalCount > 0 ? 'CRITICAL' :
                       highCount > 3 ? 'HIGH' :
                       highCount > 0 ? 'MEDIUM' : 'LOW'
    };
  }
}

export interface AnalysisResult {
  trace: FoundryTrace;
  alerts: AlertResult[];
  summary: AnalysisSummary;
}

export interface AnalysisSummary {
  totalSteps: number;
  totalStateChanges: number;
  totalEvents: number;
  totalGasUsed: string;
  alertsBySeverity: {
    critical: number;
    high: number;
    medium: number;
    warning: number;
    info: number;
  };
  riskAssessment: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export default TraceAnalyzer;
