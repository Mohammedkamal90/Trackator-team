"use strict";
/**
 * Trackator Tier 3: Trace Analysis Engine
 * =======================================
 * Parses Foundry trace JSON, computes state diffs, detects anomalies.
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
exports.TraceAnalyzer = void 0;
const fs = __importStar(require("fs"));
class TraceAnalyzer {
    constructor(structure) {
        this.alertRules = [];
        this.structure = structure;
    }
    /**
     * Set alert rules for anomaly detection
     */
    setAlertRules(rules) {
        this.alertRules = rules;
    }
    /**
     * Parse Foundry trace JSON file
     */
    parseTraceFile(filePath) {
        const content = fs.readFileSync(filePath, 'utf-8');
        let traceData;
        try {
            traceData = JSON.parse(content);
        }
        catch (e) {
            throw new Error(`Failed to parse trace JSON: ${e}`);
        }
        return this.parseTraceData(traceData);
    }
    /**
     * Parse trace data (from file or stdin)
     */
    parseTraceData(data) {
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
    analyzeTrace(trace) {
        const alerts = [];
        // Check each state diff against rules
        for (const stateDiff of (trace.stateDiffs ?? [])) {
            for (const change of (stateDiff.changes ?? [])) {
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
    extractTransactionInfo(data) {
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
        };
    }
    extractTraceSteps(data, depth) {
        const steps = [];
        // Handle array of traces or single trace
        const traces = Array.isArray(data) ? data : [data];
        let stepIndex = 0;
        for (const entry of traces) {
            if (!entry)
                continue;
            // Different Foundry output formats
            if (entry.type === 'call' || entry.type === 'Call' || entry.action?.callType) {
                steps.push(this.parseCallEntry(entry, stepIndex++, depth));
            }
            // Recursive subcalls
            if (entry.calls || entry.children || entry.logs) {
                const subcalls = this.extractTraceSteps(entry.calls || entry.children || entry.logs, depth + 1);
                steps.push(...subcalls);
            }
            // Decode events
            if (entry.type === 'event' || entry.event || entry.topics) {
                // Events handled separately
            }
        }
        return steps;
    }
    parseCallEntry(entry, stepIndex, depth) {
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
            status: (!entry.error && entry.status !== 'revert') ? 'success' : 'revert',
            success: !entry.error && entry.status !== 'revert' ? true : undefined,
            gasUsed,
            gasRemaining,
            opcodes: [], // Would be filled in post-processing
            error: entry.error || entry.revertReason || undefined,
            subcalls: [], // Would be filled in post-processing
            stateReads: this.extractStateReads(entry),
            stateWrites: this.extractStateWrites(entry)
        };
    }
    decodeFunctionSignature(data) {
        if (!data || typeof data !== 'string')
            return null;
        // Common function signatures (4-byte selector)
        const selectors = {
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
    decodeInputs(data, args) {
        if (args && typeof args === 'object')
            return args;
        // Simplified ABI decoding - real implementation would use proper decoder
        return { rawInput: data?.slice(0, 100) || '' };
    }
    decodeOutputs(output) {
        if (typeof output !== 'string')
            return output || {};
        return { rawOutput: output?.slice(0, 100) || '' };
    }
    resolveContractName(address) {
        if (!this.structure)
            return address.substring(0, 10) + '...';
        // Look up contract name from known addresses
        for (const contract of this.structure.contracts) {
            // In real implementation, would map deployed addresses
            if (contract.name.toLowerCase().includes('pool'))
                return contract.name;
            if (contract.name.toLowerCase().includes('token'))
                return contract.name;
            if (contract.name.toLowerCase().includes('oracle'))
                return contract.name;
        }
        return address.substring(0, 10) + '...';
    }
    extractStateReads(entry) {
        // Would need storage layout mapping - return empty array matching StateReadInfo shape
        return [];
    }
    extractStateWrites(entry) {
        // Would need storage layout mapping - return empty array matching StateWriteInfo shape
        return [];
    }
    // ==================== STATE DIFF COMPUTATION ====================
    computeStateDiffs(steps) {
        const diffs = [];
        // Group changes by step
        for (const step of steps) {
            const changes = [];
            // Extract state writes with before/after values
            for (const write of (step.stateWrites ?? [])) {
                // Find previous value (would need pre-execution snapshot)
                const beforeValue = this.getPreviousValue(write.slot, step.address, steps, step.stepIndex);
                changes.push({
                    variable: write.variable,
                    contract: step.contractName || step.address,
                    beforeValue: beforeValue,
                    afterValue: write.afterValue || write.value,
                    changeType: 'modified',
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
                });
            }
        }
        return diffs;
    }
    getPreviousValue(slot, contract, steps, currentStep) {
        // Search backwards for last write to this slot
        for (let i = currentStep - 1; i >= 0; i--) {
            const prevWrites = (steps[i].stateWrites ?? []).filter(w => w.slot === slot);
            if (prevWrites.length > 0) {
                return prevWrites[prevWrites.length - 1].afterValue || prevWrites[prevWrites.length - 1].value;
            }
        }
        return null; // Unknown initial value
    }
    computeDelta(before, after) {
        if (before == null || after == null)
            return null;
        if (typeof before === 'bigint' && typeof after === 'bigint') {
            return after - before;
        }
        if (typeof before === 'number' && typeof after === 'number') {
            return after - before;
        }
        return `${before} → ${after}`;
    }
    computeDeltaPercent(before, after) {
        if (before == null || after == null || before === 0)
            return undefined;
        const beforeNum = typeof before === 'bigint' ? Number(before) : before;
        const afterNum = typeof after === 'bigint' ? Number(after) : after;
        if (typeof beforeNum !== 'number' || typeof afterNum !== 'number')
            return undefined;
        return ((afterNum - beforeNum) / Math.abs(Number(beforeNum))) * 100;
    }
    // ==================== EVENT EXTRACTION ====================
    extractEvents(steps) {
        const events = [];
        for (const step of steps) {
            // Events would be extracted from logs in full implementation
            // This is a placeholder that would use ABI decoding
        }
        return events;
    }
    // ==================== GAS ANALYSIS ====================
    computeGasInfo(steps) {
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
    checkAlertsForChange(stateDiff, change) {
        const results = [];
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
                    falsePositiveRisk: 'medium',
                    timestamp: Date.now(),
                    stepIndex: stateDiff.stepIndex ?? 0,
                    suppressable: true
                });
            }
        }
        return results;
    }
    checkAlertsForStep(step) {
        const results = [];
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
                const funcName = step.function?.name || 'unknown';
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
                    falsePositiveRisk: 'low',
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
    evaluateCondition(condition, change) {
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
    evaluateStepCondition(condition, step) {
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
    deduplicateAlerts(alerts) {
        const seen = new Set();
        return alerts.filter(alert => {
            const key = `${alert.ruleId}-${alert.stepIndex}`;
            if (seen.has(key))
                return false;
            seen.add(key);
            return true;
        }).sort((a, b) => {
            // Use valid AlertSeverity values: critical, high, medium, low, info, informational
            const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 5 };
            return (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99);
        });
    }
    generateSummary(trace, alerts) {
        const criticalCount = alerts.filter(a => a.severity === 'critical').length;
        const highCount = alerts.filter(a => a.severity === 'high').length;
        const mediumCount = alerts.filter(a => a.severity === 'medium').length;
        const steps = trace.steps ?? trace.trace ?? [];
        const stateDiffs = trace.stateDiffs ?? [];
        const events = trace.events ?? [];
        const gasInfo = trace.gasUsage ?? trace.gasInfo;
        return {
            totalSteps: steps.length,
            totalStateChanges: stateDiffs.reduce((sum, d) => sum + (d.changes ?? d.slotChanges ?? []).length, 0),
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
exports.TraceAnalyzer = TraceAnalyzer;
exports.default = TraceAnalyzer;
//# sourceMappingURL=TraceAnalyzer.js.map