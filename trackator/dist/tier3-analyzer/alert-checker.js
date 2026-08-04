"use strict";
// ============================================================
// TRACKATOR Tier 3 - Alert Checker & Anomaly Detector
// Evaluates trace execution against alert rules and detects anomalies
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.runAnalysis = runAnalysis;
const state_diff_engine_1 = require("./state-diff-engine");
const oracle_analyzer_1 = require("./oracle-analyzer");
/**
 * Main entry point for Tier 3 analysis
 */
function runAnalysis(trace, options) {
    const { alertRules = [], minSeverity = 'info', includeGasAnalysis = true, includeOracleAnalysis = true, includeRoleTracking = true, verbose = false } = options;
    if (verbose)
        console.log('Starting Tier 3 analysis...');
    // Step 1: Compute state diffs
    if (verbose)
        console.log('Computing state differences...');
    const stateDiffs = (0, state_diff_engine_1.computeStateDiffs)(trace, { alertRules, verbose });
    // Step 2: Analyze oracles if enabled
    let oracleAnalysis;
    if (includeOracleAnalysis) {
        if (verbose)
            console.log('Analyzing oracle interactions...');
        oracleAnalysis = (0, oracle_analyzer_1.analyzeOracles)(trace);
    }
    // Step 3: Track role journeys if enabled
    let roleJourneys;
    if (includeRoleTracking) {
        if (verbose)
            console.log('Tracking role journeys...');
        roleJourneys = trackRoleJourneys(trace);
    }
    // Step 4: Check all alert rules
    if (verbose)
        console.log(`Evaluating ${alertRules.length} alert rules...`);
    const alerts = checkAllAlerts(trace, stateDiffs, oracleAnalysis, roleJourneys, alertRules, minSeverity);
    // Step 5: Generate summary
    const summary = generateAnalysisSummary(trace, stateDiffs, alerts, oracleAnalysis);
    return {
        alerts,
        stateDiffs,
        oracleAnalysis,
        roleJourneys,
        summary
    };
}
/**
 * Check all alert rules against execution data
 */
function checkAllAlerts(trace, stateDiffs, oracleAnalysis, _roleJourneys, alertRules = [], minSeverity = 'info') {
    const alerts = [];
    const severityOrder = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1,
        'informational': 1
    };
    const minOrder = severityOrder[minSeverity] || 0;
    for (const rule of alertRules) {
        // Skip disabled rules
        if (!rule.enabled)
            continue;
        // Skip rules below minimum severity
        if ((severityOrder[rule.severity] || 0) < minOrder)
            continue;
        // Evaluate rule based on its type
        const alert = evaluateAlertRule(rule, trace, stateDiffs, oracleAnalysis);
        if (alert) {
            alerts.push(alert);
        }
    }
    // Sort by severity (critical first)
    alerts.sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));
    return alerts;
}
/**
 * Evaluate a single alert rule
 */
function evaluateAlertRule(rule, trace, stateDiffs, oracleAnalysis) {
    switch (rule.tier) {
        case 'tier1':
            return evaluateTier1Rule(rule, trace);
        case 'tier2':
            return evaluateTier2Rule(rule, stateDiffs, oracleAnalysis);
        case 'tier3':
            return evaluateTier3Rule(rule, trace, stateDiffs);
        default:
            return null;
    }
}
/**
 * Evaluate Tier 1 rules (static pattern detection)
 */
function evaluateTier1Rule(rule, trace) {
    for (const step of trace.trace) {
        // CEI Pattern violation check
        if (rule.category === 'reentrancy' && rule.condition.field === 'ceiPattern') {
            // Look for external calls after state writes in same function
            const hasExternalCallAfterWrite = detectCEIViolation(step);
            if (hasExternalCallAfterWrite) {
                return createAlertFromRule(rule, step, [
                    {
                        type: 'call-stack',
                        description: `Function at depth ${step.depth} has potential CEI violation`,
                        data: { address: step.address, contractName: step.contractName }
                    }
                ]);
            }
        }
        // Missing access control check
        if (rule.category === 'access-control' && rule.condition.field === 'modifiers') {
            // This would need static analysis comparison - simplified here
            // In real implementation, would check against known public functions without modifiers
        }
        // DelegateCall detection
        if (rule.condition.field === 'hasDelegateCall') {
            const hasDelegateCall = detectDelegateCall(step);
            if (hasDelegateCall) {
                return createAlertFromRule(rule, step, [
                    {
                        type: 'call-stack',
                        description: 'Delegatecall detected - forwards execution context',
                        data: { address: step.address, input: step.input.slice(0, 20) + '...' }
                    }
                ]);
            }
        }
        // Unbounded loop detection
        if (rule.condition.field === 'hasLoop') {
            const hasLoop = detectUnboundedLoop(step);
            if (hasLoop) {
                return createAlertFromRule(rule, step, [
                    {
                        type: 'gas-anomaly',
                        description: 'Unbounded loop detected - potential DoS risk',
                        data: { gasUsed: step.gasUsed }
                    }
                ]);
            }
        }
        // Recurse into subcalls
        if (step.subcalls) {
            for (const subcall of step.subcalls) {
                const alert = evaluateTier1Rule(rule, { ...trace, trace: [subcall] });
                if (alert)
                    return alert;
            }
        }
    }
    return null;
}
/**
 * Evaluate Tier 2 rules (semantic/business logic checks)
 */
function evaluateTier2Rule(rule, stateDiffs, oracleAnalysis) {
    // Price deviation checks
    if (rule.category === 'oracle-manipulation' && oracleAnalysis) {
        for (const deviation of oracleAnalysis.deviations) {
            const thresholdValue = typeof rule.condition.value === 'number' ? rule.condition.value :
                typeof rule.condition.value === 'string' ? parseFloat(rule.condition.value) : 0;
            if (deviation.thresholdExceeded &&
                (rule.condition.value ? deviation.deviationPercent >= thresholdValue : true)) {
                return createAlertFromRule(rule, {}, [
                    {
                        type: 'price-deviation',
                        description: `${deviation.oracle} price for ${deviation.asset} deviated ${deviation.deviationPercent.toFixed(2)}% from expected`,
                        data: deviation
                    },
                    ...(oracleAnalysis.manipulationIndicators.map(mi => ({
                        type: 'custom',
                        description: `Manipulation indicator: ${mi.type}`,
                        data: mi
                    })))
                ]);
            }
        }
    }
    // Accounting invariant violations
    if (rule.category === 'accounting') {
        for (const diff of stateDiffs) {
            for (const slot of diff.slotChanges) {
                if (slot.anomaly?.detected && slot.anomaly.ruleId === rule.id) {
                    return createAlertFromRule(rule, {}, [
                        {
                            type: 'state-diff',
                            description: slot.anomaly.message,
                            data: slot.anomaly.context
                        }
                    ]);
                }
            }
        }
    }
    // Flash loan detection
    if (rule.category === 'flash-loan' && oracleAnalysis) {
        for (const indicator of oracleAnalysis.manipulationIndicators) {
            if (indicator.type === 'flash-loan-price-swing' && indicator.confidence > 0.7) {
                return createAlertFromRule(rule, {}, [
                    {
                        type: 'custom',
                        description: 'Flash loan attack pattern detected',
                        data: indicator
                    }
                ]);
            }
        }
    }
    return null;
}
/**
 * Evaluate Tier 3 rules (runtime behavior checks)
 */
function evaluateTier3Rule(rule, trace, stateDiffs) {
    // Gas anomaly checks
    if (rule.category === 'gas-griefing') {
        const totalGas = trace.gasInfo.gasUsed;
        const gasLimit = trace.transaction.gas;
        if (gasLimit > 0 && totalGas / gasLimit >= (rule.condition.value / 100)) {
            return createAlertFromRule(rule, trace.trace[0], [
                {
                    type: 'gas-anomaly',
                    description: `Transaction used ${(totalGas / gasLimit * 100).toFixed(1)}% of gas limit`,
                    data: { used: totalGas, limit: gasLimit, percentage: totalGas / gasLimit * 100 }
                }
            ]);
        }
    }
    // External call failure checks
    if (rule.category === 'external-call-failure') {
        for (const step of trace.trace) {
            if (step.status === 'error' || step.status === 'revert') {
                // Check if this was an external call failure
                if (step.depth > 0) { // External calls have depth > 0
                    return createAlertFromRule(rule, step, [
                        {
                            type: 'call-stack',
                            description: `External call to ${step.address} failed: ${step.error || 'Unknown error'}`,
                            data: { address: step.address, status: step.status, error: step.error }
                        }
                    ]);
                }
            }
        }
    }
    // Timestamp dependency checks
    if (rule.category === 'timestamp-dependency') {
        const usesTimestamp = detectTimestampUsage(trace);
        if (usesTimestamp) {
            return createAlertFromRule(rule, trace.trace[0], [
                {
                    type: 'timing',
                    description: 'Transaction uses block.timestamp for critical logic',
                    data: { timestamp: trace.timestamp }
                }
            ]);
        }
    }
    // Unexpected value changes
    if (rule.category === 'unexpected-value') {
        for (const diff of stateDiffs) {
            for (const slot of diff.slotChanges) {
                if (slot.deviation && slot.deviation > rule.condition.value) {
                    return createAlertFromRule(rule, {}, [
                        {
                            type: 'state-diff',
                            description: `Unexpected large change (${slot.deviation.toFixed(2)}%) in ${slot.slotLabel || slot.slot}`,
                            data: {
                                contract: diff.contractName,
                                variable: slot.slotLabel,
                                before: slot.decodedBefore || slot.beforeValue,
                                after: slot.decodedAfter || slot.afterValue,
                                deviation: slot.deviation
                            }
                        }
                    ]);
                }
            }
        }
    }
    return null;
}
/**
 * Create an Alert object from a triggered rule
 */
function createAlertFromRule(rule, step, evidence) {
    return {
        id: generateAlertId(),
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        title: `[${rule.severity.toUpperCase()}] ${rule.name}`,
        description: rule.description,
        location: {
            file: '', // Would need source map
            line: 0,
            contract: step.contractName || '',
            function: step.contractName || ''
        },
        evidence,
        suggestion: rule.mitigation || 'Review the code path that triggered this alert.',
        falsePositiveRisk: assessFalsePositiveRisk(rule, evidence),
        timestamp: Date.now(),
        stepIndex: step.stepIndex,
        suppressable: true
    };
}
/**
 * Assess false positive risk for an alert
 */
function assessFalsePositiveRisk(_rule, evidence) {
    // High confidence indicators
    if (evidence.some(e => e.type === 'price-deviation')) {
        return 'low'; // Price deviations are usually real issues
    }
    if (evidence.some(e => e.type === 'state-diff' && e.data?.deviation > 50)) {
        return 'low'; // Very large changes are suspicious
    }
    // Medium confidence
    if (evidence.length >= 2) {
        return 'medium';
    }
    // Single evidence items could be FPs
    return 'high';
}
// ============================================================
// PATTERN DETECTION FUNCTIONS
// ============================================================
function detectCEIViolation(step) {
    // Simplified CEI violation detection
    // Would need detailed opcode analysis in production
    if (!step.subcalls || step.subcalls.length === 0)
        return false;
    // Check if there are storage modifications followed by external calls
    let foundStorageChange = false;
    for (const subcall of step.subcalls) {
        if (subcall.storageAfter && Object.keys(subcall.storageAfter.slots).length > 0) {
            foundStorageChange = true;
        }
        // If we already had storage change and now see external call, flag it
        if (foundStorageChange && isExternalCall(subcall)) {
            return true;
        }
    }
    return false;
}
function isExternalCall(step) {
    // External calls typically go to different addresses with calldata
    return step.input && step.input !== '0x' && step.input.length > 10;
}
function detectDelegateCall(step) {
    // Check for DELEGATECALL opcode or pattern
    if (step.opcodes) {
        return step.opcodes.some(op => op.opcode === 'DELEGATECALL');
    }
    // Check input for delegate call patterns
    // This is very simplified
    return false;
}
function detectUnboundedLoop(_step) {
    // Would need loop detection via opcode analysis
    // For now, check gas usage as proxy for potential loops
    return false;
}
function detectTimestampUsage(_trace) {
    // Would need to check TIMESTAMP opcode usage
    return false;
}
// ============================================================
// ROLE JOURNEY TRACKING
// ============================================================
function trackRoleJourneys(trace) {
    const journeys = [];
    const actorMap = new Map();
    // Track msg.sender through execution
    const sender = trace.transaction.from;
    const journey = {
        actor: sender,
        role: determineInitialRole(sender),
        actions: [],
        permissionsChecked: [],
        privilegesEscalated: [],
        finalState: 'completed'
    };
    // Process each step to build action history
    processStepForJourney(trace.trace[0], journey, 0);
    journeys.push(journey);
    actorMap.set(sender, journey);
    return journeys;
}
function determineInitialRole(address) {
    // Simplified role determination
    if (address === '0x0000000000000000000000000000000000000000' ||
        address === '0x000000000000000000000000000000000000dead') {
        return 'system';
    }
    return 'external-caller';
}
function processStepForJourney(step, journey, depth) {
    if (!step)
        return;
    // Log action
    if (step.contractName) {
        journey.actions.push({
            order: journey.actions.length,
            function: step.contractName, // RoleAction.function can be string or string[]
            contract: step.address,
            success: step.status === 'success',
            stateImpact: step.storageAfter ? [Object.keys(step.storageAfter.slots).length.toString()] : ['none']
        });
    }
    // Check for permission checks (modifiers)
    if (step.input) {
        // This would need deeper analysis of require statements
        // For now, assume external calls might have permission checks
        if (depth > 0) {
            journey.permissionsChecked.push({
                function: step.contractName || 'unknown',
                required: 'unknown', // Would need modifier analysis
                hadPermission: step.status === 'success',
                bypassed: false
            });
        }
    }
    // Recurse into subcalls
    if (step.subcalls) {
        for (const subcall of step.subcalls) {
            processStepForJourney(subcall, journey, depth + 1);
        }
    }
}
// ============================================================
// SUMMARY GENERATION
// ============================================================
function generateAnalysisSummary(trace, stateDiffs, alerts, oracleAnalysis) {
    const stateSummary = (0, state_diff_engine_1.generateStateDiffSummary)(stateDiffs);
    // Count alerts by severity
    const alertCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        informational: 0
    };
    for (const alert of alerts) {
        alertCounts[alert.severity]++;
    }
    // Collect top anomalies
    const topAnomalies = [];
    for (const diff of stateDiffs) {
        for (const slot of diff.slotChanges) {
            if (slot.anomaly?.detected && topAnomalies.length < 5) {
                topAnomalies.push(slot.anomaly);
            }
        }
    }
    // Gas efficiency
    const gasEfficiency = {
        used: trace.gasInfo.gasUsed,
        limit: trace.transaction.gas,
        percentage: trace.transaction.gas > 0 ? (trace.gasInfo.gasUsed / trace.transaction.gas) * 100 : 0
    };
    // Determine verdict
    let verdict = 'pass';
    if (alertCounts.critical > 0) {
        verdict = 'fail';
    }
    else if (alertCounts.high > 0 || alertCounts.medium > 3) {
        verdict = 'warning';
    }
    else if (alerts.length > 0) {
        verdict = 'needs-review';
    }
    // Add oracle-specific concerns
    if (oracleAnalysis?.manipulationIndicators.length > 0) {
        verdict = verdict === 'pass' ? 'needs-review' : verdict;
    }
    return {
        totalSteps: trace.trace.length,
        totalContractsTouched: stateSummary.totalContractsTouched,
        totalStorageSlotsChanged: stateSummary.totalSlotsChanged,
        totalValueMoved: estimateValueMoved(stateDiffs), // Simplified
        alertCounts,
        topAnomalies,
        gasEfficiency,
        verdict
    };
}
function estimateValueMoved(_stateDiffs) {
    // Would need price feeds to convert token amounts to USD
    return 'Unknown (requires price feeds)';
}
function generateAlertId() {
    return `alert_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}
//# sourceMappingURL=alert-checker.js.map