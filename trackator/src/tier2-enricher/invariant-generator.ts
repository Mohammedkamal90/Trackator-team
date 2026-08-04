// ============================================================
// TRACKATOR Tier 2 - Invariant Generator & Alert Rule Builder
// Combines X-Ray and Breakdown data to generate alert rules
// ============================================================

import {
  XRayOutput,
  BreakdownOutput,
  Invariant,
  AlertRule,
  AlertCategory,
  AlertSeverity,
  AlertCondition,
  ProtocolType,
  SolidityContract,
  FunctionDef,
  RegisteredFunction
} from '../types';
import { ingestXRay } from './xray-ingestor';
import { ingestBreakdown } from './breakdown-ingestor';

export interface EnrichmentOptions {
  xrayFile?: string;
  breakdownFile?: string;
  protocolType?: ProtocolType;
  contracts?: SolidityContract[];
  registry?: Map<string, RegisteredFunction[]>;
  generateAlerts?: boolean;
  verbose?: boolean;
}

export interface EnrichmentResult {
  xray: XRayOutput;
  breakdown: BreakdownOutput;
  invariants: Invariant[];
  alertRules: AlertRule[];
  generatedAt: string;
}

/**
 * Main entry point for Tier 2 enrichment
 */
export function runEnrichment(options: EnrichmentOptions): EnrichmentResult {
  const {
    xrayFile,
    breakdownFile,
    protocolType,
    contracts = [],
    registry,
    generateAlerts = true,
    verbose = false
  } = options;
  
  if (verbose) console.log('Starting Tier 2 enrichment...');
  
  // Step 1: Ingest X-Ray data
  const xray = ingestXRay({
    xrayFile,
    protocolType,
    contracts,
    verbose
  });
  
  if (verbose) console.log(`X-Ray loaded: ${xray.protocolType} protocol, ${xray.invariants.length} invariants`);
  
  // Step 2: Ingest Breakdown data
  const breakdown = ingestBreakdown({
    breakdownFile,
    contracts,
    verbose
  });
  
  if (verbose) console.log(`Breakdown loaded: ${breakdown.components.length} components, ${breakdown.moneyFlows.length} flows`);
  
  // Step 3: Merge and enhance invariants
  const mergedInvariants = mergeInvariants(xray, breakdown);
  
  // Step 4: Generate alert rules
  let alertRules: AlertRule[] = [];
  if (generateAlerts) {
    alertRules = generateAlertRules(xray, breakdown, mergedInvariants, registry);
    
    if (verbose) console.log(`Generated ${alertRules.length} alert rules`);
  }
  
  return {
    xray,
    breakdown,
    invariants: mergedInvariants,
    alertRules,
    generatedAt: new Date().toISOString()
  };
}

/**
 * Merge invariants from X-Ray and Breakdown, removing duplicates
 */
function mergeInvariants(xray: XRayOutput, breakdown: BreakdownOutput): Invariant[] {
  const invariantMap = new Map<string, Invariant>();
  
  // Add X-Ray invariants
  for (const inv of xray.invariants) {
    invariantMap.set(inv.id, inv);
  }
  
  // Generate additional invariants from Breakdown numeric behaviors
  for (const nb of breakdown.numericBehaviors) {
    const id = `INV_NB_${nb.variable.toUpperCase()}`;
    
    if (!invariantMap.has(id)) {
      invariantMap.set(id, {
        id,
        category: 'bounds',
        protocolType: xray.protocolType,
        template: `${nb.variable} must stay within expected range`,
        instance: `${nb.expectedRange.min} <= ${nb.variable} <= ${nb.expectedRange.max}`,
        severity: 'high' as const,
        checkable: true,
        expression: `${nb.variable} >= ${nb.expectedRange.min} && ${nb.variable} <= ${nb.expectedRange.max}`,
        relatedStateVars: [nb.variable],
        relatedFunctions: []
      });
    }
  }
  
  // Generate invariants from state authority analysis
  for (const sa of breakdown.stateAuthority) {
    const id = `INV_AUTH_${sa.variable.toUpperCase()}`;
    
    if (!invariantMap.has(id)) {
      invariantMap.set(id, {
        id,
        category: 'permission',
        protocolType: xray.protocolType,
        template: `${sa.variable} must only be modified by authorized functions`,
        instance: `${sa.whoCanWrite.join(' OR ')}`,
        severity: sa.validationPresent ? 'medium' : 'high',
        checkable: false, // Hard to check at runtime without deep instrumentation
        expression: null,
        relatedStateVars: [sa.variable],
        relatedFunctions: sa.whoCanWrite.map(w => w.split(' ')[0])
      });
    }
  }
  
  return Array.from(invariantMap.values());
}

/**
 * Generate alert rules from X-Ray threats and Breakdown behaviors
 */
function generateAlertRules(
  xray: XRayOutput,
  breakdown: BreakdownOutput,
  invariants: Invariant[],
  registry?: Map<string, RegisteredFunction[]>
): AlertRule[] {
  const rules: AlertRule[] = [];
  let ruleCounter = 1;
  
  // ========================================
  // TIER 1 RULES: From static analysis patterns
  // ========================================
  
  // CEI Violation Rules
  rules.push({
    id: `ALERT_${ruleCounter++}`,
    name: 'CEI Pattern Violation - Potential Reentrancy',
    tier: 'tier1',
    category: 'reentrancy',
    severity: 'critical',
    condition: {
      type: 'pattern',
      field: 'ceiPattern',
      operator: 'eq',
      value: 'violated'
    },
    description: 'Function has external calls after state modifications, violating Checks-Effects-Interactions pattern. This is a strong indicator of potential reentrancy vulnerability.',
    mitigation: 'Reorder operations to perform all external calls after all state updates, or use reentrancy guards.',
    source: 'runtime',
    enabled: true
  });
  
  // Missing Access Control Rules
  rules.push({
    id: `ALERT_${ruleCounter++}`,
    name: 'Missing Access Control on State-Changing Function',
    tier: 'tier1',
    category: 'access-control',
    severity: 'critical',
    condition: {
      type: 'absence',
      field: 'modifiers',
      operator: 'not-contains',
      value: 'onlyOwner|onlyRole|require'
    },
    description: 'Public/external function modifies state but lacks explicit access control modifier.',
    mitigation: 'Add appropriate access control modifiers based on intended permissions.',
    source: 'runtime',
    enabled: true
  });
  
  // DelegateCall Usage
  rules.push({
    id: `ALERT_${ruleCounter++}`,
    name: 'DelegateCall Detected - Execution Context Forwarding',
    tier: 'tier1',
    category: 'access-control',
    severity: 'critical',
    condition: {
      type: 'presence',
      field: 'hasDelegateCall',
      operator: 'eq',
      value: true
    },
    description: 'Function uses delegatecall which forwards execution context including storage. Malicious target contract can compromise entire contract.',
    mitigation: 'Ensure delegatecall target is trusted, immutable, or governed by robust access control.',
    source: 'runtime',
    enabled: true
  });
  
  // Unbounded Loop Detection
  rules.push({
    id: `ALERT_${ruleCounter++}`,
    name: 'Unbounded Loop - Potential DoS Risk',
    tier: 'tier1',
    category: 'denial-of-service',
    severity: 'medium',
    condition: {
      type: 'presence',
      field: 'hasLoop',
      operator: 'eq',
      value: true
    },
    description: 'Function contains loop that may iterate over unbounded data structures. Could exceed block gas limit with sufficient data.',
    mitigation: 'Add iteration limits, use pagination, or move loop logic off-chain.',
    source: 'runtime',
    enabled: true
  });
  
  // ========================================
  // TIER 2 RULES: From X-Ray threat model
  // ========================================
  
  // Oracle Manipulation Rules
  if (xray.protocolType === 'lending' || xray.protocolType === 'dex') {
    rules.push({
      id: `ALERT_${ruleCounter++}`,
      name: 'Oracle Price Deviation Exceeds Threshold',
      tier: 'tier2',
      category: 'oracle-manipulation',
      severity: 'critical',
      condition: {
        type: 'threshold',
        field: 'priceDeviationPercent',
        operator: 'gte',
        value: 5, // 5% threshold
        secondaryField: 'expectedPrice'
      },
      description: 'Observed oracle price deviates more than 5% from expected/TWAP price. Possible manipulation attempt.',
      mitigation: 'Use TWAP oracles, implement circuit breakers, add flash loan detection.',
      source: 'xray',
      enabled: true
    });
  }
  
  // Accounting Invariant Violations
  for (const inv of invariants.filter(i => i.category === 'accounting')) {
    rules.push({
      id: `ALERT_${ruleCounter++}`,
      name: `Accounting Invariant Violation: ${inv.template.substring(0, 50)}...`,
      tier: 'tier2',
      category: 'accounting',
      severity: inv.severity,
      condition: {
        type: 'custom',
        field: inv.expression || inv.instance,
        operator: 'not-contains', // Simplified
        value: 'valid'
      },
      description: inv.instance || inv.template,
      mitigation: 'Review transaction that caused accounting inconsistency. May indicate fund leakage or calculation error.',
      source: 'xray',
      enabled: inv.checkable
    });
  }
  
  // Flash Loan Detection
  for (const threat of xray.attackVectors.filter(t => t.category === 'flash-loan')) {
    rules.push({
      id: `ALERT_${ruleCounter++}`,
      name: `Flash Loan Attack Pattern: ${threat.name}`,
      tier: 'tier2',
      category: 'flash-loan',
      severity: threat.severity,
      condition: {
        type: 'sequence',
        field: 'balanceChanges',
        operator: 'in-sequence',
        value: ['large_deposit', 'manipulation_action', 'large_withdraw'] as any
      },
      description: threat.impact,
      mitigation: threat.detectionMethod || 'Implement flash loan detection checks.',
      source: 'xray',
      enabled: true
    });
  }
  
  // ========================================
  // TIER 2 RULES: From Breakdown behavioral analysis
  // ========================================
  
  // Numeric Anomaly Detection
  for (const nb of breakdown.numericBehaviors) {
    rules.push({
      id: `ALERT_${ruleCounter++}`,
      name: `Anomalous Change in ${nb.variable}`,
      tier: 'tier2',
      category: 'unexpected-value',
      severity: 'medium',
      condition: {
        type: 'threshold',
        field: `${nb.contract}.${nb.variable}`,
        operator: 'gt',
        value: nb.anomalyThreshold
      },
      description: `${nb.variable} changed by more than ${nb.anomalyThreshold}% from previous value. Expected behavior: ${nb.normalPattern}`,
      mitigation: 'Verify this change is legitimate. Check for manipulation or bugs.',
      source: 'breakdown',
      enabled: true
    });
  }
  
  // ERC4626 Share Inflation (Vault-specific)
  if (xray.protocolType === 'vault') {
    rules.push({
      id: `ALERT_${ruleCounter++}`,
      name: 'Potential Share Inflation Attack (ERC4626)',
      tier: 'tier2',
      category: 'share-inflation',
      severity: 'high',
      condition: {
        type: 'threshold',
        field: 'shareToAssetRatio',
        operator: 'lt',
        value: 0.99, // 1% deviation threshold
        secondaryField: 'previousShareToAssetRatio'
      },
      description: 'Share-to-asset ratio decreased significantly, indicating possible share inflation attack via donation or rounding exploits.',
      mitigation: 'Implement share inflation protection mechanisms. Consider using wrapped version.',
      source: 'xray',
      enabled: true
    });
  }
  
  // Bridge-specific Rules
  if (xray.protocolType === 'bridge') {
    rules.push({
      id: `ALERT_${ruleCounter++}`,
      name: 'Bridge Message Replay Detected',
      tier: 'tier2',
      category: 'logic-error',
      severity: 'critical',
      condition: {
        type: 'presence',
        field: 'nonceReuse',
        operator: 'eq',
        value: true
      },
      description: 'Same nonce being used for multiple message executions. Indicates replay attack or nonce handling bug.',
      mitigation: 'Ensure nonces are strictly incrementing and checked before execution.',
      source: 'xray',
      enabled: true
    });
  }
  
  // ========================================
  // TIER 3 RULES: Runtime detection rules
  // ========================================
  
  // Gas Anomaly Detection
  rules.push({
    id: `ALERT_${ruleCounter++}`,
    name: 'Unusual Gas Consumption Pattern',
    tier: 'tier3',
    category: 'gas-griefing',
    severity: 'low',
    condition: {
      type: 'threshold',
      field: 'gasUsed',
      operator: 'gte',
      value: 0.9 // 90% of gas limit
    },
    description: 'Transaction consumed unusually high percentage of gas limit. Could indicate griefing attack or infinite loop.',
    mitigation: 'Monitor for repeated high-gas transactions from same address.',
    source: 'runtime',
    enabled: true
  });
  
  // External Call Failure
  rules.push({
    id: `ALERT_${ruleCounter++}`,
    name: 'External Call Failed Silently',
    tier: 'tier3',
    category: 'external-call-failure',
    severity: 'medium',
    condition: {
      type: 'presence',
      field: 'failedExternalCall',
      operator: 'eq',
      value: true
    },
    description: 'External call returned false but execution continued. May lead to inconsistent state.',
    mitigation: 'Check return values of external calls and revert on failure.',
    source: 'runtime',
    enabled: true
  });
  
  // Timestamp Dependency
  rules.push({
    id: `ALERT_${ruleCounter++}`,
    name: 'Timestamp-Dependent Logic Detected',
    tier: 'tier3',
    category: 'timestamp-dependency',
    severity: 'low',
    condition: {
      type: 'presence',
      field: 'usesBlockTimestamp',
      operator: 'eq',
      value: true
    },
    description: 'Function uses block.timestamp for critical logic. Miners can manipulate this value slightly.',
    mitigation: 'Avoid timestamp dependency for critical calculations or use wider time windows.',
    source: 'runtime',
    enabled: true
  });
  
  // Enhance rules with function-specific context from registry
  if (registry) {
    enhanceRulesWithRegistry(rules, registry);
  }
  
  return rules;
}

/**
 * Enhance alert rules with specific function information from registry
 */
function enhanceRulesWithRegistry(
  rules: AlertRule[],
  registry: Map<string, RegisteredFunction[]>
): void {
  // Find high-risk functions and create specific alerts
  // Cast to any to handle extended RegisteredFunction shape from function-registry
  for (const [, funcs] of registry) {
    for (const func of funcs as any[]) {
      // Create specific alerts for critical-risk functions
      if (func.risk?.overall === 'critical') {
        const funcName = func.function?.name || func.name || 'unknown';
        const funcDef = func.function || {};
        const body = func.body || {};
        const existingAlert = rules.find(r =>
          r.name.includes(funcName) &&
          r.category === 'reentrancy'
        );
        
        if (!existingAlert && body.ceiPattern === 'violated') {
          const riskFactors = func.risk?.factors || [];
          rules.push({
            id: `ALERT_FUNC_${func.contract}_${funcName}`,
            name: `Critical: ${func.contract}.${funcName}() has CEI violation`,
            tier: 'tier1',
            category: 'reentrancy',
            severity: 'critical',
            condition: {
              type: 'pattern',
              field: 'functionCalled',
              operator: 'eq',
              value: `${func.contract}.${funcName}`
            } as AlertCondition,
            description: `High-risk function ${funcName}() violates CEI pattern. Risk factors: ${riskFactors.map((f: any) => f.type).join(', ')}.`,
            mitigation: riskFactors[0]?.mitigated ? 'Partially mitigated - review further' : 'Immediate remediation required',
            source: 'custom',
            enabled: true
          });
        }
      }
      
      // Add alerts for missing access control
      const accessControl = func.accessControl || {};
      const stateImpact = func.stateImpact || {};
      const funcDef = func.function || {};
      
      if (accessControl.mechanism === 'none' &&
          funcDef.stateMutability !== 'view' &&
          funcDef.stateMutability !== 'pure') {
        const funcName = funcDef.name || func.name || 'unknown';
        const writes = stateImpact.writes || func.stateWrites || [];
        rules.push({
          id: `ALERT_AC_${func.contract}_${funcName}`,
          name: `No Access Control: ${func.contract}.${funcName}()`,
          tier: 'tier1',
          category: 'access-control',
          severity: stateImpact.transfers || stateImpact.mints ? 'high' : 'medium',
          condition: {
            type: 'pattern',
            field: 'functionCalled',
            operator: 'eq',
            value: `${func.contract}.${funcName}`
          } as AlertCondition,
          description: `Function ${funcName}() is ${funcDef.visibility}, modifies state (${writes.length} vars), but has no access control.`,
          mitigation: `Add appropriate access control modifier (onlyOwner, onlyRole, etc.)`,
            source: 'custom',
          enabled: true
        });
      }
    }
  }
}

/**
 * Get alert rules filtered by severity
 */
export function getAlertRulesBySeverity(
  rules: AlertRule[],
  minSeverity: AlertSeverity = 'info'
): AlertRule[] {
  const severityOrder: Partial<Record<AlertSeverity, number>> = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'info': 1,
    'informational': 0
  };
  
  const minOrder = severityOrder[minSeverity] || 0;
  
  return rules.filter(r => 
    r.enabled && (severityOrder[r.severity] || 0) >= minOrder
  );
}

/**
 * Get alert rules by category
 */
export function getAlertRulesByCategory(
  rules: AlertRule[],
  category: AlertCategory
): AlertRule[] {
  return rules.filter(r => r.enabled && r.category === category);
}

/**
 * Export enrichment result to JSON-serializable format
 */
export function exportEnrichmentResult(result: EnrichmentResult): any {
  return {
    xray: result.xray,
    breakdown: result.breakdown,
    invariants: result.invariants,
    alertRules: result.alertRules,
    generatedAt: result.generatedAt,
    summary: {
      protocolType: result.xray.protocolType,
      totalInvariants: result.invariants.length,
      totalAlertRules: result.alertRules.length,
      enabledAlertRules: result.alertRules.filter(r => r.enabled).length,
      criticalAlerts: result.alertRules.filter(r => r.severity === 'critical').length,
      highAlerts: result.alertRules.filter(r => r.severity === 'high').length
    }
  };
}
