/**
 * Trackator Tier 2: AI Enrichment Engine
 * ======================================
 * Ingests X-Ray and Breakdown reports, generates alert rules.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import {
  ProtocolStructure,
  XRayReport,
  BreakdownReport,
  AlertRule,
  Invariant,
  AnomalyPattern,
  ExpectedBehavior,
  AlertCondition,
  AlertSeverity,
  AlertCategory
} from '../types';

export class AIEnrichmentEngine {
  private structure: ProtocolStructure;
  private xRayReport?: XRayReport;
  private breakdownReport?: BreakdownReport;

  constructor(structure: ProtocolStructure) {
    this.structure = structure;
  }

  /**
   * Ingest X-Ray report (from file or object)
   */
  ingestXRay(xRayData: string | XRayReport): void {
    if (typeof xRayData === 'string') {
      const filePath = path.resolve(xRayData);
      if (!fs.existsSync(filePath)) {
        throw new Error(`X-Ray file not found: ${filePath}`);
      }
      
      // Parse markdown or JSON
      const content = fs.readFileSync(filePath, 'utf-8');
      if (filePath.endsWith('.json')) {
        this.xRayReport = JSON.parse(content);
      } else {
        // Parse structured markdown (simplified)
        this.xRayReport = this.parseXRayMarkdown(content);
      }
    } else {
      this.xRayReport = xRayData;
    }

    console.log(`✅ X-Ray ingested: ${this.xRayReport.protocolType} protocol detected`);
  }

  /**
   * Ingest Breakdown report (from file or object)
   */
  ingestBreakdown(breakdownData: string | BreakdownReport): void {
    if (typeof breakdownData === 'string') {
      const filePath = path.resolve(breakdownData);
      if (!fs.existsSync(filePath)) {
        throw new Error(`Breakdown file not found: ${filePath}`);
      }

      const content = fs.readFileSync(filePath, 'utf-8');
      if (filePath.endsWith('.json')) {
        this.breakdownReport = JSON.parse(content);
      } else {
        this.breakdownReport = this.parseBreakdownMarkdown(content);
      }
    } else {
      this.breakdownReport = breakdownData;
    }

    console.log(`✅ Breakdown ingested: ${this.breakdownReport?.components?.length || this.breakdownReport?.coreComponents?.length || 0} components analyzed`);
  }

  /**
   * Generate alert rules from X-Ray + Breakdown data
   */
  generateAlertRules(): AlertRule[] {
    const rules: AlertRule[] = [];
    
    if (!this.xRayReport && !this.breakdownReport) {
      console.warn('⚠️  No X-Ray/Breakdown data. Using default rules.');
      return this.generateDefaultRules();
    }

    // Rules from X-Ray invariants
    if (this.xRayReport) {
      rules.push(...this.generateInvariantRules());
      rules.push(...this.generateThreatBasedRules());
      rules.push(...this.generateTrustAssumptionRules());
    }

    // Rules from Breakdown expected behaviors
    if (this.breakdownReport) {
      rules.push(...this.generateExpectedBehaviorRules());
      rules.push(...this.generateRolePermissionRules());
    }

    console.log(`📋 Generated ${rules.length} alert rules`);
    return rules;
  }

  /**
   * Generate enriched protocol analysis
   */
  generateEnrichedAnalysis(): EnrichedAnalysis {
    const analysis: EnrichedAnalysis = {
      protocolType: this.xRayReport?.protocolType || 'Unknown',
      complexity: typeof this.xRayReport?.protocolClassification === 'string' 
        ? this.xRayReport.protocolClassification 
        : (this.xRayReport?.protocolClassification as any)?.complexity || 'medium',
      primaryAdversaries: (this.xRayReport?.threatModel?.primaryAdversaries || []).map(adv => ({
        type: adv.type,
        motivation: adv.goals?.[0] || 'unknown',
        likelihood: adv.likelyAttacks?.length > 0 ? 'high' : 'low'
      })),
      criticalInvariants: this.extractCriticalInvariants(),
      highRiskAreas: this.identifyHighRiskAreas(),
      rolePermissions: this.mapRolePermissions(),
      expectedBehaviors: this.extractExpectedBehaviors(),
      moneyFlows: this.structureMoneyFlows(),
      alertRules: this.generateAlertRules()
    };

    return analysis;
  }

  // ==================== RULE GENERATORS ====================

  private generateInvariantRules(): AlertRule[] {
    const rules: AlertRule[] = [];
    
    if (!this.xRayReport) return rules;

    let index = 0;
    for (const invariant of this.xRayReport.invariants) {
      rules.push({
        id: `INV-${String(++index).padStart(3, '0')}`,
        name: `${invariant.category}: ${invariant.description?.substring(0, 50) || 'Unnamed invariant'}`,
        source: `x-ray.md §Invariants`,
        tier: 'tier2',
        category: 'invariant-violation',
        condition: this.createConditionFromString(invariant.expression || invariant.instance || 'unknown'),
        severity: this.mapSeverity(invariant.severity),
        description: `Category: ${invariant.category}. Related functions: ${invariant.relatedFunctions?.join(', ') || 'unknown'}`,
        remediation: `Ensure invariant holds after every state change to affected variables.`,
        enabled: true
      });
    }

    return rules;
  }

  private generateThreatBasedRules(): AlertRule[] {
    const rules: AlertRule[] = [];

    const attackSurfaces = this.xRayReport?.threatModel?.attackSurfaces || 
                           this.xRayReport?.attackSurfaces;
    if (!attackSurfaces || attackSurfaces.length === 0) return rules;

    let index = 100;
    for (const surface of attackSurfaces) {
      const riskLevel = surface.riskLevel || surface.severity;
      if (riskLevel === 'critical' || riskLevel === 'high') {
        rules.push({
          id: `THREAT-${String(++index).padStart(3, '0')}`,
          name: `${surface.type} risk at ${surface.name || 'unknown'}`,
          source: `x-ray.md §Attack Surfaces`,
          tier: 'tier2',
          category: 'dangerous-pattern',
          condition: {
            type: 'pattern',
            field: `access_to_${(surface.name || '').toLowerCase().replace(/\s+/g, '_')}`,
            operator: 'contains',
            value: true
          },
          severity: riskLevel === 'critical' ? 'critical' : 'high',
          description: surface.description || '',
          remediation: Array.isArray((surface as any).mitigations) ? (surface as any).mitigations.join('; ') : 'Implement proper access controls.',
          enabled: true
        });
      }
    }

    return rules;
  }

  private generateTrustAssumptionRules(): AlertRule[] {
    const rules: AlertRule[] = [];

    if (!this.xRayReport?.trustAssumptions) return rules;

    let index = 200;
    for (const assumption of this.xRayReport.trustAssumptions) {
      const severity = assumption.severity || 'medium';
      if (severity === 'critical' || severity === 'high') {
        rules.push({
          id: `TRUST-${String(++index).padStart(3, '0')}`,
          name: `Trust assumption: ${assumption.assumption.substring(0, 40)}`,
          source: `x-ray.md §Trust Assumptions`,
          tier: 'tier2',
          category: 'anomaly',
          condition: {
            type: 'absence',
            field: `${assumption.category}_violation`,
            operator: 'eq',
            value: true
          },
          severity: severity as AlertSeverity,
          description: `If violated: ${assumption.ifViolated}`,
          remediation: `Add validation checks for this assumption.`,
          enabled: true
        });
      }
    }

    return rules;
  }

  private generateExpectedBehaviorRules(): AlertRule[] {
    const rules: AlertRule[] = [];

    if (!this.breakdownReport?.expectedBehaviors) return rules;

    let index = 300;
    for (const behavior of this.breakdownReport.expectedBehaviors) {
      const anomalies = behavior.anomaliesToDetect || [];
      for (const anomaly of anomalies) {
        rules.push({
          id: `BEHAV-${String(++index).padStart(3, '0')}`,
          name: anomaly.name,
          source: `breakdown.md §${behavior.scenario || behavior.functionSig || 'unknown'}`,
          tier: 'tier2',
          category: 'anomaly',
          condition: anomaly.detectionLogic || {
            type: 'pattern',
            field: anomaly.name.toLowerCase().replace(/\s+/g, '_'),
            operator: 'not-contains',
            value: true
          },
          severity: anomaly.severity as AlertSeverity,
          description: anomaly.description || '',
          remediation: `Check for ${anomaly.name} pattern during execution.`,
          enabled: true
        });
      }
    }

    return rules;
  }

  private generateRolePermissionRules(): AlertRule[] {
    const rules: AlertRule[] = [];

    const rolePermissions = this.breakdownReport?.rolePermissions;
    if (!rolePermissions || rolePermissions.length === 0) return rules;

    let index = 400;
    for (const rolePerm of rolePermissions) {
      const damagePotential = rolePerm.damagePotential || 'low';
      if (typeof damagePotential === 'string' && (
          damagePotential.includes('drain') || 
          damagePotential.includes('critical') ||
          damagePotential === 'high'
      )) {
        rules.push({
          id: `ROLE-${String(++index).padStart(3, '0')}`,
          name: `High-damage role: ${rolePerm.role}`,
          source: `breakdown.md §Role Permissions`,
          tier: 'tier2',
          category: 'access-breach',
          condition: {
            type: 'presence',
            field: `unauthorized_${rolePerm.role.toLowerCase()}_access`,
            operator: 'eq',
            value: false
          },
          severity: 'critical',
          description: `Damage potential: ${String(damagePotential)}. Permissions: ${rolePerm.permissions?.join(', ') || 'unknown'}`,
          remediation: `Ensure proper multisig/timelock for ${rolePerm.role} functions.`,
          enabled: true
        });
      }
    }

    return rules;
  }

  private generateDefaultRules(): AlertRule[] {
    return [
      {
        id: 'DEF-001',
        name: 'Unexpected state variable change',
        source: 'Default rules',
        tier: 'tier1',
        category: 'anomaly',
        condition: { type: 'threshold', field: 'delta_percent', operator: 'gt', value: 10 },
        severity: 'medium',
        description: 'Detect large unexpected state changes',
        enabled: true
      },
      {
        id: 'DEF-002',
        name: 'Access control bypass attempt',
        source: 'Default rules',
        tier: 'tier1',
        category: 'access-breach',
        condition: { type: 'pattern', field: 'caller_role_check', operator: 'neq', value: 'expected' },
        severity: 'high',
        description: 'Detect unauthorized function calls',
        enabled: true
      },
      {
        id: 'DEF-003',
        name: 'Reentrancy pattern detected',
        source: 'Default rules',
        tier: 'tier1',
        category: 'reentrancy',
        condition: { type: 'sequence', field: 'external_call_state_update', operator: 'in-sequence', window: 1 },
        severity: 'critical',
        description: 'Potential CEI violation',
        enabled: true
      },
      {
        id: 'DEF-004',
        name: 'Oracle price deviation',
        source: 'Default rules',
        tier: 'tier1',
        category: 'price-deviation',
        condition: { type: 'threshold', field: 'price_deviation_pct', operator: 'gt', value: 5 },
        severity: 'high',
        description: 'Price deviation exceeds 5% threshold',
        enabled: true
      },
      {
        id: 'DEF-005',
        name: 'Balance inconsistency',
        source: 'Default rules',
        tier: 'tier1',
        category: 'accounting',
        condition: { type: 'custom', field: 'sum_balances_vs_supply', operator: 'eq', value: false },
        severity: 'critical',
        description: 'Accounting invariant violated',
        enabled: true
      }
    ];
  }

  // ==================== ANALYSIS HELPERS ====================

  private extractCriticalInvariants(): Invariant[] {
    if (!this.xRayReport) return [];

    return this.xRayReport.invariants
      .filter(inv => inv.severity === 'critical' || inv.severity === 'high')
      .slice(0, 10); // Top 10 most critical
  }

  private identifyHighRiskAreas(): HighRiskArea[] {
    const areas: HighRiskArea[] = [];

    // From X-Ray attack surfaces
    const attackSurfaces = this.xRayReport?.attackSurfaces || 
                          this.xRayReport?.threatModel?.attackSurfaces;
    if (attackSurfaces && attackSurfaces.length > 0) {
      for (const surface of attackSurfaces) {
        const riskLevel = surface.riskLevel || surface.severity;
        if (riskLevel === 'critical' || riskLevel === 'high') {
          areas.push({
            location: surface.name || 'unknown',
            type: surface.type || 'unknown',
            description: surface.description || '',
            riskLevel: riskLevel
          });
        }
      }
    }

    // From structure analysis (unprotected functions)
    const ac = (this.structure as any).accessControl;
    if (ac && (ac.unprotectedFunctions?.length ?? 0) > 3) {
      areas.push({
        location: 'Multiple contracts',
        type: 'Missing Access Control',
        description: `${ac.unprotectedFunctions.length} functions lack explicit access control`,
        riskLevel: ac.unprotectedFunctions.length > 10 ? 'high' : 'medium'
      });
    }

    // Dangerous patterns from external calls
    const ecm = (this.structure as any).externalCallMap;
    if (ecm?.dangerousPatterns) {
      for (const pattern of ecm.dangerousPatterns) {
        areas.push({
          location: `${pattern.contract}:${pattern.line || pattern.function || 'unknown'}`,
          type: pattern.type || pattern.name || 'unknown',
          description: pattern.description || '',
          riskLevel: pattern.severity || 'medium'
        });
      }
    }

    return areas;
  }

  private mapRolePermissions(): RolePermissionSummary[] {
    const permissions: RolePermissionSummary[] = [];

    const rolePermissions = this.breakdownReport?.rolePermissions;
    if (rolePermissions && rolePermissions.length > 0) {
      for (const rp of rolePermissions) {
        permissions.push({
          role: rp.role,
          functionsCount: rp.permissions?.length || 0,
          damagePotential: String(rp.damagePotential || 'low'),
          constraints: rp.constraints || [],
          transferability: rp.canEscalate ? 'escalatable' : 'fixed'
        });
      }
    } else {
      // From structure analysis
      const ac = (this.structure as any).accessControl;
      const roles = ac?.roles || [];
      for (const role of roles) {
        permissions.push({
          role: role.name || role.role || 'unknown',
          functionsCount: role.functions?.length || role.permissions?.length || 0,
          damagePotential: role.trustLevel === 'critical' ? 'Can drain funds' :
                         role.trustLevel === 'high' ? 'Significant impact' : 'Limited scope',
          constraints: role.constraints || [],
          transferability: 'Unknown'
        });
      }
    }

    return permissions;
  }

  private extractExpectedBehaviors(): ExpectedBehaviorSummary[] {
    if (!this.breakdownReport?.expectedBehaviors) return [];

    return this.breakdownReport.expectedBehaviors.map(eb => ({
      scenario: eb.scenario || eb.functionSig || 'unknown',
      preConditions: eb.preConditions || [],
      expectedOutcome: eb.expectedOutcome || eb.postConditions?.join('; ') || '',
      anomaliesToWatch: (eb.anomaliesToDetect || []).map(a => a.name)
    }));
  }

  private structureMoneyFlows(): MoneyFlowSummary[] {
    // Basic flow extraction from contract structure
    const flows: MoneyFlowSummary[] = [];

    const contracts = (this.structure as any).contracts || [this.structure];
    for (const contract of contracts) {
      const functions = contract.functions || contract.contractFunctions || [];
      for (const func of functions) {
        // Detect transfer patterns
        const externalCalls = func.externalCalls || func.externalCallInfos || [];
        const hasTransfer = externalCalls.some((c: any) => 
          c.isSendOrTransfer || c.isSend || c.functionName?.toLowerCase() === 'transfer' || c.name?.toLowerCase() === 'transfer'
        );

        if (hasTransfer) {
          flows.push({
            function: `${contract.name || contract.contractName || 'unknown'}.${func.name || func.functionName || 'unknown'}`,
            direction: this.inferTransferDirection(func),
            assetType: 'ERC20/ETH', // Would need deeper analysis
            conditions: func.modifiers || []
          });
        }
      }
    }

    return flows;
  }

  private inferTransferDirection(func: any): string {
    const nameLower = (func.name || func.functionName || '').toLowerCase();
    if (nameLower.includes('deposit') || nameLower.includes('mint') || nameLower.includes('supply')) {
      return 'inflow';
    }
    if (nameLower.includes('withdraw') || nameLower.includes('burn') || nameLower.includes('redeem')) {
      return 'outflow';
    }
    if (nameLower.includes('transfer') || nameLower.includes('send')) {
      return 'internal';
    }
    return 'unknown';
  }

  // ==================== HELPERS ====================

  private createConditionFromString(expr: string): AlertCondition {
    // Try to parse expression into structured condition
    // Default to custom type for complex expressions
    return {
      type: 'custom',
      field: expr.substring(0, 50),
      operator: 'eq',
      value: true
    };
  }

  private mapSeverity(severity: string): AlertSeverity {
    const severityMap: Record<string, AlertSeverity> = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'informational': 'info',
      'info': 'info'
    };
    return severityMap[severity] || 'medium';
  }

  // ==================== PARSERS ====================

  private parseXRayMarkdown(content: string): XRayReport {
    // Simplified parser - real implementation would use proper MD parsing
    const protocolMatch = content.match(/Protocol Type:\s*(\w+)/i);
    const complexityMatch = content.match(/Complexity:\s*(\w+)/i);

    return {
      protocolType: protocolMatch?.[1] || 'Unknown',
      protocolClassification: complexityMatch?.[1] || 'medium',
      threatModel: {
        assetsAtRisk: [],
        entryPoints: [],
        privilegeBoundaries: [],
        keyActors: [],
        primaryAdversaries: [],
        attackSurfaces: []
      },
      invariants: this.extractInvariantsFromMD(content),
      trustAssumptions: [],
      adversaryProfiles: [],
      attackVectors: [],
      attackSurfaces: [],
      generatedAt: new Date().toISOString()
    };
  }

  private parseBreakdownMarkdown(content: string): BreakdownReport {
    // Simplified parser
    return {
      components: [],
      coreComponents: [],
      moneyFlows: [],
      numericBehaviors: [],
      stateAuthority: [],
      expectedBehaviors: this.extractExpectedBehaviorsFromMD(content),
      rolePermissions: [],
      generatedAt: new Date().toISOString()
    };
  }

  private extractInvariantsFromMD(content: string): Invariant[] {
    const invariants: Invariant[] = [];
    const regex = /(?:^|\n)[-*]\s*\*\*(INV-\d+)?\**\s*(.+?)(?:\n|$)/gi;
    let match;
    let index = 0;

    while ((match = regex.exec(content)) !== null) {
      const text = match[2].trim();
      if (text.toLowerCase().includes('invariant') || 
          text.toLowerCase().includes('must') ||
          text.toLowerCase().includes('should always')) {
        invariants.push({
          id: `INV-${String(++index).padStart(3, '0')}`,
          category: 'accounting',
          protocolType: 'unknown',
          template: text.substring(0, 100),
          instance: text,
          severity: text.toLowerCase().includes('never') || text.toLowerCase().includes('must') ? 'critical' : 'high',
          checkable: true,
          relatedStateVars: [],
          relatedFunctions: [],
          description: text.substring(0, 200),
          expression: text,
          triggerCondition: {
            type: 'custom',
            field: 'state_change',
            operator: 'changed',
            value: true
          }
        });
      }
    }

    return invariants.slice(0, 20); // Limit
  }

  private extractExpectedBehaviorsFromMD(content: string): ExpectedBehavior[] {
    // Simplified extraction
    return [
      {
        functionSig: 'standard_operations',
        preConditions: ['Valid inputs', 'Sufficient balance'],
        postConditions: ['State updated correctly'],
        stateChanges: [],
        revertConditions: [],
        scenario: 'Standard operations',
        expectedOutcome: 'State updated correctly',
        stepByStep: [],
        anomaliesToDetect: [
          { id: 'ANOM-001', name: 'Unexpected state change', description: '', detectionLogic: { type: 'custom', field: 'state_change', operator: 'changed', value: true }, severity: 'medium', category: 'anomaly' } as AnomalyPattern
        ]
      }
    ];
  }

  /**
   * Export alert rules to YAML file
   */
  exportAlertRules(rules: AlertRule[], outputPath: string): void {
    const yamlContent = yaml.dump(
      { alert_rules: rules },
      { indent: 2, lineWidth: 120 }
    );
    
    fs.writeFileSync(outputPath, yamlContent, 'utf-8');
    console.log(`✅ Alert rules exported: ${outputPath}`);
  }
}

// Additional types for enriched output
interface EnrichedAnalysis {
  protocolType: string;
  complexity: string;
  primaryAdversaries: Array<{ type: string; motivation: string; likelihood: string }>;
  criticalInvariants: Invariant[];
  highRiskAreas: HighRiskArea[];
  rolePermissions: RolePermissionSummary[];
  expectedBehaviors: ExpectedBehaviorSummary[];
  moneyFlows: MoneyFlowSummary[];
  alertRules: AlertRule[];
}

interface HighRiskArea {
  location: string;
  type: string;
  description: string;
  riskLevel: string;
}

interface RolePermissionSummary {
  role: string;
  functionsCount: number;
  damagePotential: string;
  constraints: string[];
  transferability: string;
}

interface ExpectedBehaviorSummary {
  scenario: string;
  preConditions: string[];
  expectedOutcome: string;
  anomaliesToWatch: string[];
}

interface MoneyFlowSummary {
  function: string;
  direction: string;
  assetType: string;
  conditions: string[];
}

export default AIEnrichmentEngine;
