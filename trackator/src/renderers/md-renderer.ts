// ============================================================
// TRACKATOR Tier 3 - Markdown Renderer
// Generates .md files with Mermaid diagrams and tables
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import {
  FoundryTrace,
  TraceStep,
  StateDiff,
  Alert,
  OracleAnalysis,
  AnalysisSummary,
  RoleJourney,
  TrackatorOutput
} from '../types';

export interface MarkdownRenderOptions {
  includeMermaid?: boolean;
  includeDetails?: boolean;
  maxAlerts?: number;
}

/**
 * Generate markdown report for analysis results
 */
export function generateMarkdownReport(
  outputDir: string,
  trace: FoundryTrace,
  stateDiffs: StateDiff[],
  alerts: Alert[],
  oracleAnalysis?: OracleAnalysis,
  roleJourneys?: RoleJourney[],
  summary?: AnalysisSummary,
  options: MarkdownRenderOptions = {}
): string {
  const {
    includeMermaid = true,
    includeDetails = true,
    maxAlerts = 50
  } = options;
  
  let md = '';
  
  // Header
  md += '# Trackator Runtime Analysis Report\n\n';
  md += `**Generated:** ${new Date().toISOString()}\n`;
  md += `**Transaction:** ${trace.transaction.from} → ${trace.transaction.to || 'Contract Creation'}\n\n`;
  
  // Table of Contents
  md += '## Table of Contents\n\n';
  md += '- [Executive Summary](#executive-summary)\n';
  md += '- [Transaction Details](#transaction-details)\n';
  md += '- [Execution Flow](#execution-flow)\n';
  md += '- [State Changes](#state-changes)\n';
  md += '- [Alerts](#alerts)\n';
  if (oracleAnalysis) md += '- [Oracle Analysis](#oracle-analysis)\n';
  if (roleJourneys?.length) md += '- [Role Journeys](#role-journeys)\n';
  md += '- [Verdict](#verdict)\n\n';
  
  // Executive Summary
  md += '## Executive Summary\n\n';
  md += generateExecutiveSummary(summary, alerts);
  
  // Transaction Details
  md += '## Transaction Details\n\n';
  md += generateTransactionTable(trace);
  
  // Execution Flow
  md += '## Execution Flow\n\n';
  if (includeMermaid) {
    md += generateExecutionMermaid(trace);
  }
  md += generateExecutionList(trace);
  
  // State Changes
  md += '## State Changes\n\n';
  md += generateStateChangesSection(stateDiffs, includeDetails);
  
  // Alerts
  md += '## Alerts\n\n';
  md += generateAlertsSection(alerts, maxAlerts);
  
  // Oracle Analysis
  if (oracleAnalysis) {
    md += '\n## Oracle Analysis\n\n';
    md += generateOracleSection(oracleAnalysis);
  }
  
  // Role Journeys
  if (roleJourneys && roleJourneys.length > 0) {
    md += '\n## Role Journeys\n\n';
    md += generateRoleJourneysSection(roleJourneys);
  }
  
  // Verdict
  md += '\n## Verdict\n\n';
  md += generateVerdictSection(summary, alerts);
  
  return md;
}

function generateExecutiveSummary(summary: AnalysisSummary | undefined, alerts: Alert[]): string {
  let md = '';
  
  if (!summary) {
    md += '*No summary available.*\n\n';
    return md;
  }
  
  md += '| Metric | Value |\n';
  md += '|--------|-------|\n';
  md += '| **Verdict** | **' + summary.verdict.toUpperCase() + '** |\n';
  md += '| Total Steps | ' + summary.totalSteps + ' |\n';
  md += '| Contracts Touched | ' + summary.totalContractsTouched + ' |\n';
  md += '| Storage Slots Changed | ' + summary.totalStorageSlotsChanged + ' |\n';
  md += '| Gas Efficiency | ' + summary.gasEfficiency.percentage.toFixed(1) + '% |\n';
  
  // Alert Summary
  md += '### Alert Summary\n\n';
  md += '| Severity | Count |\n';
  md += '|----------|-------|\n';
  md += '| \u{1F534} Critical | ' + summary.alertCounts.critical + ' |\n';
  md += '| \u{1F7E0} High | ' + summary.alertCounts.high + ' |\n';
  md += '| \u{1F7E1} Medium | ' + summary.alertCounts.medium + ' |\n';
  md += '| \u{1F7E2} Low | ' + summary.alertCounts.low + ' |\n';
md += '| \u{2139}\uFE0F Info | ' + summary.alertCounts.info + ' |\n';
  
  return md;
}

function generateTransactionTable(trace: FoundryTrace): string {
  const tx = trace.transaction;
  
  let md = '';
  md += '| Field | Value |\n';
  md += '|------|-------|\n';
  md += `| From | \`${tx.from}\` |\n`;
  md += `| To | \`${tx.to || '(Contract Creation)'}\` |\n`;
  md += `| Value | \`${formatEther(tx.value)} ETH\` |\n`;
  md += `| Gas Limit | \`${tx.gas.toLocaleString()}\` |\n`;
  md += `| Gas Used | \`${trace.gasInfo.gasUsed.toLocaleString()}\` (${(trace.gasInfo.gasUsed / tx.gas * 100).toFixed(1)}%) |\n`;
  md += `| Input Data | \`${tx.input.slice(0, 42)}${tx.input.length > 42 ? '...' : ''}\` |\n\n`;
  
  return md;
}

function generateExecutionMermaid(trace: FoundryTrace): string {
  let md = '### Call Graph\n\n';
  md += '```mermaid\n';
  md += 'graph TD\n';
  md += generateMermaidNodes(trace.trace, 0);
  md += '```\n\n';
  
  return md;
}

function generateMermaidNodes(steps: TraceStep[], depth: number): string {
  let lines = '';
  const prefix = '  '.repeat(depth);
  
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const nodeId = `node_${depth}_${i}`;
    const label = step.contractName || decodeSelector(step.input) || 'unknown';
    
    lines += `${prefix}${nodeId}["${label}<br/>${step.gasUsed} gas"]\n`;
    
    if (step.subcalls && step.subcalls.length > 0 && depth < 3) {
      for (let j = 0; j < step.subcalls.length; j++) {
        const childNodeId = `node_${depth + 1}_${j}`;
        lines += `${prefix}${nodeId} --> ${childNodeId}\n`;
      }
      lines += generateMermaidNodes(step.subcalls, depth + 1);
    }
  }
  
  return lines;
}

function generateExecutionList(trace: FoundryTrace): string {
  let md = '### Step-by-Step Execution\n\n';
  md += '| Depth | Contract/Function | Status | Gas Used |\n';
  md += '|-------|-------------------|--------|----------|\n';
  
  for (const step of trace.trace) {
    const name = step.contractName || decodeSelector(step.input) || 'unknown';
    const statusIcon = step.status === 'success' ? '✅' : step.status === 'revert' ? '❌' : '⚠️';
    md += `| ${step.depth} | \`${name}\` | ${statusIcon} | ${step.gasUsed.toLocaleString()} |\n`;
    
    if (step.subcalls) {
      for (const subcall of step.subcalls.slice(0, 5)) {
        const subName = subcall.contractName || decodeSelector(subcall.input) || 'unknown';
        const subStatusIcon = subcall.status === 'success' ? '✅' : subcall.status === 'revert' ? '❌' : '⚠️';
        md += `| ${subcall.depth + 1} | ↳ \`${subName}\` | ${subStatusIcon} | ${subcall.gasUsed.toLocaleString()} |\n`;
      }
      
      if (step.subcalls.length > 5) {
        md += `| | ↳ ... and ${step.subcalls.length - 5} more calls | | |\n`;
      }
    }
  }
  
  md += '\n';
  return md;
}

function generateStateChangesSection(diffs: StateDiff[], includeDetails: boolean): string {
  let md = '';
  
  // Summary table
  md += '### Changes by Contract\n\n';
  md += '| Contract | Address | Slots Changed | Anomalies |\n';
  md += '|----------|--------|---------------|------------|\n';
  
  for (const diff of diffs) {
    const anomalyCount = diff.slotChanges.filter(s => s.anomaly?.detected).length;
    const anomalyBadge = anomalyCount > 0 ? `⚠️ ${anomalyCount}` : '-';
    md += `| \`${diff.contractName}\` | \`${shortenAddress(diff.address)}\` | ${diff.slotChanges.length} | ${anomalyBadge} |\n`;
  }
  
  md += '\n';
  
  // Detailed changes
  if (includeDetails) {
    md += '### Detailed Slot Changes\n\n';
    
    for (const diff of diffs.slice(0, 10)) {
      md += `#### ${diff.contractName}\n\n`;
      
      if (diff.slotChanges.length === 0) {
        md += '*No storage changes.*\n\n';
        continue;
      }
      
      md += '| Slot | Label | Before | After | Deviation | Anomaly? |\n';
      md += '|------|-------|--------|------|-----------|----------|\n';
      
      for (const slot of diff.slotChanges.slice(0, 20)) {
        const before = slot.decodedBefore !== undefined ? String(slot.decodedBefore) : shortenHex(slot.beforeValue);
        const after = slot.decodedAfter !== undefined ? String(slot.decodedAfter) : shortenHex(slot.afterValue);
        const deviation = slot.deviation !== undefined ? `${slot.deviation > 0 ? '+' : ''}${slot.deviation.toFixed(2)}%` : '-';
        const anomaly = slot.anomaly?.detected ? '⚠️ Yes' : '-';
        
        md += `| \`${slot.slot.slice(0, 16)}...\` | ${slot.slotLabel || '-'} | \`${before}\` | \`${after}\` | ${deviation} | ${anomaly} |\n`;
        
        if (slot.anomaly?.detected) {
          md += `| | | | | | **${slot.anomaly.message}** |\n`;
        }
      }
      
      if (diff.slotChanges.length > 20) {
        md += `| ... | ... | ... | ... | ... | ... |\n`;
      }
      
      md += '\n';
    }
  }
  
  return md;
}

function generateAlertsSection(alerts: Alert[], maxShow: number): string {
  let md = '';
  
  if (alerts.length === 0) {
    md += '✅ **No alerts triggered.**\n\n';
    return md;
  }
  
  // Summary by severity
  const critical = alerts.filter(a => a.severity === 'critical');
  const high = alerts.filter(a => a.severity === 'high');
  const medium = alerts.filter(a => a.severity === 'medium');
  const low = alerts.filter(a => a.severity === 'low');
  
  md += `### Overview: ${alerts.length} Alerts\n\n`;
  md += ` \u{1F534} Critical  \u{1F7E0} High  \u{1F7E1} Medium  \u{1F7E2} Low |\n`;
  md += `|------------|---------|-----------|--------|\n`;
  md += `| ${critical.length} | ${high.length} | ${medium.length} | ${low.length} |\n\n`;
  
  // Critical alerts
  if (critical.length > 0) {
    md += '#### 🔴 Critical Alerts\n\n';
    md += generateAlertTable(critical.slice(0, Math.floor(maxShow / 2)));
  }
  
  // High alerts
  if (high.length > 0) {
    md += '#### 🟠 High Priority Alerts\n\n';
    md += generateAlertTable(high.slice(0, Math.floor(maxShow / 2)));
  }
  
  // Medium/Low alerts (just list)
  if (medium.length > 0 || low.length > 0) {
    md += '#### Other Alerts\n\n';
    
    for (const alert of [...medium, ...low].slice(0, maxShow - critical.length - high.length)) {
      md += `- **[${alert.severity.toUpperCase()}]** ${alert.title}: ${alert.description.substring(0, 100)}...\n`;
    }
  }
  
  // Remaining count
  const shown = Math.min(alerts.length, maxShow);
  if (alerts.length > shown) {
    md += `\n*... and ${alerts.length - shown} more alerts*\n`;
  }
  
  md += '\n';
  return md;
}

function generateAlertTable(alerts: Alert[]): string {
  let md = '';
  md += '| Rule | Category | Description | Suggestion |\n';
  md += '|------|----------|-------------|------------|\n';
  
  for (const alert of alerts) {
    md += `| ${alert.ruleName} | ${alert.category} | ${alert.description.substring(0, 80)}... | ${alert.suggestion?.substring(0, 60) || '-'}... |\n`;
  }
  
  md += '\n';
  return md;
}

function generateOracleSection(analysis: OracleAnalysis): string {
  let md = '';
  
  md += '### Price Observations\n\n';
  md += '| Oracle | Asset | Price | Source | Confidence |\n';
  md += '|--------|-------|------|--------|------------|\n';
  
  for (const obs of analysis.pricesObserved) {
    md += `| ${obs.oracle} | ${obs.asset} | $${obs.price.toLocaleString()} | ${obs.source} | ${obs.confidence} |\n`;
  }
  
  md += '\n';
  
  // Deviations
  if (analysis.deviations.length > 0) {
    md += '### Price Deviations\n\n';
    md += '| Asset | Expected | Observed | Deviation | Threshold Exceeded? |\n';
    md += '|-------|----------|----------|-----------|---------------------|\n';
    
    for (const dev of analysis.deviations) {
      const exceeded = dev.thresholdExceeded ? '⚠️ YES' : 'No';
      md += `| ${dev.asset} | $${dev.expectedPrice.toLocaleString()} | $${dev.observedPrice.toLocaleString()} | ${dev.deviationPercent.toFixed(2)}% | ${exceeded} |\n`;
    }
    
    md += '\n';
  }
  
  // TWAP
  if (analysis.twapAnalysis) {
    md += '### TWAP Analysis\n\n';
    md += '| Metric | Value |\n';
    md += '|--------|-------|\n';
    md += `| Average Price | $${analysis.twapAnalysis.avgPrice.toLocaleString()} |\n`;
    md += `| Current Price | $${analysis.twapAnalysis.currentPrice.toLocaleString()} |\n`;
    md += `| Deviation | ${analysis.twapAnalysis.deviation.toFixed(2)}% |\n`;
    md += `| Sample Count | ${analysis.twapAnalysis.sampleCount} |\n\n`;
  }
  
  // Manipulation indicators
  if (analysis.manipulationIndicators.length > 0) {
    md += '### ⚠️ Manipulation Indicators\n\n';
    
    for (const indicator of analysis.manipulationIndicators) {
      md += `#### ${indicator.type.replace(/-/g, ' ').toUpperCase()}\n\n`;
      md += `- **Confidence:** ${(indicator.confidence * 100).toFixed(0)}%\n`;
      md += '- **Evidence:**\n';
      for (const evidence of indicator.evidence) {
        md += `  - ${evidence}\n`;
      }
      md += '- **Affected Functions:**\n';
      for (const func of indicator.affectedFunctions) {
        md += `  - \`${func}\`\n`;
      }
      md += '\n';
    }
  }
  
  return md;
}

function generateRoleJourneysSection(journeys: RoleJourney[]): string {
  let md = '';
  
  for (const journey of journeys) {
    md += `### Actor: \`${journey.actor}\`\n\n`;
    md += '| Property | Value |\n';
    md += '|----------|-------|\n';
    md += `| Initial Role | ${journey.role} |\n`;
    md += `| Actions Taken | ${journey.actions.length} |\n`;
    md += `| Permission Checks | ${journey.permissionsChecked.length} |\n`;
    md += `| Privilege Escalations | ${journey.privilegesEscalated.length} |\n`;
    md += `| Final State | ${journey.finalState} |\n\n`;
    
    if (journey.actions.length > 0) {
      md += '#### Action Log\n\n';
      md += '| # | Function | Contract | Success | Impact |\n';
      md += '|---|----------|----------|---------|--------|\n';
      
      for (const action of journey.actions.slice(0, 20)) {
        const icon = action.success ? '✅' : '❌';
        md += `| ${action.order} | \`${action.function}\` | \`${action.contract}\` | ${icon} | ${action.stateImpact} |\n`;
      }
      
      if (journey.actions.length > 20) {
        md += `| ... | ... | ... | ... | ... |\n`;
      }
      
      md += '\n';
    }
  }
  
  return md;
}

function generateVerdictSection(summary: AnalysisSummary | undefined, alerts: Alert[]): string {
  let md = '';
  
  const verdict = summary?.verdict || 'pass';
  const verdictEmoji = verdict === 'pass' ? '✅' : verdict === 'warning' ? '⚠️' : verdict === 'fail' ? '❌' : 'ℹ️';
  
  md += `## Verdict: ${verdictEmoji} ${verdict.toUpperCase()}\n\n`;
  
  if (verdict !== 'pass') {
    md += '### Key Concerns\n\n';
    
    const criticalAlerts = alerts.filter(a => a.severity === 'critical').slice(0, 5);
    const highAlerts = alerts.filter(a => a.severity === 'high').slice(0, 5);
    
    if (criticalAlerts.length > 0) {
      md += '**Critical Issues:**\n';
      for (const alert of criticalAlerts) {
        md += `- ${alert.title}\n`;
      }
      md += '\n';
    }
    
    if (highAlerts.length > 0) {
      md += '**High Priority Issues:**\n';
      for (const alert of highAlerts) {
        md += `- ${alert.title}\n`;
      }
      md += '\n';
    }
    
    md += '### Recommendations\n\n';
    md += '1. Review all critical and high severity alerts\n';
    md += '2. Verify state changes match expected behavior\n';
    md += '3. Check oracle prices against external sources\n';
    md += '4. Re-run with different inputs to confirm findings\n';
  } else {
    md += '✨ **No significant issues detected in this execution.**\n\n';
    md += 'The transaction completed without triggering any critical or high-severity alerts.\n';
  }
  
  return md;
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function shortenAddress(address: string): string {
  if (!address || address.length < 12) return address || '0x0';
  return `${address.slice(0, 8)}...${address.slice(-6)}`;
}

function shortenHex(hex: string): string {
  if (!hex) return '0x0';
  return hex.length > 18 ? `${hex.slice(0, 12)}...` : hex;
}

function formatEther(wei: string): string {
  try {
    const weiBigInt = BigInt(wei);
    const eth = Number(weiBigInt) / 1e18;
    return eth < 0.001 ? '<0.001' : eth.toFixed(6);
  } catch {
    return '0';
  }
}

function decodeSelector(calldata: string): string | null {
  if (!calldata || calldata.length < 10) return null;
  
  const selectors: Record<string, string> = {
    '0xa9059cbb': 'transfer',
    '0x23b872dd': 'transferFrom',
    '0x095ea7b3': 'approve',
    '0x7ff36ab5': 'swapExactETHForTokens',
    '0x18cbafe5': 'swapExactTokensForETH',
    '0x1f00390c': 'swapExactTokensForTokens'
  };
  
  return selectors[calldata.slice(0, 10)] || null;
}
