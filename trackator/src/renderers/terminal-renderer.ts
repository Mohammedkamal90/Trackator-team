// ============================================================
// TRACKATOR Tier 3 - Terminal Renderer
// ASCII art instant output for CLI
// ============================================================

import chalk from 'chalk';
import boxen from 'boxen';
import {
  FoundryTrace,
  TraceStep,
  StateDiff,
  Alert,
  OracleAnalysis,
  AnalysisSummary,
  RoleJourney
} from '../types';

export interface TerminalRenderOptions {
  showDetails?: boolean;
  maxAlerts?: number;
  colorOutput?: boolean;
}

/**
 * Render analysis results to terminal with ASCII visualization
 */
export function renderTerminal(
  trace: FoundryTrace,
  stateDiffs: StateDiff[],
  alerts: Alert[],
  oracleAnalysis?: OracleAnalysis,
  roleJourneys?: RoleJourney[],
  summary?: AnalysisSummary,
  options: TerminalRenderOptions = {}
): void {
  const {
    showDetails = true,
    maxAlerts = 20,
    colorOutput = true
  } = options;
  
  // Disable colors if requested
  if (!colorOutput) {
    chalk.level = 0;
  }
  
  console.log('\n');
  
  // Header Banner
  renderHeader(summary);
  
  // Transaction Overview
  renderTransactionOverview(trace);
  
  // Execution Flow
  if (showDetails) {
    renderExecutionFlow(trace);
  }
  
  // State Changes Summary
  renderStateChangesSummary(stateDiffs);
  
  // Detailed State Diffs
  if (showDetails && stateDiffs.length > 0) {
    renderDetailedStateDiffs(stateDiffs);
  }
  
  // Alerts Section
  renderAlerts(alerts, maxAlerts);
  
  // Oracle Analysis
  if (oracleAnalysis && showDetails) {
    renderOracleAnalysis(oracleAnalysis);
  }
  
  // Role Journeys
  if (roleJourneys && roleJourneys.length > 0 && showDetails) {
    renderRoleJourneys(roleJourneys);
  }
  
  // Verdict Footer
  renderVerdictFooter(summary, alerts);
}

function renderHeader(summary?: AnalysisSummary): void {
  const verdictColor = getVerdictColor(summary?.verdict || 'pass');
  const verdictIcon = getVerdictIcon(summary?.verdict || 'pass');
  
  console.log(chalk.white.bold('╔══════════════════════════════════════════════════════════════╗'));
  console.log(chalk.white.bold('║') + chalk.cyan.bold('           TRACKATOR - RUNTIME ANALYSIS') + ' '.repeat(24) + chalk.white.bold('║'));
  console.log(chalk.white.bold('╠══════════════════════════════════════════════════════════════╣'));
  console.log(chalk.white.bold('║') + ` ${verdictIcon} Verdict: ${verdictColor((summary?.verdict || 'pass').toUpperCase())}` + ' '.repeat(38) + chalk.white.bold('║'));
  console.log(chalk.white.bold('╚══════════════════════════════════════════════════════════════╝'));
  console.log('');
}

function renderTransactionOverview(trace: FoundryTrace): void {
  console.log(chalk.hex('#4fc3f7').bold('┌─────────────────────────────────────────────────────────────┐'));
  console.log(chalk.hex('#4fc3f7').bold('│              TRANSACTION OVERVIEW                        │'));
  console.log(chalk.hex('#4fc3f7').bold('├─────────────────────────────────────────────────────────────┤'));
  
  const tx = trace.transaction;
  console.log(chalk.white(`  From:     ${chalk.cyan(shortenAddress(tx.from))}`));
  console.log(chalk.white(`  To:       ${chalk.cyan(tx.to ? shortenAddress(tx.to) : '(Contract Creation)')}`));
  console.log(chalk.white(`  Value:    ${chalk.yellow(formatEther(tx.value))} ETH`));
  console.log(chalk.white(`  Gas Used: ${chalk.white(trace.gasInfo.gasUsed.toLocaleString())} / ${tx.gas.toLocaleString()} (${(trace.gasInfo.gasUsed / tx.gas * 100).toFixed(1)}%)`));
  console.log(chalk.white(`  Input:    ${chalk.gray(tx.input.slice(0, 30) + (tx.input.length > 30 ? '...' : ''))}`));
  
  console.log(chalk.hex('#4fc3f7').bold('└─────────────────────────────────────────────────────────────┘'));
  console.log('');
}

function renderExecutionFlow(trace: FoundryTrace): void {
  console.log(chalk.hex('#81c784').bold('┌─────────────────────────────────────────────────────────────┐'));
  console.log(chalk.hex('#81c784').bold('│              EXECUTION FLOW                               │'));
  console.log(chalk.hex('#81c784').bold('├─────────────────────────────────────────────────────────────┤'));
  
  renderStepTree(trace.trace, 0, trace.trace.length.toString().length);
  
  console.log(chalk.hex('#81c784').bold('└─────────────────────────────────────────────────────────────┘'));
  console.log('');
}

function renderStepTree(steps: TraceStep[], depth: number, _maxIndexWidth: number): void {
  const indent = '  '.repeat(depth);
  const prefix = depth === 0 ? '' : (depth === 1 ? '├─' : '└─');
  const connector = depth > 1 ? '┬' : '';
  
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const statusIcon = step.status === 'success' ? '✓' :
                      step.status === 'revert' ? '✗' : '⚠';
    
    const statusColor = step.status === 'success' ? chalk.green :
                       step.status === 'revert' ? chalk.red : chalk.yellow;
    
    const funcName = step.contractName || decodeSelector(step.input) || 'unknown';
    const gasInfo = `${step.gasUsed.toLocaleString()} gas`;
    
    console.log(`${indent}${prefix}${connector} ${statusIcon} ${chalk.white(funcName)} ${chalk.gray(gasInfo)}`);
    
    if (step.subcalls && step.subcalls.length > 0) {
      renderStepTree(step.subcalls, depth + 1, 0);
    }
    
    // Limit display depth
    if (depth >= 3 && i >= 2) {
      console.log(`${indent}  └─ ... (${step.subcalls?.length || 0} more calls)`);
      break;
    }
  }
}

function renderStateChangesSummary(diffs: StateDiff[]): void {
  console.log(chalk.hex('#ffb74d').bold('┌─────────────────────────────────────────────────────────────┐'));
  console.log(chalk.hex('#ffb74d').bold('│              STATE CHANGES SUMMARY                         │'));
  console.log(chalk.hex('#ffb74d').bold('├─────────────────────────────────────────────────────────────┤'));
  
  let totalSlots = 0;
  let significantChanges = 0;
  
  for (const diff of diffs) {
    totalSlots += diff.slotChanges.length;
    significantChanges += diff.slotChanges.filter(s => s.deviation && s.deviation > 10).length;
  }
  
  console.log(chalk.white(`  Contracts Touched: ${chalk.cyan(diffs.length.toString())}`));
  console.log(chalk.white(`  Total Slot Changes: ${chalk.cyan(totalSlots.toString())}`));
  console.log(chalk.white(`  Significant Changes (>10%): ${chalk.yellow(significantChanges.toString())}`));
  
  if (diffs.length > 0) {
    console.log('');
    console.log(chalk.gray('  Changes by contract:'));
    
    for (const diff of diffs.slice(0, 10)) {
      const anomalyCount = diff.slotChanges.filter(s => s.anomaly?.detected).length;
      const anomalyBadge = anomalyCount > 0 ? chalk.red(` [${anomalyCount} ⚠]`) : '';
      console.log(chalk.gray(`    • ${diff.contractName}: ${diff.slotChanges.length} slots${anomalyBadge}`));
    }
    
    if (diffs.length > 10) {
      console.log(chalk.gray(`    ... and ${diffs.length - 10} more contracts`));
    }
  } else {
    console.log(chalk.gray('  No storage changes detected'));
  }
  
  console.log(chalk.hex('#ffb74d').bold('└─────────────────────────────────────────────────────────────┘'));
  console.log('');
}

function renderDetailedStateDiffs(diffs: StateDiff[]): void {
  console.log(chalk.hex('#ce93d8').bold('┌─────────────────────────────────────────────────────────────┐'));
  console.log(chalk.hex('#ce93d8').bold('│              DETAILED STATE DIFFS                          │'));
  console.log(chalk.hex('#ce93d8').bold('├─────────────────────────────────────────────────────────────┤'));
  
  for (const diff of diffs.slice(0, 5)) { // Limit to prevent overflow
    console.log(chalk.bold(`\n  ${diff.contractName} (${shortenAddress(diff.address)})`));
    console.log('  ' + '─'.repeat(50));
    
    for (const slot of diff.slotChanges.slice(0, 8)) {
      const deviationStr = slot.deviation !== undefined ? 
        `(${slot.deviation > 0 ? '+' : ''}${slot.deviation.toFixed(2)}%)` : '';
      
      const deviationColor = !slot.deviation ? chalk.white :
        slot.deviation > 50 ? chalk.red :
        slot.deviation > 10 ? chalk.yellow : chalk.green;
      
      const anomalyIndicator = slot.anomaly?.detected ? chalk.red(' ⚠ ANOMALY') : '';
      
      const label = slot.slotLabel || `Slot ${slot.slot}`;
      const before = slot.decodedBefore !== undefined ? String(slot.decodedBefore) : shortenHex(slot.beforeValue);
      const after = slot.decodedAfter !== undefined ? String(slot.decodedAfter) : shortenHex(slot.afterValue);
      
      console.log(`  ${chalk.gray(label)}`);
      console.log(`    ${chalk.red(before)} → ${chalk.green(after)} ${deviationColor(deviationStr)}${anomalyIndicator}`);
      
      if (slot.anomaly?.detected) {
        console.log(`    ${chalk.red(`    Reason: ${slot.anomaly.message}`)}`);
      }
    }
    
    if (diff.slotChanges.length > 8) {
      console.log(chalk.gray(`  ... and ${diff.slotChanges.length - 8} more changes`));
    }
  }
  
  if (diffs.length > 5) {
    console.log(chalk.gray(`\n  ... and ${diffs.length - 5} more contracts`));
  }
  
  console.log(chalk.hex('#ce93d8').bold('└─────────────────────────────────────────────────────────────┘'));
  console.log('');
}

function renderAlerts(alerts: Alert[], maxShow: number): void {
  console.log(chalk.red.bold('┌─────────────────────────────────────────────────────────────┐'));
  console.log(chalk.red.bold('│                      ALERTS                                │'));
  console.log(chalk.red.bold('├─────────────────────────────────────────────────────────────┤'));
  
  if (alerts.length === 0) {
    console.log(chalk.green('  ✓ No alerts triggered'));
  } else {
    console.log(chalk.white(`  Total Alerts: ${alerts.length}`));
    console.log('');
    
    // Group by severity
    const critical = alerts.filter(a => a.severity === 'critical');
    const high = alerts.filter(a => a.severity === 'high');
    const medium = alerts.filter(a => a.severity === 'medium');
    const low = alerts.filter(a => a.severity === 'low');
    
    if (critical.length > 0) {
      console.log(chalk.red.bold(`  🔴 CRITICAL (${critical.length}):`));
      for (const alert of critical.slice(0, Math.floor(maxShow / 2))) {
        console.log(chalk.red(`     • ${alert.title}`));
        console.log(chalk.gray(`       ${alert.description.substring(0, 80)}...`));
      }
    }
    
    if (high.length > 0) {
      console.log(chalk.hex('#ff6b6b').bold(`  🟠 HIGH (${high.length}):`));
      for (const alert of high.slice(0, Math.floor(maxShow / 2))) {
        console.log(chalk.hex('#ff6b6b')(`     • ${alert.title}`));
      }
    }
    
    if (medium.length > 0) {
      console.log(chalk.yellow(`  🟡 MEDIUM (${medium.length})`));
    }
    
    if (low.length > 0) {
      console.log(chalk.hex('#ffee58')(`  🟢 LOW (${low.length})`));
    }
    
    const remaining = alerts.length - Math.min(alerts.length, maxShow);
    if (remaining > 0) {
      console.log(chalk.gray(`  ... and ${remaining} more alerts`));
    }
  }
  
  console.log(chalk.red.bold('└─────────────────────────────────────────────────────────────┘'));
  console.log('');
}

function renderOracleAnalysis(analysis: OracleAnalysis): void {
  console.log(chalk.hex('#90caf9').bold('┌─────────────────────────────────────────────────────────────┐'));
  console.log(chalk.hex('#90caf9').bold('│              ORACLE ANALYSIS                              │'));
  console.log(chalk.hex('#90caf9').bold('├─────────────────────────────────────────────────────────────┤'));
  
  console.log(chalk.white(`  Price Observations: ${analysis.pricesObserved.length}`));
  console.log(chalk.white(`  Deviations Detected: ${analysis.deviations.filter(d => d.thresholdExceeded).length}`));
  
  if (analysis.twapAnalysis) {
    console.log(chalk.white(`  TWAP Deviation: ${analysis.twapAnalysis.deviation.toFixed(2)}%`));
  }
  
  if (analysis.manipulationIndicators.length > 0) {
    console.log('');
    console.log(chalk.yellow('  ⚠ Manipulation Indicators:'));
    for (const indicator of analysis.manipulationIndicators) {
      console.log(chalk.yellow(`    • [${indicator.confidence.toFixed(0)}%] ${indicator.type.replace(/-/g, ' ')}`));
      for (const evidence of indicator.evidence.slice(0, 2)) {
        console.log(chalk.gray(`      - ${evidence}`));
      }
    }
  }
  
  if (analysis.pricesObserved.length > 0) {
    console.log('');
    console.log(chalk.gray('  Observed Prices:'));
    for (const obs of analysis.pricesObserved.slice(0, 5)) {
      console.log(chalk.gray(`    • ${obs.asset}: $${obs.price.toLocaleString()} (${obs.source})`));
    }
  }
  
  console.log(chalk.hex('#90caf9').bold('└─────────────────────────────────────────────────────────────┘'));
  console.log('');
}

function renderRoleJourneys(journeys: RoleJourney[]): void {
  console.log(chalk.hex('#b39ddb').bold('┌─────────────────────────────────────────────────────────────┐'));
  console.log(chalk.hex('#b39ddb').bold('│              ROLE JOURNEYS                                │'));
  console.log(chalk.hex('#b39ddb').bold('├─────────────────────────────────────────────────────────────┤'));
  
  for (const journey of journeys) {
    console.log(chalk.white(`  Actor: ${chalk.cyan(shortenAddress(journey.actor))}`));
    console.log(chalk.white(`  Role: ${journey.role}`));
    console.log(chalk.white(`  Actions: ${journey.actions.length}`));
    
    if (journey.actions.length > 0) {
      console.log(chalk.gray('  Execution Path:'));
      for (const action of journey.actions.slice(0, 5)) {
        const statusIcon = action.success ? '✓' : '✗';
        console.log(chalk.gray(`    ${statusIcon} ${action.contract}.${action.function}`));
      }
      
      if (journey.actions.length > 5) {
        console.log(chalk.gray(`    ... and ${journey.actions.length - 5} more actions`));
      }
    }
    
    if (journey.privilegesEscalated.length > 0) {
      console.log(chalk.yellow(`  ⚠ Privilege Escalations: ${journey.privilegesEscalated.length}`));
    }
  }
  
  console.log(chalk.hex('#b39ddb').bold('└─────────────────────────────────────────────────────────────┘'));
  console.log('');
}

function renderVerdictFooter(summary?: AnalysisSummary, alerts?: Alert[]): void {
  const verdict = summary?.verdict || 'pass';
  const verdictColor = getVerdictColor(verdict);
  const verdictIcon = getVerdictIcon(verdict);
  
  const criticalCount = alerts?.filter(a => a.severity === 'critical').length || 0;
  const highCount = alerts?.filter(a => a.severity === 'high').length || 0;
  
  const footerBox = boxen(
    chalk.bold(verdictColor(`${verdictIcon} ANALYSIS COMPLETE: ${verdict.toUpperCase()}\n`)) +
    chalk.white(`Critical: ${criticalCount} | High: ${highCount} | Total: ${alerts?.length || 0}\n`) +
    chalk.gray(`Contracts: ${summary?.totalContractsTouched || 0} | Slots Changed: ${summary?.totalStorageSlotsChanged || 0}\n`) +
    chalk.gray(`Gas Efficiency: ${summary?.gasEfficiency.percentage.toFixed(1) || 0}%`),
    {
      padding: 1,
      borderColor: verdict === 'pass' ? 'green' : verdict === 'fail' ? 'red' : 'yellow',
      borderStyle: 'round',
      margin: { top: 1, bottom: 1 }
    }
  );
  
  console.log(footerBox);
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function getVerdictColor(verdict: string): (text: string) => string {
  switch (verdict) {
    case 'pass': return chalk.green;
    case 'warning': return chalk.yellow;
    case 'fail': return chalk.red;
    default: return chalk.blue;
  }
}

function getVerdictIcon(verdict: string): string {
  switch (verdict) {
    case 'pass': return '✅';
    case 'warning': return '⚠️';
    case 'fail': return '❌';
    default: return 'ℹ️';
  }
}

function shortenAddress(address: string): string {
  if (!address || address.length < 12) return address || '0x0';
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function shortenHex(hex: string): string {
  if (!hex) return '0x0';
  return hex.length > 16 ? `${hex.slice(0, 10)}...` : hex;
}

function formatEther(wei: string): string {
  try {
    const weiBigInt = BigInt(wei);
    const eth = Number(weiBigInt) / 1e18;
    return eth < 0.001 ? '<0.001' : eth.toFixed(4);
  } catch {
    return '0';
  }
}

function decodeSelector(calldata: string): string | null {
  if (!calldata || calldata.length < 10) return null;
  
  const selectors: Record<string, string> = {
    '0xa9059cbb': 'transfer()',
    '0x23b872dd': 'transferFrom()',
    '0x095ea7b3': 'approve()',
    '0x70a08231': 'balanceOf()',
    '0x18160ddd': 'totalSupply()',
    '0xa457c2d7': 'pause()',
    '0x3f4ba83a': 'unpause()',
    '0xd0e30db0': 'deposit()',
    '0x2e1a4d4d': 'withdraw()',
    '0x7ff36ab5': 'swapExactETHForTokens()',
    '0x18cbafe5': 'swapExactTokensForETH()',
    '0x1f00390c': 'swapExactTokensForTokens()'
  };
  
  return selectors[calldata.slice(0, 10)] || null;
}
