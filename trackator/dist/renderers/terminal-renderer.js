"use strict";
// ============================================================
// TRACKATOR Tier 3 - Terminal Renderer
// ASCII art instant output for CLI
// ============================================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderTerminal = renderTerminal;
const chalk_1 = __importDefault(require("chalk"));
const boxen_1 = __importDefault(require("boxen"));
/**
 * Render analysis results to terminal with ASCII visualization
 */
function renderTerminal(trace, stateDiffs, alerts, oracleAnalysis, roleJourneys, summary, options = {}) {
    const { showDetails = true, maxAlerts = 20, colorOutput = true } = options;
    // Disable colors if requested
    if (!colorOutput) {
        chalk_1.default.level = 0;
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
function renderHeader(summary) {
    const verdictColor = getVerdictColor(summary?.verdict || 'pass');
    const verdictIcon = getVerdictIcon(summary?.verdict || 'pass');
    console.log(chalk_1.default.white.bold('╔══════════════════════════════════════════════════════════════╗'));
    console.log(chalk_1.default.white.bold('║') + chalk_1.default.cyan.bold('           TRACKATOR - RUNTIME ANALYSIS') + ' '.repeat(24) + chalk_1.default.white.bold('║'));
    console.log(chalk_1.default.white.bold('╠══════════════════════════════════════════════════════════════╣'));
    console.log(chalk_1.default.white.bold('║') + ` ${verdictIcon} Verdict: ${verdictColor((summary?.verdict || 'pass').toUpperCase())}` + ' '.repeat(38) + chalk_1.default.white.bold('║'));
    console.log(chalk_1.default.white.bold('╚══════════════════════════════════════════════════════════════╝'));
    console.log('');
}
function renderTransactionOverview(trace) {
    console.log(chalk_1.default.hex('#4fc3f7').bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.hex('#4fc3f7').bold('│              TRANSACTION OVERVIEW                        │'));
    console.log(chalk_1.default.hex('#4fc3f7').bold('├─────────────────────────────────────────────────────────────┤'));
    const tx = trace.transaction;
    console.log(chalk_1.default.white(`  From:     ${chalk_1.default.cyan(shortenAddress(tx.from))}`));
    console.log(chalk_1.default.white(`  To:       ${chalk_1.default.cyan(tx.to ? shortenAddress(tx.to) : '(Contract Creation)')}`));
    console.log(chalk_1.default.white(`  Value:    ${chalk_1.default.yellow(formatEther(tx.value))} ETH`));
    console.log(chalk_1.default.white(`  Gas Used: ${chalk_1.default.white(trace.gasInfo.gasUsed.toLocaleString())} / ${tx.gas.toLocaleString()} (${(trace.gasInfo.gasUsed / tx.gas * 100).toFixed(1)}%)`));
    console.log(chalk_1.default.white(`  Input:    ${chalk_1.default.gray(tx.input.slice(0, 30) + (tx.input.length > 30 ? '...' : ''))}`));
    console.log(chalk_1.default.hex('#4fc3f7').bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
}
function renderExecutionFlow(trace) {
    console.log(chalk_1.default.hex('#81c784').bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.hex('#81c784').bold('│              EXECUTION FLOW                               │'));
    console.log(chalk_1.default.hex('#81c784').bold('├─────────────────────────────────────────────────────────────┤'));
    renderStepTree(trace.trace, 0, trace.trace.length.toString().length);
    console.log(chalk_1.default.hex('#81c784').bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
}
function renderStepTree(steps, depth, _maxIndexWidth) {
    const indent = '  '.repeat(depth);
    const prefix = depth === 0 ? '' : (depth === 1 ? '├─' : '└─');
    const connector = depth > 1 ? '┬' : '';
    for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        const statusIcon = step.status === 'success' ? '✓' :
            step.status === 'revert' ? '✗' : '⚠';
        const statusColor = step.status === 'success' ? chalk_1.default.green :
            step.status === 'revert' ? chalk_1.default.red : chalk_1.default.yellow;
        const funcName = step.contractName || decodeSelector(step.input) || 'unknown';
        const gasInfo = `${step.gasUsed.toLocaleString()} gas`;
        console.log(`${indent}${prefix}${connector} ${statusIcon} ${chalk_1.default.white(funcName)} ${chalk_1.default.gray(gasInfo)}`);
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
function renderStateChangesSummary(diffs) {
    console.log(chalk_1.default.hex('#ffb74d').bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.hex('#ffb74d').bold('│              STATE CHANGES SUMMARY                         │'));
    console.log(chalk_1.default.hex('#ffb74d').bold('├─────────────────────────────────────────────────────────────┤'));
    let totalSlots = 0;
    let significantChanges = 0;
    for (const diff of diffs) {
        totalSlots += diff.slotChanges.length;
        significantChanges += diff.slotChanges.filter(s => s.deviation && s.deviation > 10).length;
    }
    console.log(chalk_1.default.white(`  Contracts Touched: ${chalk_1.default.cyan(diffs.length.toString())}`));
    console.log(chalk_1.default.white(`  Total Slot Changes: ${chalk_1.default.cyan(totalSlots.toString())}`));
    console.log(chalk_1.default.white(`  Significant Changes (>10%): ${chalk_1.default.yellow(significantChanges.toString())}`));
    if (diffs.length > 0) {
        console.log('');
        console.log(chalk_1.default.gray('  Changes by contract:'));
        for (const diff of diffs.slice(0, 10)) {
            const anomalyCount = diff.slotChanges.filter(s => s.anomaly?.detected).length;
            const anomalyBadge = anomalyCount > 0 ? chalk_1.default.red(` [${anomalyCount} ⚠]`) : '';
            console.log(chalk_1.default.gray(`    • ${diff.contractName}: ${diff.slotChanges.length} slots${anomalyBadge}`));
        }
        if (diffs.length > 10) {
            console.log(chalk_1.default.gray(`    ... and ${diffs.length - 10} more contracts`));
        }
    }
    else {
        console.log(chalk_1.default.gray('  No storage changes detected'));
    }
    console.log(chalk_1.default.hex('#ffb74d').bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
}
function renderDetailedStateDiffs(diffs) {
    console.log(chalk_1.default.hex('#ce93d8').bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.hex('#ce93d8').bold('│              DETAILED STATE DIFFS                          │'));
    console.log(chalk_1.default.hex('#ce93d8').bold('├─────────────────────────────────────────────────────────────┤'));
    for (const diff of diffs.slice(0, 5)) { // Limit to prevent overflow
        console.log(chalk_1.default.bold(`\n  ${diff.contractName} (${shortenAddress(diff.address)})`));
        console.log('  ' + '─'.repeat(50));
        for (const slot of diff.slotChanges.slice(0, 8)) {
            const deviationStr = slot.deviation !== undefined ?
                `(${slot.deviation > 0 ? '+' : ''}${slot.deviation.toFixed(2)}%)` : '';
            const deviationColor = !slot.deviation ? chalk_1.default.white :
                slot.deviation > 50 ? chalk_1.default.red :
                    slot.deviation > 10 ? chalk_1.default.yellow : chalk_1.default.green;
            const anomalyIndicator = slot.anomaly?.detected ? chalk_1.default.red(' ⚠ ANOMALY') : '';
            const label = slot.slotLabel || `Slot ${slot.slot}`;
            const before = slot.decodedBefore !== undefined ? String(slot.decodedBefore) : shortenHex(slot.beforeValue);
            const after = slot.decodedAfter !== undefined ? String(slot.decodedAfter) : shortenHex(slot.afterValue);
            console.log(`  ${chalk_1.default.gray(label)}`);
            console.log(`    ${chalk_1.default.red(before)} → ${chalk_1.default.green(after)} ${deviationColor(deviationStr)}${anomalyIndicator}`);
            if (slot.anomaly?.detected) {
                console.log(`    ${chalk_1.default.red(`    Reason: ${slot.anomaly.message}`)}`);
            }
        }
        if (diff.slotChanges.length > 8) {
            console.log(chalk_1.default.gray(`  ... and ${diff.slotChanges.length - 8} more changes`));
        }
    }
    if (diffs.length > 5) {
        console.log(chalk_1.default.gray(`\n  ... and ${diffs.length - 5} more contracts`));
    }
    console.log(chalk_1.default.hex('#ce93d8').bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
}
function renderAlerts(alerts, maxShow) {
    console.log(chalk_1.default.red.bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.red.bold('│                      ALERTS                                │'));
    console.log(chalk_1.default.red.bold('├─────────────────────────────────────────────────────────────┤'));
    if (alerts.length === 0) {
        console.log(chalk_1.default.green('  ✓ No alerts triggered'));
    }
    else {
        console.log(chalk_1.default.white(`  Total Alerts: ${alerts.length}`));
        console.log('');
        // Group by severity
        const critical = alerts.filter(a => a.severity === 'critical');
        const high = alerts.filter(a => a.severity === 'high');
        const medium = alerts.filter(a => a.severity === 'medium');
        const low = alerts.filter(a => a.severity === 'low');
        if (critical.length > 0) {
            console.log(chalk_1.default.red.bold(`  🔴 CRITICAL (${critical.length}):`));
            for (const alert of critical.slice(0, Math.floor(maxShow / 2))) {
                console.log(chalk_1.default.red(`     • ${alert.title}`));
                console.log(chalk_1.default.gray(`       ${alert.description.substring(0, 80)}...`));
            }
        }
        if (high.length > 0) {
            console.log(chalk_1.default.hex('#ff6b6b').bold(`  🟠 HIGH (${high.length}):`));
            for (const alert of high.slice(0, Math.floor(maxShow / 2))) {
                console.log(chalk_1.default.hex('#ff6b6b')(`     • ${alert.title}`));
            }
        }
        if (medium.length > 0) {
            console.log(chalk_1.default.yellow(`  🟡 MEDIUM (${medium.length})`));
        }
        if (low.length > 0) {
            console.log(chalk_1.default.hex('#ffee58')(`  🟢 LOW (${low.length})`));
        }
        const remaining = alerts.length - Math.min(alerts.length, maxShow);
        if (remaining > 0) {
            console.log(chalk_1.default.gray(`  ... and ${remaining} more alerts`));
        }
    }
    console.log(chalk_1.default.red.bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
}
function renderOracleAnalysis(analysis) {
    console.log(chalk_1.default.hex('#90caf9').bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.hex('#90caf9').bold('│              ORACLE ANALYSIS                              │'));
    console.log(chalk_1.default.hex('#90caf9').bold('├─────────────────────────────────────────────────────────────┤'));
    console.log(chalk_1.default.white(`  Price Observations: ${analysis.pricesObserved.length}`));
    console.log(chalk_1.default.white(`  Deviations Detected: ${analysis.deviations.filter(d => d.thresholdExceeded).length}`));
    if (analysis.twapAnalysis) {
        console.log(chalk_1.default.white(`  TWAP Deviation: ${analysis.twapAnalysis.deviation.toFixed(2)}%`));
    }
    if (analysis.manipulationIndicators.length > 0) {
        console.log('');
        console.log(chalk_1.default.yellow('  ⚠ Manipulation Indicators:'));
        for (const indicator of analysis.manipulationIndicators) {
            console.log(chalk_1.default.yellow(`    • [${indicator.confidence.toFixed(0)}%] ${indicator.type.replace(/-/g, ' ')}`));
            for (const evidence of indicator.evidence.slice(0, 2)) {
                console.log(chalk_1.default.gray(`      - ${evidence}`));
            }
        }
    }
    if (analysis.pricesObserved.length > 0) {
        console.log('');
        console.log(chalk_1.default.gray('  Observed Prices:'));
        for (const obs of analysis.pricesObserved.slice(0, 5)) {
            console.log(chalk_1.default.gray(`    • ${obs.asset}: $${obs.price.toLocaleString()} (${obs.source})`));
        }
    }
    console.log(chalk_1.default.hex('#90caf9').bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
}
function renderRoleJourneys(journeys) {
    console.log(chalk_1.default.hex('#b39ddb').bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.hex('#b39ddb').bold('│              ROLE JOURNEYS                                │'));
    console.log(chalk_1.default.hex('#b39ddb').bold('├─────────────────────────────────────────────────────────────┤'));
    for (const journey of journeys) {
        console.log(chalk_1.default.white(`  Actor: ${chalk_1.default.cyan(shortenAddress(journey.actor))}`));
        console.log(chalk_1.default.white(`  Role: ${journey.role}`));
        console.log(chalk_1.default.white(`  Actions: ${journey.actions.length}`));
        if (journey.actions.length > 0) {
            console.log(chalk_1.default.gray('  Execution Path:'));
            for (const action of journey.actions.slice(0, 5)) {
                const statusIcon = action.success ? '✓' : '✗';
                console.log(chalk_1.default.gray(`    ${statusIcon} ${action.contract}.${action.function}`));
            }
            if (journey.actions.length > 5) {
                console.log(chalk_1.default.gray(`    ... and ${journey.actions.length - 5} more actions`));
            }
        }
        if (journey.privilegesEscalated.length > 0) {
            console.log(chalk_1.default.yellow(`  ⚠ Privilege Escalations: ${journey.privilegesEscalated.length}`));
        }
    }
    console.log(chalk_1.default.hex('#b39ddb').bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
}
function renderVerdictFooter(summary, alerts) {
    const verdict = summary?.verdict || 'pass';
    const verdictColor = getVerdictColor(verdict);
    const verdictIcon = getVerdictIcon(verdict);
    const criticalCount = alerts?.filter(a => a.severity === 'critical').length || 0;
    const highCount = alerts?.filter(a => a.severity === 'high').length || 0;
    const footerBox = (0, boxen_1.default)(chalk_1.default.bold(verdictColor(`${verdictIcon} ANALYSIS COMPLETE: ${verdict.toUpperCase()}\n`)) +
        chalk_1.default.white(`Critical: ${criticalCount} | High: ${highCount} | Total: ${alerts?.length || 0}\n`) +
        chalk_1.default.gray(`Contracts: ${summary?.totalContractsTouched || 0} | Slots Changed: ${summary?.totalStorageSlotsChanged || 0}\n`) +
        chalk_1.default.gray(`Gas Efficiency: ${summary?.gasEfficiency.percentage.toFixed(1) || 0}%`), {
        padding: 1,
        borderColor: verdict === 'pass' ? 'green' : verdict === 'fail' ? 'red' : 'yellow',
        borderStyle: 'round',
        margin: { top: 1, bottom: 1 }
    });
    console.log(footerBox);
}
// ============================================================
// UTILITY FUNCTIONS
// ============================================================
function getVerdictColor(verdict) {
    switch (verdict) {
        case 'pass': return chalk_1.default.green;
        case 'warning': return chalk_1.default.yellow;
        case 'fail': return chalk_1.default.red;
        default: return chalk_1.default.blue;
    }
}
function getVerdictIcon(verdict) {
    switch (verdict) {
        case 'pass': return '✅';
        case 'warning': return '⚠️';
        case 'fail': return '❌';
        default: return 'ℹ️';
    }
}
function shortenAddress(address) {
    if (!address || address.length < 12)
        return address || '0x0';
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
}
function shortenHex(hex) {
    if (!hex)
        return '0x0';
    return hex.length > 16 ? `${hex.slice(0, 10)}...` : hex;
}
function formatEther(wei) {
    try {
        const weiBigInt = BigInt(wei);
        const eth = Number(weiBigInt) / 1e18;
        return eth < 0.001 ? '<0.001' : eth.toFixed(4);
    }
    catch {
        return '0';
    }
}
function decodeSelector(calldata) {
    if (!calldata || calldata.length < 10)
        return null;
    const selectors = {
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
//# sourceMappingURL=terminal-renderer.js.map