// ============================================================
// TRACKATOR Tier 3 - HTML Renderer
// Generates interactive .html file with VS Code-like UI
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
  RoleJourney
} from '../types';

export interface HtmlRenderOptions {
  includeCharts?: boolean;
  includeInteractivity?: boolean;
  theme?: 'dark' | 'light';
}

/**
 * Generate HTML report with VS Code-like interactive UI
 */
export function generateHtmlReport(
  outputDir: string,
  trace: FoundryTrace,
  stateDiffs: StateDiff[],
  alerts: Alert[],
  oracleAnalysis?: OracleAnalysis,
  roleJourneys?: RoleJourney[],
  summary?: AnalysisSummary,
  options: HtmlRenderOptions = {}
): string {
  const {
    includeCharts = true,
    includeInteractivity = true,
    theme = 'dark'
  } = options;
  
  const htmlPath = path.join(outputDir, 'trackator-analysis.html');
  
  let html = generateHtmlSkeleton(theme);
  
  // Header section
  html += generateHeaderSection(trace, summary);
  
  // Main content area
  html += '<main class="main-content">';
  
  // Dashboard/Overview tab
  html += generateDashboardTab(trace, summary, alerts, oracleAnalysis);
  
  // Execution Flow tab
  html += generateExecutionFlowTab(trace);
  
  // State Changes tab
  html += generateStateChangesTab(stateDiffs);
  
  // Alerts tab
  html += generateAlertsTab(alerts);
  
  // Oracle tab (if data available)
  if (oracleAnalysis) {
    html += generateOracleTab(oracleAnalysis);
  }
  
  // Role Journeys tab (if data available)
  if (roleJourneys && roleJourneys.length > 0) {
    html += generateRoleJourneysTab(roleJourneys);
  }
  
  html += '</main>';
  
  // Sidebar navigation
  html += generateSidebar(summary !== undefined, !!oracleAnalysis, roleJourneys?.length > 0);
  
  // JavaScript for interactivity
  if (includeInteractivity) {
    html += generateJavaScript(trace, stateDiffs, alerts, oracleAnalysis);
  }
  
  // Chart.js for visualizations
  if (includeCharts) {
    html += generateChartIncludes();
  }
  
  html += '</body></html>';
  
  fs.writeFileSync(htmlPath, html);
  
  return htmlPath;
}

function generateHtmlSkeleton(theme: 'dark' | 'light'): string {
  const isDark = theme === 'dark';
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Trackator - Runtime Analysis</title>
  <style>
    :root {
      --bg-primary: ${isDark ? '#1e1e1e' : '#ffffff'};
      --bg-secondary: ${isDark ? '#252526' : '#f5f5f5'};
      --bg-tertiary: ${isDark ? '#2d2d30' : '#e8e8e8'};
      --text-primary: ${isDark ? '#d4d4d4' : '#333333'};
      --text-secondary: ${isDark ? '#9d9d9d' : '#666666'};
      --accent-blue: #007acc;
      --accent-green: #4ec9b0;
      --accent-orange: #ce9178;
      --accent-red: #f48771;
      --accent-yellow: #dcdcaa;
      --border-color: ${isDark ? '#3e3e42' : '#dddddd'};
      --success: #89d185;
      --warning: #dcdcaa;
      --error: #f48771;
      --scrollbar-bg: ${isDark ? '#1e1e1e' : '#f0f0f0'};
      --scrollbar-thumb: ${isDark ? '#424242' : '#c0c0c0'};
    }
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      display: flex;
      height: 100vh;
      overflow: hidden;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: var(--scrollbar-bg); }
    ::-webkit-scrollbar-thumb { background: var(--scrollbar-thumb); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-secondary); }
    
    /* Sidebar */
    .sidebar {
      width: 260px;
      background: var(--bg-secondary);
      border-right: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
    }
    
    .sidebar-header {
      padding: 16px;
      border-bottom: 1px solid var(--border-color);
    }
    
    .logo {
      font-size: 18px;
      font-weight: bold;
      color: var(--accent-green);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .nav-section {
      padding: 12px 0;
      border-bottom: 1px solid var(--border-color);
    }
    
    .nav-title {
      font-size: 11px;
      text-transform: uppercase;
      color: var(--text-secondary);
      padding: 0 16px;
      margin-bottom: 8px;
      letter-spacing: 0.5px;
    }
    
    .nav-item {
      padding: 8px 16px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 13px;
      color: var(--text-primary);
      transition: all 0.15s ease;
      border-left: 2px solid transparent;
    }
    
    .nav-item:hover {
      background: var(--bg-tertiary);
    }
    
    .nav-item.active {
      background: var(--bg-tertiary);
      color: var(--accent-blue);
      border-left-color: var(--accent-blue);
    }
    
    .nav-icon { font-size: 16px; width: 20px; text-align: center; }
    
    /* Main Content */
    .main-content {
      flex: 1;
      overflow-y: auto;
      padding: 24px;
    }
    
    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border-color);
    }
    
    .header h1 {
      font-size: 22px;
      font-weight: 600;
    }
    
    .badges { display: flex; gap: 8px; }
    
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
    }
    
    .badge-success { background: rgba(137, 209, 133, 0.15); color: var(--success); }
    .badge-warning { background: rgba(220, 220, 170, 0.15); color: var(--warning); }
    .badge-error { background: rgba(244, 135, 113, 0.15); color: var(--error); }
    .badge-info { background: rgba(122, 162, 220, 0.15); color: var(--accent-blue); }
    
    /* Tabs */
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    
    /* Cards */
    .card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      margin-bottom: 16px;
      overflow: hidden;
    }
    
    .card-header {
      padding: 12px 16px;
      background: var(--bg-tertiary);
      border-bottom: 1px solid var(--border-color);
      font-weight: 500;
      display: flex;
      justify-content: space-between;
      align-items: center;
      cursor: pointer;
      user-select: none;
    }
    
    .card-header:hover {
      background: ${isDark ? '#353538' : '#ddd'};
    }
    
    .card-body {
      padding: 16px;
    }
    
    /* Tables */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    
    th {
      text-align: left;
      padding: 10px 12px;
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      font-weight: 500;
      border-bottom: 1px solid var(--border-color);
      position: sticky;
      top: 0;
    }
    
    td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border-color);
    }
    
    tr:hover td {
      background: ${isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)'};
    }
    
    /* Code */
    code {
      background: var(--bg-tertiary);
      padding: 2px 6px;
      border-radius: 3px;
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 12px;
      color: var(--accent-orange);
    }
    
    /* Grid */
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    
    .stat-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 20px;
    }
    
    .stat-value {
      font-size: 32px;
      font-weight: bold;
      color: var(--accent-blue);
      line-height: 1;
    }
    
    .stat-label {
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 8px;
    }
    
    .stat-change {
      font-size: 12px;
      margin-top: 4px;
    }
    
    .stat-change.positive { color: var(--success); }
    .stat-change.negative { color: var(--error); }
    
    /* Alert styles */
    .alert-item {
      padding: 12px 16px;
      border-left: 3px solid;
      margin-bottom: 8px;
      background: var(--bg-tertiary);
      border-radius: 0 4px 4px 0;
    }
    
    .alert-critical { border-left-color: var(--error); }
    .alert-high { border-left-color: #ff6b6b; }
    .alert-medium { border-left-color: var(--warning); }
    .alert-low { border-left-color: #ffee58; }
    
    .alert-title {
      font-weight: 500;
      margin-bottom: 4px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    .alert-description {
      font-size: 12px;
      color: var(--text-secondary);
    }
    
    /* Execution tree */
    .execution-tree {
      font-family: 'Consolas', monospace;
      font-size: 13px;
      line-height: 1.8;
    }
    
    .tree-node {
      padding: 4px 0;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .tree-indent { margin-left: 20px; }
    
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    
    .status-success { background: var(--success); }
    .status-error { background: var(--error); }
    .status-revert { background: var(--warning); }
    
    /* Search */
    .search-box {
      width: 100%;
      padding: 10px 14px;
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      color: var(--text-primary);
      font-size: 14px;
      margin-bottom: 16px;
    }
    
    .search-box:focus {
      outline: none;
      border-color: var(--accent-blue);
    }
    
    /* Verdict */
    .verdict-banner {
      padding: 16px 20px;
      border-radius: 4px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    
    .verdict-pass { background: rgba(137, 209, 133, 0.1); border: 1px solid var(--success); }
    .verdict-warning { background: rgba(220, 220, 170, 0.1); border: 1px solid var(--warning); }
    .verdict-fail { background: rgba(244, 135, 113, 0.1); border: 1px solid var(--error); }
    
    .verdict-icon { font-size: 24px; }
    
    /* Charts */
    .chart-container {
      height: 200px;
      position: relative;
    }
    
    /* Responsive */
    @media (max-width: 768px) {
      .sidebar { display: none; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
`;
}

function generateHeaderSection(trace: FoundryTrace, summary?: AnalysisSummary): string {
  const verdict = summary?.verdict || 'pass';
  const verdictClass = verdict === 'pass' ? 'verdict-pass' : verdict === 'fail' ? 'verdict-fail' : 'verdict-warning';
  const verdictIcon = verdict === 'pass' ? '✅' : verdict === 'fail' ? '❌' : '⚠️';
  
  return `
<div class="header">
  <div>
    <h1>🔍 Trackator Analysis</h1>
    <p style="color: var(--text-secondary); margin-top: 4px;">Runtime transaction analysis</p>
  </div>
  <div class="badges">
    <span class="badge badge-info">${trace.trace.length} steps</span>
    <span class="badge badge-${summary?.totalContractsTouched ? 'info' : 'success'}">${summary?.totalContractsTouched || 0} contracts</span>
  </div>
</div>

<div class="verdict-banner ${verdictClass}">
  <span class="verdict-icon">${verdictIcon}</span>
  <div>
    <strong style="font-size: 16px;">Verdict: ${verdict.toUpperCase()}</strong>
    <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
      Gas efficiency: ${summary?.gasEfficiency.percentage.toFixed(1) || 0}% | 
      Alerts: ${summary ? Object.values(summary.alertCounts).reduce((a, b) => a + b, 0) : 0}
    </p>
  </div>
</div>`;
}

function generateDashboardTab(trace: FoundryTrace, summary?: AnalysisSummary, alerts?: Alert[], oracleAnalysis?: OracleAnalysis): string {
  return `
<section id="tab-dashboard" class="tab-content active">
  <div class="grid">
    <div class="stat-card">
      <div class="stat-value">${summary?.totalSteps || trace.trace.length}</div>
      <div class="stat-label">Execution Steps</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: var(--accent-blue)">${summary?.totalContractsTouched || 0}</div>
      <div class="stat-label">Contracts Touched</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: ${alerts?.filter(a => a.severity === 'critical').length ? 'var(--error)' : 'var(--success)'}">${alerts?.filter(a => a.severity === 'critical').length || 0}</div>
      <div class="stat-label">Critical Alerts</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: ${summary?.gasEfficiency.percentage && summary.gasEfficiency.percentage > 80 ? 'var(--error)' : 'var(--success)'}">${summary?.gasEfficiency.percentage.toFixed(0) || 0}%</div>
      <div class="stat-label">Gas Efficiency</div>
    </div>
  </div>
  
  <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
    <div class="card">
      <div class="card-header">
        <span>📊 Transaction Info</span>
      </div>
      <div class="card-body">
        <table>
          <tr><td><strong>From</strong></td><td><code>${shortenAddress(trace.transaction.from)}</code></td></tr>
          <tr><td><strong>To</strong></td><td><code>${trace.transaction.to ? shortenAddress(trace.transaction.to) : 'Contract Creation'}</code></td></tr>
          <tr><td><strong>Value</strong></td><td>${formatEther(trace.transaction.value)} ETH</td></tr>
          <tr><td><strong>Gas Used</strong></td><td>${trace.gasInfo.gasUsed.toLocaleString()} / ${trace.transaction.gas.toLocaleString()}</td></tr>
        </table>
      </div>
    </div>
    
    <div class="card">
      <div class="card-header">
        <span>⚠️ Alert Summary</span>
      </div>
      <div class="card-body">
        <table>
          <tr><td><span style="color: var(--error)">🔴 Critical</span></td><td><strong>${alerts?.filter(a => a.severity === 'critical').length || 0}</strong></td></tr>
          <tr><td><span style="color: #ff6b6b">🟠 High</span></td><td><strong>${alerts?.filter(a => a.severity === 'high').length || 0}</strong></td></tr>
          <tr><td><span style="color: var(--warning)">🟡 Medium</span></td><td><strong>${alerts?.filter(a => a.severity === 'medium').length || 0}</strong></td></tr>
          <tr><td><span style="color: #ffee58">🟢 Low</span></td><td><strong>${alerts?.filter(a => a.severity === 'low').length || 0}</strong></td></tr>
        </table>
      </div>
    </div>
  </div>
  
  ${oracleAnalysis ? `
  <div class="card" style="margin-top: 16px;">
    <div class="card-header">
      <span>📈 Oracle Overview</span>
    </div>
    <div class="card-body">
      <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));">
        <div>
          <div style="font-size: 24px; font-weight: bold; color: var(--accent-blue);">${oracleAnalysis.pricesObserved.length}</div>
          <div style="font-size: 12px; color: var(--text-secondary);">Price Observations</div>
        </div>
        <div>
          <div style="font-size: 24px; font-weight: bold; color: ${oracleAnalysis.deviations.filter(d => d.thresholdExceeded).length > 0 ? 'var(--error)' : 'var(--success)'};">${oracleAnalysis.deviations.filter(d => d.thresholdExceeded).length}</div>
          <div style="font-size: 12px; color: var(--text-secondary);">Deviations</div>
        </div>
        <div>
          <div style="font-size: 24px; font-weight: bold; color: ${oracleAnalysis.manipulationIndicators.length > 0 ? 'var(--warning)' : 'var(--success)'};">${oracleAnalysis.manipulationIndicators.length}</div>
          <div style="font-size: 12px; color: var(--text-secondary);">Manipulation Signals</div>
        </div>
      </div>
    </div>
  </div>` : ''}
</section>`;
}

function generateExecutionFlowTab(trace: FoundryTrace): string {
  return `
<section id="tab-execution" class="tab-content">
  <div class="card">
    <div class="card-header">
      <span>🔄 Call Tree</span>
      <span style="color: var(--text-secondary); font-size: 12px;">${trace.trace.length} calls</span>
    </div>
    <div class="card-body">
      <div class="execution-tree">
        ${generateExecutionTreeHTML(trace.trace, 0)}
      </div>
    </div>
  </div>
</section>`;
}

function generateExecutionTreeHTML(steps: TraceStep[], depth: number): string {
  let html = '';
  
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const name = step.contractName || decodeSelector(step.input) || 'unknown';
    const statusClass = step.status === 'success' ? 'status-success' : step.status === 'revert' ? 'status-revert' : 'status-error';
    const indent = depth > 0 ? 'tree-indent' : '';
    
    html += `<div class="tree-node ${indent}">`;
    html += `<span class="status-dot ${statusClass}"></span>`;
    html += `<span>${name}</span>`;
    html += `<span style="color: var(--text-secondary); margin-left: auto; font-size: 11px;">${step.gasUsed.toLocaleString()} gas</span>`;
    html += `</div>`;
    
    if (step.subcalls && step.subcalls.length > 0 && depth < 4) {
      html += generateExecutionTreeHTML(step.subcalls, depth + 1);
    }
    
    if (depth >= 3 && i < steps.length - 1) {
      html += `<div class="tree-node tree-indent" style="color: var(--text-secondary);">... more calls</div>`;
      break;
    }
  }
  
  return html;
}

function generateStateChangesTab(stateDiffs: StateDiff[]): string {
  let slotRows = '';
  
  for (const diff of stateDiffs.slice(0, 10)) {
    for (const slot of diff.slotChanges.slice(0, 10)) {
      const before = slot.decodedBefore !== undefined ? String(slot.decodedBefore) : shortenHex(slot.beforeValue);
      const after = slot.decodedAfter !== undefined ? String(slot.decodedAfter) : shortenHex(slot.afterValue);
      const deviation = slot.deviation !== undefined ? 
        `<span style="color: ${slot.deviation > 10 ? 'var(--error)' : 'var(--success)'}">${slot.deviation > 0 ? '+' : ''}${slot.deviation.toFixed(2)}%</span>` : '-';
      const anomalyBadge = slot.anomaly?.detected ? '<span class="badge badge-error" style="margin-left: 8px;">ANOMALY</span>' : '';
      
      slotRows += `<tr>
        <td><code>${diff.contractName}</code></td>
        <td>${slot.slotLabel || shortenHex(slot.slot)}</td>
        <td><code>${before}</code></td>
        <td><code>${after}</code></td>
        <td>${deviation}</td>
        <td>${anomalyBadge}</td>
      </tr>`;
    }
  }
  
  return `
<section id="tab-state" class="tab-content">
  <input type="text" class="search-box" placeholder="Search state changes..." id="state-search">
  
  <div class="grid" style="margin-bottom: 16px;">
    <div class="stat-card">
      <div class="stat-value" style="color: var(--accent-orange)">${stateDiffs.length}</div>
      <div class="stat-label">Contracts Modified</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: var(--accent-orange)">${stateDiffs.reduce((sum, d) => sum + d.slotChanges.length, 0)}</div>
      <div class="stat-label">Total Slot Changes</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: ${stateDiffs.some(d => d.slotChanges.some(s => s.anomaly?.detected)) ? 'var(--error)' : 'var(--success)'}">${stateDiffs.reduce((sum, d) => sum + d.slotChanges.filter(s => s.anomaly?.detected).length, 0)}</div>
      <div class="stat-label">Anomalies Detected</div>
    </div>
  </div>
  
  <div class="card">
    <div class="card-header">
      <span>💾 Storage Changes</span>
    </div>
    <div class="card-body" style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Contract</th>
            <th>Variable</th>
            <th>Before</th>
            <th>After</th>
            <th>Deviation</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${slotRows || '<tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">No storage changes detected</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>
</section>`;
}

function generateAlertsTab(alerts: Alert[]): string {
  let alertItems = '';
  
  if (alerts.length === 0) {
    alertItems = '<div style="padding: 24px; text-align: center; color: var(--success);"><span style="font-size: 48px;">✅</span><p style="margin-top: 12px;">No alerts triggered</p></div>';
  } else {
    for (const alert of alerts.slice(0, 30)) {
      alertItems += `<div class="alert-item alert-${alert.severity}">
        <div class="alert-title">
          <span>${alert.title}</span>
          <span class="badge badge-${alert.severity === 'critical' ? 'error' : alert.severity === 'high' ? 'warning' : 'info'}">${alert.severity.toUpperCase()}</span>
        </div>
        <div class="alert-description">${alert.description}</div>
        ${alert.suggestion ? `<div style="margin-top: 8px; font-size: 11px; color: var(--accent-blue);">💡 ${alert.suggestion}</div>` : ''}
      </div>`;
    }
  }
  
  return `
<section id="tab-alerts" class="tab-content">
  <input type="text" class="search-box" placeholder="Filter alerts..." id="alert-search">
  
  <div class="grid" style="margin-bottom: 16px;">
    <div class="stat-card">
      <div class="stat-value" style="color: var(--error)">${alerts.filter(a => a.severity === 'critical').length}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: #ff6b6b">${alerts.filter(a => a.severity === 'high').length}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: var(--warning)">${alerts.filter(a => a.severity === 'medium').length}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: #ffee58">${alerts.filter(a => a.severity === 'low').length}</div>
      <div class="stat-label">Low</div>
    </div>
  </div>
  
  <div id="alerts-container">
    ${alertItems}
  </div>
  
  ${alerts.length > 30 ? `<p style="text-align: center; color: var(--text-secondary); margin-top: 16px;">Showing 30 of ${alerts.length} alerts</p>` : ''}
</section>`;
}

function generateOracleTab(analysis: OracleAnalysis): string {
  let priceRows = '';
  
  for (const obs of analysis.pricesObserved) {
    priceRows += `<tr>
      <td>${obs.oracle}</td>
      <td><strong>${obs.asset}</strong></td>
      <td>$${obs.price.toLocaleString()}</td>
      <td>${obs.source}</td>
      <td><span class="badge badge-${obs.confidence === 'high' ? 'success' : obs.confidence === 'medium' ? 'warning' : 'error'}">${obs.confidence}</span></td>
    </tr>`;
  }
  
  return `
<section id="tab-oracle" class="tab-content">
  <div class="grid" style="margin-bottom: 16px;">
    <div class="stat-card">
      <div class="stat-value" style="color: var(--accent-blue)">${analysis.pricesObserved.length}</div>
      <div class="stat-label">Price Observations</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color: ${analysis.deviations.filter(d => d.thresholdExceeded).length > 0 ? 'var(--error)' : 'var(--success)'}">${analysis.deviations.filter(d => d.thresholdExceeded).length}</div>
      <div class="stat-label">Threshold Deviations</div>
    </div>
    ${analysis.twapAnalysis ? `
    <div class="stat-card">
      <div class="stat-value" style="color: ${Math.abs(analysis.twapAnalysis.deviation) > 5 ? 'var(--warning)' : 'var(--success)'}">${analysis.twapAnalysis.deviation.toFixed(2)}%</div>
      <div class="stat-label">TWAP Deviation</div>
    </div>` : ''}
  </div>
  
  <div class="card">
    <div class="card-header">
      <span>📊 Price Observations</span>
    </div>
    <div class="card-body">
      <table>
        <thead>
          <tr>
            <th>Oracle</th>
            <th>Asset</th>
            <th>Price</th>
            <th>Source</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody>
          ${priceRows || '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No price observations</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>
  
  ${analysis.manipulationIndicators.length > 0 ? `
  <div class="card" style="margin-top: 16px;">
    <div class="card-header">
      <span>⚠️ Manipulation Indicators</span>
    </div>
    <div class="card-body">
      ${analysis.manipulationIndicators.map(ind => `
        <div class="alert-item alert-medium" style="margin-bottom: 12px;">
          <div class="alert-title">
            <span>${ind.type.replace(/-/g, ' ').toUpperCase()}</span>
            <span class="badge badge-warning">${(ind.confidence * 100).toFixed(0)}% confidence</span>
          </div>
          <ul style="margin-top: 8px; padding-left: 20px; font-size: 12px; color: var(--text-secondary);">
            ${ind.evidence.map(e => `<li>${e}</li>`).join('')}
          </ul>
        </div>
      `).join('')}
    </div>
  </div>` : ''}
</section>`;
}

function generateRoleJourneysTab(journeys: RoleJourney[]): string {
  return `
<section id="tab-roles" class="tab-content">
  ${journeys.map(journey => `
    <div class="card" style="margin-bottom: 16px;">
      <div class="card-header">
        <span>👤 Actor: <code>${shortenAddress(journey.actor)}</code></span>
        <span class="badge badge-info">${journey.role}</span>
      </div>
      <div class="card-body">
        <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); margin-bottom: 16px;">
          <div>
            <div style="font-size: 20px; font-weight: bold;">${journey.actions.length}</div>
            <div style="font-size: 11px; color: var(--text-secondary);">Actions</div>
          </div>
          <div>
            <div style="font-size: 20px; font-weight: bold;">${journey.permissionsChecked.length}</div>
            <div style="font-size: 11px; color: var(--text-secondary);">Permission Checks</div>
          </div>
          <div>
            <div style="font-size: 20px; font-weight: bold; color: ${journey.privilegesEscalated.length > 0 ? 'var(--warning)' : 'var(--success)'}">${journey.privilegesEscalated.length}</div>
            <div style="font-size: 11px; color: var(--text-secondary);">Privilege Escalations</div>
          </div>
        </div>
        
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Function</th>
              <th>Contract</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${journey.actions.slice(0, 15).map(action => `
              <tr>
                <td>${action.order}</td>
                <td><code>${action.function}</code></td>
                <td><code>${shortenAddress(action.contract)}</code></td>
                <td>${action.success ? '<span style="color: var(--success)">✅</span>' : '<span style="color: var(--error)">❌</span>'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `).join('')}
</section>`;
}

function generateSidebar(hasData: boolean, hasOracle: boolean, hasRoles: boolean): string {
  return `
<aside class="sidebar">
  <div class="sidebar-header">
    <div class="logo">🔍 Trackator</div>
  </div>
  
  <nav class="nav-section">
    <div class="nav-title">Analysis</div>
    <div class="nav-item active" onclick="showTab('dashboard')">
      <span class="nav-icon">📊</span> Dashboard
    </div>
    <div class="nav-item" onclick="showTab('execution')">
      <span class="nav-icon">🔄</span> Execution Flow
    </div>
    <div class="nav-item" onclick="showTab('state')">
      <span class="nav-icon">💾</span> State Changes
    </div>
    <div class="nav-item" onclick="showTab('alerts')">
      <span class="nav-icon">⚠️</span> Alerts
    </div>
    ${hasOracle ? `
    <div class="nav-item" onclick="showTab('oracle')">
      <span class="nav-icon">📈</span> Oracle Analysis
    </div>` : ''}
    ${hasRoles ? `
    <div class="nav-item" onclick="showTab('roles')">
      <span class="nav-icon">👤</span> Role Journeys
    </div>` : ''}
  </nav>
  
  <nav class="nav-section">
    <div class="nav-title">Export</div>
    <div class="nav-item" onclick="window.print()">
      <span class="nav-icon">🖨️</span> Print Report
    </div>
    <div class="nav-item" onclick="downloadJSON()">
      <span class="nav-icon">💾</span> Export JSON
    </div>
  </nav>
</aside>`;
}

function generateJavaScript(_trace: FoundryTrace, _stateDiffs: StateDiff[], _alerts: Alert[], _oracleAnalysis?: OracleAnalysis): string {
  return `
<script>
// Tab switching
function showTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
  
  document.getElementById('tab-' + tabId)?.classList.add('active');
  event.target.closest('.nav-item')?.classList.add('active');
}

// Search filtering
document.getElementById('alert-search')?.addEventListener('input', function(e) {
  const query = e.target.value.toLowerCase();
  document.querySelectorAll('.alert-item').forEach(item => {
    item.style.display = item.textContent.toLowerCase().includes(query) ? '' : 'none';
  });
});

document.getElementById('state-search')?.addEventListener('input', function(e) {
  const query = e.target.value.toLowerCase();
  document.querySelectorAll('#tab-state tbody tr').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(query) ? '' : 'none';
  });
});

// Download JSON
function downloadJSON() {
  const data = ${JSON.stringify({ trace: _trace, stateDiffs: _stateDiffs, alerts: _alerts })};
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'trackator-analysis.json';
  a.click();
}
</script>`;
}

function generateChartIncludes(): string {
  return `
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>`;
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
    '0x18cbafe5': 'swapExactTokensForETH'
  };
  
  return selectors[calldata.slice(0, 10)] || null;
}
