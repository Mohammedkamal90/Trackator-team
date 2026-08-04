"use strict";
// ============================================================
// TRACKATOR Tier 2 - Enrich Command
// Orchestrates AI enrichment pipeline
// ============================================================
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runEnrich = runEnrich;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const boxen_1 = __importDefault(require("boxen"));
const invariant_generator_1 = require("./invariant-generator");
/**
 * Main entry point for `trackator enrich` command
 */
async function runEnrich(inputDir, options) {
    const startTime = Date.now();
    console.log('');
    console.log(chalk_1.default.magenta.bold('╔══════════════════════════════════════════════╗'));
    console.log(chalk_1.default.magenta.bold('║         TIER 2: AI ENRICHMENT                  ║'));
    console.log(chalk_1.default.magenta.bold('╚══════════════════════════════════════════════╝'));
    console.log('');
    // Load existing init data if available
    const initDataPath = path.join(inputDir, 'trackator-init.json');
    let contracts = [];
    if (fs.existsSync(initDataPath)) {
        const initData = JSON.parse(fs.readFileSync(initDataPath, 'utf-8'));
        contracts = initData.contracts || [];
        if (options.verbose) {
            console.log(chalk_1.default.gray('Loaded ' + contracts.length + ' contracts from previous init'));
        }
    }
    // Step 1: Run enrichment pipeline
    const enrichSpinner = (0, ora_1.default)('Running enrichment pipeline...').start();
    const enrichmentResult = (0, invariant_generator_1.runEnrichment)({
        xrayFile: options.xrayFile,
        breakdownFile: options.breakdownFile,
        protocolType: options.protocolType,
        contracts,
        generateAlerts: options.generateAlerts,
        verbose: options.verbose
    });
    enrichSpinner.succeed('Enrichment complete: ' + enrichmentResult.invariants.length + ' invariants, ' + enrichmentResult.alertRules.length + ' alert rules');
    // Ensure output directory exists
    const outputDir = path.resolve(options.output);
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    // Prepare output data
    const outputData = {
        runId: generateRunId(),
        command: 'enrich',
        timestamp: new Date().toISOString(),
        duration: Date.now() - startTime,
        xrayOutput: enrichmentResult.xray,
        breakdownOutput: enrichmentResult.breakdown,
        alertRules: enrichmentResult.alertRules
    };
    // Print terminal output
    printTerminalEnrichment(enrichmentResult, options.verbose);
    // Generate markdown report
    await generateMarkdownReport(outputDir, enrichmentResult);
    // Generate HTML report
    await generateHtmlReport(outputDir, enrichmentResult);
    // Save raw data
    const jsonPath = path.join(outputDir, 'trackator-enrich.json');
    fs.writeFileSync(jsonPath, JSON.stringify((0, invariant_generator_1.exportEnrichmentResult)(enrichmentResult), null, 2));
    // Print summary
    const criticalCount = enrichmentResult.alertRules.filter(r => r.severity === 'critical').length;
    const highCount = enrichmentResult.alertRules.filter(r => r.severity === 'high').length;
    console.log('');
    console.log((0, boxen_1.default)(chalk_1.default.green.bold('✓ Enrichment Complete\n') +
        chalk_1.default.white('Protocol Type: ' + enrichmentResult.xray.protocolType.toUpperCase() + '\n') +
        chalk_1.default.white('Invariants Generated: ' + enrichmentResult.invariants.length + '\n') +
        chalk_1.default.white('Alert Rules Created: ' + enrichmentResult.alertRules.length + '\n') +
        chalk_1.default.red('Critical Alerts: ' + criticalCount + '\n') +
        chalk_1.default.hex('#ff6b6b')('High Alerts: ' + highCount + '\n') +
        chalk_1.default.white('Duration: ' + (Date.now() - startTime) + 'ms\n') +
        chalk_1.default.gray('Output saved to: ' + outputDir), {
        padding: 1,
        borderColor: 'magenta',
        borderStyle: 'round'
    }));
}
/**
 * Print terminal output for enrichment results
 */
function printTerminalEnrichment(result, verbose = false) {
    console.log('\n');
    console.log(chalk_1.default.white.bold('═'.repeat(60)));
    console.log(chalk_1.default.white.bold('           ENRICHMENT RESULTS'));
    console.log(chalk_1.default.white.bold('═'.repeat(60)));
    console.log('');
    // Protocol Classification
    console.log(chalk_1.default.cyan.bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.cyan.bold('│              PROTOCOL CLASSIFICATION                     │'));
    console.log(chalk_1.default.cyan.bold('├─────────────────────────────────────────────────────────────┤'));
    console.log(chalk_1.default.white('  Type: ' + chalk_1.default.bold(result.xray.protocolType.toUpperCase())));
    console.log(chalk_1.default.white('  Confidence: Based on code pattern analysis'));
    console.log(chalk_1.default.cyan.bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
    // Threat Model Summary
    console.log(chalk_1.default.yellow.bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.yellow.bold('│                   THREAT MODEL                            │'));
    console.log(chalk_1.default.yellow.bold('├─────────────────────────────────────────────────────────────┤'));
    const threatModel = result.xray.threatModel;
    console.log(chalk_1.default.white('  Assets at Risk: ' + threatModel.assetsAtRisk.length));
    console.log(chalk_1.default.white('  Entry Points:  ' + threatModel.entryPoints.length));
    console.log(chalk_1.default.white('  Adversaries:   ' + result.xray.adversaryProfiles.length));
    console.log(chalk_1.default.white('  Attack Vectors: ' + result.xray.attackVectors.length));
    if (threatModel.assetsAtRisk.length > 0) {
        console.log(chalk_1.default.gray('\n  Key Assets:'));
        for (const asset of threatModel.assetsAtRisk.slice(0, 5)) {
            console.log(chalk_1.default.gray('    • ' + asset.type + ': ' + asset.name + ' (' + asset.location + ')'));
        }
    }
    console.log(chalk_1.default.yellow.bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
    // Invariants Summary
    console.log(chalk_1.default.green.bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.green.bold('│                    INVARIANTS                              │'));
    console.log(chalk_1.default.green.bold('├─────────────────────────────────────────────────────────────┤'));
    const invariantCategories = groupBy(result.invariants, 'category');
    for (const [category, invs] of Object.entries(invariantCategories)) {
        const icon = getCategoryIcon(category);
        console.log(chalk_1.default.white('  ' + icon + ' ' + category + ': ' + invs.length + ' invariants'));
        if (verbose) {
            for (const inv of invs.slice(0, 3)) {
                const severityColor = getSeverityColor(inv.severity);
                console.log(chalk_1.default.gray('      - [' + severityColor(inv.severity) + '] ' + inv.template.substring(0, 60) + '...'));
            }
        }
    }
    console.log(chalk_1.default.green.bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
    // Alert Rules Summary
    console.log(chalk_1.default.red.bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.red.bold('│                   ALERT RULES                              │'));
    console.log(chalk_1.default.red.bold('├─────────────────────────────────────────────────────────────┤'));
    const severityGroups = groupBy(result.alertRules, 'severity');
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    for (const severity of severityOrder) {
        const rules = severityGroups[severity] || [];
        if (rules.length > 0) {
            const color = getSeverityColor(severity);
            console.log(color('  ' + severity.toUpperCase() + ' (' + rules.length + '):'));
            for (const rule of rules.slice(0, 3)) {
                console.log(chalk_1.default.gray('      • ' + rule.name));
            }
            if (rules.length > 3) {
                console.log(chalk_1.default.gray('      ... and ' + (rules.length - 3) + ' more'));
            }
        }
    }
    console.log(chalk_1.default.red.bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
    // Trust Assumptions
    if (result.xray.trustAssumptions.length > 0) {
        console.log(chalk_1.default.hex('#9b59b6').bold('┌─────────────────────────────────────────────────────────────┐'));
        console.log(chalk_1.default.hex('#9b59b6').bold('│                TRUST ASSUMPTIONS                           │'));
        console.log(chalk_1.default.hex('#9b59b6').bold('├─────────────────────────────────────────────────────────────┤'));
        for (const ta of result.xray.trustAssumptions.slice(0, 5)) {
            const confidenceIcon = ta.confidence === 'high' ? '\u{1F7E2}' :
                ta.confidence === 'medium' ? '\u{1F7E1}' : '\u{1F534}';
            console.log(chalk_1.default.white('  ' + confidenceIcon + ' [' + ta.category + '] ' + ta.assumption));
            console.log(chalk_1.default.gray('     If violated: ' + ta.ifViolated));
        }
        console.log(chalk_1.default.hex('#9b59b6').bold('└─────────────────────────────────────────────────────────────┘'));
        console.log('');
    }
}
/**
 * Generate Markdown report for enrichment
 */
async function generateMarkdownReport(outputDir, result) {
    const mdPath = path.join(outputDir, 'trackator-enrich-report.md');
    let md = '# Trackator Enrichment Report\n\n';
    md += '**Generated:** ' + new Date().toISOString() + '\n';
    md += '**Protocol Type:** ' + result.xray.protocolType + '\n\n';
    // Table of Contents
    md += '## Table of Contents\n\n';
    md += '- [Executive Summary](#executive-summary)\n';
    md += '- [Threat Model](#threat-model)\n';
    md += '- [Invariants](#invariants)\n';
    md += '- [Trust Assumptions](#trust-assumptions)\n';
    md += '- [Attack Vectors](#attack-vectors)\n';
    md += '- [Alert Rules](#alert-rules)\n';
    md += '- [Component Analysis](#component-analysis)\n';
    md += '- [Money Flows](#money-flows)\n\n';
    // Executive Summary
    md += '## Executive Summary\n\n';
    md += '| Metric | Value |\n';
    md += '|--------|-------|\n';
    md += '| Protocol Type | **' + result.xray.protocolType.toUpperCase() + '** |\n';
    md += '| Total Invariants | ' + result.invariants.length + ' |\n';
    md += '| Alert Rules | ' + result.alertRules.length + ' |\n';
    md += '| Critical Alerts | ' + result.alertRules.filter((r) => r.severity === 'critical').length + ' |\n';
    md += '| High Alerts | ' + result.alertRules.filter((r) => r.severity === 'high').length + ' |\n';
    md += '| Assets at Risk | ' + result.xray.threatModel.assetsAtRisk.length + ' |\n';
    md += '| Entry Points | ' + result.xray.threatModel.entryPoints.length + ' |\n\n';
    // Threat Model
    md += '## Threat Model\n\n';
    md += '### Assets at Risk\n\n';
    md += '| Asset | Type | Location |\n';
    md += '|-------|------|----------|\n';
    for (const asset of result.xray.threatModel.assetsAtRisk) {
        md += '| ' + asset.name + ' | ' + asset.type + ' | ' + asset.location + ' |\n';
    }
    md += '\n### Entry Points\n\n';
    md += '| Function | Contract | Access | Criticality |\n';
    md += '|----------|----------|--------|-------------|\n';
    for (const ep of result.xray.threatModel.entryPoints) {
        const bt = String.fromCharCode(96);
        md += '| ' + bt + ep.name + bt + ' | ' + ep.contract + ' | ' + ep.access + ' | ' + ep.criticality + ' |\n';
    }
    md += '\n';
    // Invariants
    md += '## Invariants\n\n';
    md += '| ID | Category | Severity | Template | Checkable |\n';
    md += '|----|----------|----------|----------|----------|\n';
    for (const inv of result.invariants) {
        md += '| ' + inv.id + ' | ' + inv.category + ' | ' + inv.severity + ' | ' + inv.template.substring(0, 50) + '... | ' + (inv.checkable ? '✅' : '❌') + ' |\n';
    }
    md += '\n';
    // Trust Assumptions
    md += '## Trust Assumptions\n\n';
    md += '| ID | Category | Assumption | If Violated | Confidence |\n';
    md += '|----|----------|------------|-------------|------------|\n';
    for (const ta of result.xray.trustAssumptions) {
        md += '| ' + ta.id + ' | ' + ta.category + ' | ' + ta.assumption + ' | ' + ta.ifViolated + ' | ' + ta.confidence + ' |\n';
    }
    md += '\n';
    // Attack Vectors
    md += '## Attack Vectors\n\n';
    md += '| Name | Category | Likelihood | Severity | Impact |\n';
    md += '|------|----------|------------|----------|--------|\n';
    for (const av of result.xray.attackVectors) {
        md += '| ' + av.name + ' | ' + av.category + ' | ' + av.likelihood + ' | ' + av.severity + ' | ' + av.impact + ' |\n';
    }
    md += '\n';
    // Alert Rules
    md += '## Alert Rules\n\n';
    md += '### Critical & High Priority\n\n';
    md += '| Rule Name | Category | Condition | Mitigation |\n';
    md += '|-----------|----------|-----------|------------|\n';
    for (const rule of result.alertRules.filter((r) => r.severity === 'critical' || r.severity === 'high')) {
        md += '| ' + rule.name + ' | ' + rule.category + ' | ' + JSON.stringify(rule.condition).substring(0, 50) + '... | ' + ((rule.mitigation && rule.mitigation.substring(0, 40)) || '-') + ' |\n';
    }
    md += '\n';
    // Component Analysis
    if (result.breakdown?.components) {
        md += '## Component Analysis\n\n';
        md += '| Component | Type | Risk Level | Responsibility |\n';
        md += '|-----------|------|------------|---------------|\n';
        for (const comp of result.breakdown.components) {
            md += '| ' + comp.name + ' | ' + comp.type + ' | ' + comp.riskLevel + ' | ' + ((comp.responsibility && comp.responsibility.substring(0, 40)) || '') + '... |\n';
        }
        md += '\n';
    }
    // Money Flows
    if (result.breakdown?.moneyFlows) {
        md += '## Money Flows\n\n';
        for (const flow of result.breakdown.moneyFlows.slice(0, 10)) {
            md += '### ' + flow.name + '\n\n';
            md += '**Trigger:** ' + flow.trigger + '\n\n';
            md += '**Steps:**\n';
            for (const step of flow.steps) {
                md += step.order + '. ' + step.action + ': ' + step.from + ' → ' + step.to + ' (' + step.asset + ')\n';
            }
            md += '\n**Conditions:**\n';
            for (const cond of flow.conditions) {
                md += '- ' + cond + '\n';
            }
            md += '\n';
        }
    }
    fs.writeFileSync(mdPath, md);
}
/**
 * Generate HTML report for enrichment
 */
async function generateHtmlReport(outputDir, result) {
    const htmlPath = path.join(outputDir, 'trackator-enrich-report.html');
    // Build HTML report using string concatenation only
    let html = '';
    html += '<!DOCTYPE html>\n';
    html += '<html lang="en">\n';
    html += '<head>\n';
    html += '  <meta charset="UTF-8">\n';
    html += '  <title>Trackator Enrichment Report</title>\n';
    html += '  <style>\n';
    html += '    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #1a1a2e; color: #eee; }\n';
    html += '    h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 0.5rem; }\n';
    html += '    h2 { color: #ff6b6b; margin-top: 2rem; }\n';
    html += '    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }\n';
    html += '    th, td { border: 1px solid #444; padding: 0.75rem; text-align: left; }\n';
    html += '    th { background: #16213e; color: #00d4ff; }\n';
    html += '    tr:hover { background: #16213e; }\n';
    html += '    .critical { color: #ff6b6b; }\n';
    html += '    .high { color: #ffa726; }\n';
    html += '    .medium { color: #ffee58; }\n';
    html += '    .low { color: #69f0ae; }\n';
    html += '    .safe { color: #ffffff; }\n';
    html += '  </style>\n';
    html += '</head>\n';
    html += '<body>\n';
    html += '  <h1>Trackator Enrichment Report</h1>\n';
    html += '  <p><strong>Protocol Type:</strong> ' + (result.xray?.protocolType || 'Unknown') + '</p>\n';
    html += '  <p><strong>Generated:</strong> ' + new Date().toISOString() + '</p>\n';
    // Alert Rules Section
    if (result.alertRules && result.alertRules.length > 0) {
        html += '  <h2>Alert Rules</h2>\n';
        html += '  <table>\n';
        html += '    <tr><th>Name</th><th>Severity</th><th>Category</th><th>Condition</th><th>Mitigation</th></tr>\n';
        for (const rule of result.alertRules) {
            const sevClass = rule.severity || 'info';
            html += '    <tr>\n';
            html += '      <td>' + (rule.name || '-') + '</td>\n';
            html += '      <td class="' + sevClass + '">' + rule.severity + '</td>\n';
            html += '      <td>' + (rule.category || '-') + '</td>\n';
            html += '      <td>' + (JSON.stringify(rule.condition).substring(0, 80) || '-') + '</td>\n';
            html += '      <td>' + (((rule.mitigation || '').substring(0, 80)) || '-') + '</td>\n';
            html += '    </tr>\n';
        }
        html += '  </table>\n';
    }
    // Invariants Section
    if (result.invariants && result.invariants.length > 0) {
        html += '  <h2>Invariants</h2>\n';
        html += '  <table>\n';
        html += '    <tr><th>ID</th><th>Category</th><th>Severity</th><th>Template</th></tr>\n';
        for (const inv of result.invariants) {
            html += '    <tr>\n';
            html += '      <td>' + (inv.id || '-') + '</td>\n';
            html += '      <td>' + (inv.category || '-') + '</td>\n';
            html += '      <td class="' + (inv.severity || 'info') + '">' + inv.severity + '</td>\n';
            html += '      <td>' + ((inv.template || '').substring(0, 100)) + '</td>\n';
            html += '    </tr>\n';
        }
        html += '  </table>\n';
    }
    // Attack Vectors Section
    if (result.xray?.attackVectors && result.xray.attackVectors.length > 0) {
        html += '  <h2>Attack Vectors</h2>\n';
        html += '  <table>\n';
        html += '    <tr><th>Name</th><th>Category</th><th>Likelihood</th><th>Severity</th><th>Impact</th></tr>\n';
        for (const av of result.xray.attackVectors) {
            html += '    <tr>\n';
            html += '      <td>' + (av.name || '-') + '</td>\n';
            html += '      <td>' + (av.category || '-') + '</td>\n';
            html += '      <td>' + (av.likelihood || '-') + '</td>\n';
            html += '      <td class="' + (av.severity || 'info') + '">' + av.severity + '</td>\n';
            html += '      <td>' + (av.impact || '-') + '</td>\n';
            html += '    </tr>\n';
        }
        html += '  </table>\n';
    }
    // Trust Assumptions Section
    if (result.xray?.trustAssumptions && result.xray.trustAssumptions.length > 0) {
        html += '  <h2>Trust Assumptions</h2>\n';
        html += '  <table>\n';
        html += '    <tr><th>Category</th><th>Assumption</th><th>If Violated</th><th>Confidence</th></tr>\n';
        for (const ta of result.xray.trustAssumptions) {
            const confColor = ta.confidence === 'high' ? '#69f0ae' :
                ta.confidence === 'medium' ? '#ffa726' : '#ff6b6b';
            html += '    <tr>\n';
            html += '      <td>' + (ta.category || '-') + '</td>\n';
            html += '      <td>' + ((ta.assumption || '-').substring(0, 100)) + '</td>\n';
            html += '      <td>' + ((ta.ifViolated || '-').substring(0, 100)) + '</td>\n';
            html += '      <td style="color: ' + confColor + '">' + ta.confidence + '</td>\n';
            html += '    </tr>\n';
        }
        html += '  </table>\n';
    }
    html += '</body>\n';
    html += '</html>\n';
    fs.writeFileSync(htmlPath, html);
}
// ============================================================
// UTILITY FUNCTIONS
// ============================================================
function generateRunId() {
    return 'run_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
}
function groupBy(array, key) {
    return array.reduce((groups, item) => {
        const value = item[key];
        groups[value] = groups[value] || [];
        groups[value].push(item);
        return groups;
    }, {});
}
function getCategoryIcon(category) {
    const icons = {
        'accounting': '\u{1F4B0}',
        'bounds': '\u{1F4CF}',
        'ordering': '\u{1F4CB}',
        'state-machine': '\u{2699}\u{FE0F}',
        'oracle': '\u{1F4CA}',
        'permission': '\u{1F510}'
    };
    return icons[category] || '\u{1F4CC}';
}
function getSeverityColor(severity) {
    const colors = {
        'critical': chalk_1.default.red,
        'high': chalk_1.default.hex('#ff6b6b'),
        'medium': chalk_1.default.hex('#ffa726'),
        'low': chalk_1.default.hex('#ffee58'),
        'info': chalk_1.default.blue
    };
    return colors[severity] || chalk_1.default.white;
}
// Note: exportEnrichmentResult is now imported from invariant-generator
//# sourceMappingURL=enrich-command.js.map