"use strict";
// ============================================================
// TRACKATOR Tier 3 - Analyze Command
// Orchestrates runtime trace analysis and triple output
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
exports.runAnalyze = runAnalyze;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const boxen_1 = __importDefault(require("boxen"));
// Tier 3 imports
const foundry_trace_parser_1 = require("./foundry-trace-parser");
const state_diff_engine_1 = require("./state-diff-engine");
const oracle_analyzer_1 = require("./oracle-analyzer");
const alert_checker_1 = require("./alert-checker");
// Renderer imports
const terminal_renderer_1 = require("../renderers/terminal-renderer");
const md_renderer_1 = require("../renderers/md-renderer");
const html_renderer_1 = require("../renderers/html-renderer");
/**
 * Main entry point for `trackator analyze` command
 */
async function runAnalyze(traceFilePath, options) {
    const startTime = Date.now();
    console.log('');
    console.log(chalk_1.default.blue.bold('╔══════════════════════════════════════════════╗'));
    console.log(chalk_1.default.blue.bold('║         TIER 3: RUNTIME ANALYSIS                ║'));
    console.log(chalk_1.default.blue.bold('╚══════════════════════════════════════════════╝'));
    console.log('');
    // Step 1: Validate trace file exists
    if (!fs.existsSync(traceFilePath)) {
        console.error(chalk_1.default.red(`✖ Trace file not found: ${traceFilePath}`));
        process.exit(1);
    }
    // Step 2: Load enriched data (from Tier 2) if available
    let enrichedData = null;
    const enrichPath = path.join(options.output, 'trackator-enrich.json');
    if (fs.existsSync(enrichPath)) {
        const loadSpinner = (0, ora_1.default)('Loading enrichment data...').start();
        try {
            enrichedData = JSON.parse(fs.readFileSync(enrichPath, 'utf-8'));
            loadSpinner.succeed(`Loaded enrichment data`);
        }
        catch (e) {
            loadSpinner.warn('Could not load enrichment data, continuing without it');
        }
    }
    else if (options.verbose) {
        console.log(chalk_1.default.gray('No enrichment data found. Run `trackator enrich` first for enhanced analysis.'));
    }
    // Step 3: Parse Foundry trace
    const parseSpinner = (0, ora_1.default)('Parsing Foundry trace JSON...').start();
    let trace;
    try {
        trace = (0, foundry_trace_parser_1.parseFoundryTrace)(traceFilePath, {
            verbose: options.verbose,
            includeOpcodes: false, // Opcodes are verbose, skip by default
            maxDepth: 50
        });
        parseSpinner.succeed(`Parsed trace: ${trace.trace.length} steps, ${trace.logs.length} logs`);
    }
    catch (error) {
        parseSpinner.fail(`Failed to parse trace: ${error.message}`);
        process.exit(1);
    }
    // Step 4: Compare with baseline if provided
    let baselineTrace;
    if (options.baselineFile && fs.existsSync(options.baselineFile)) {
        const baselineSpinner = (0, ora_1.default)('Loading baseline trace...').start();
        try {
            baselineTrace = (0, foundry_trace_parser_1.parseFoundryTrace)(options.baselineFile, { verbose: options.verbose });
            baselineSpinner.succeed('Baseline loaded');
        }
        catch (e) {
            baselineSpinner.warn('Failed to load baseline, skipping comparison');
        }
    }
    // Step 5: Compute state diffs
    const stateSpinner = (0, ora_1.default)('Computing state differences...').start();
    const stateDiffs = (0, state_diff_engine_1.computeStateDiffs)(trace, {
        alertRules: enrichedData?.alertRules || [],
        verbose: options.verbose
    });
    // If baseline provided, compute differential analysis
    if (baselineTrace) {
        const baselineDiffs = (0, state_diff_engine_1.computeStateDiffs)(baselineTrace);
        console.log(chalk_1.default.gray('\nBaseline comparison available'));
    }
    stateSpinner.succeed(`Computed ${stateDiffs.length} contract state diffs, ${stateDiffs.reduce((sum, d) => sum + d.slotChanges.length, 0)} slot changes`);
    // Step 6: Oracle analysis (if enabled)
    let oracleAnalysis;
    if (options.oracleAnalysis) {
        const oracleSpinner = (0, ora_1.default)('Analyzing oracle interactions...').start();
        try {
            oracleAnalysis = (0, oracle_analyzer_1.analyzeOracles)(trace, {
                deviationThreshold: 5,
                twapWindow: 1800,
                verbose: options.verbose
            });
            const deviationCount = oracleAnalysis.deviations.filter(d => d.thresholdExceeded).length;
            const manipulationCount = oracleAnalysis.manipulationIndicators.length;
            oracleSpinner.succeed(`Oracle analysis: ${oracleAnalysis.pricesObserved.length} observations, ${deviationCount} deviations, ${manipulationCount} manipulation signals`);
        }
        catch (e) {
            oracleSpinner.warn('Oracle analysis completed with warnings');
            oracleAnalysis = undefined; // Continue without it
        }
    }
    // Step 7: Run full analysis with alert checking
    const analysisSpinner = (0, ora_1.default)('Running alert checks and anomaly detection...').start();
    const analysisResult = (0, alert_checker_1.runAnalysis)(trace, {
        alertRules: enrichedData?.alertRules || [],
        minSeverity: options.alertLevel || 'info',
        focusContract: options.focusContract,
        focusFunction: options.focusFunction,
        includeGasAnalysis: options.gasAnalysis,
        includeOracleAnalysis: !!oracleAnalysis,
        includeRoleTracking: options.roleTracking,
        verbose: options.verbose
    });
    const { alerts, roleJourneys, summary } = analysisResult;
    analysisSpinner.succeed(`Analysis complete: ${alerts.length} alerts triggered (${alerts.filter(a => a.severity === 'critical').length} critical)`);
    // Ensure output directory exists
    const outputDir = path.resolve(options.output);
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    // Prepare output data
    const outputData = {
        runId: generateRunId(),
        command: 'analyze',
        timestamp: new Date().toISOString(),
        duration: Date.now() - startTime,
        trace,
        stateDiffs,
        oracleAnalysis,
        roleJourneys,
        alerts,
        summary
    };
    // Step 8: Generate outputs based on format option
    // Terminal Output (always show unless format is only md/html)
    if (options.format === 'all' || options.format === 'terminal') {
        (0, terminal_renderer_1.renderTerminal)(trace, stateDiffs, alerts, oracleAnalysis, roleJourneys, summary);
    }
    // Markdown Output
    if (options.format === 'all' || options.format === 'md') {
        const mdSpinner = (0, ora_1.default)('Generating Markdown report...').start();
        try {
            const mdContent = (0, md_renderer_1.generateMarkdownReport)(outputDir, trace, stateDiffs, alerts, oracleAnalysis, roleJourneys, summary);
            const mdPath = path.join(outputDir, 'trackator-analysis.md');
            fs.writeFileSync(mdPath, mdContent);
            mdSpinner.succeed(`Markdown report saved to ${mdPath}`);
        }
        catch (error) {
            mdSpinner.fail(`Failed to generate markdown: ${error.message}`);
        }
    }
    // HTML Output
    if (options.format === 'all' || options.format === 'html') {
        const htmlSpinner = (0, ora_1.default)('Generating interactive HTML report...').start();
        try {
            const htmlPath = (0, html_renderer_1.generateHtmlReport)(outputDir, trace, stateDiffs, alerts, oracleAnalysis, roleJourneys, summary);
            htmlSpinner.succeed(`HTML report saved to ${htmlPath}`);
        }
        catch (error) {
            htmlSpinner.fail(`Failed to generate HTML: ${error.message}`);
        }
    }
    // Save raw JSON data
    const jsonPath = path.join(outputDir, 'trackator-analysis.json');
    fs.writeFileSync(jsonPath, JSON.stringify(outputData, null, 2));
    // Print final summary
    printFinalSummary(summary, alerts, outputDir, Date.now() - startTime);
}
/**
 * Print final summary box
 */
function printFinalSummary(summary, alerts, outputDir, duration) {
    const criticalCount = alerts.filter(a => a.severity === 'critical').length;
    const highCount = alerts.filter(a => a.severity === 'high').length;
    const verdict = summary?.verdict || 'pass';
    const verdictColor = verdict === 'pass' ? chalk_1.default.green : verdict === 'fail' ? chalk_1.default.red : chalk_1.default.yellow;
    const verdictIcon = verdict === 'pass' ? '✅' : verdict === 'fail' ? '❌' : '⚠️';
    console.log('');
    console.log((0, boxen_1.default)(verdictColor.bold(`${verdictIcon} ANALYSIS COMPLETE: ${verdict.toUpperCase()}\n`) +
        chalk_1.default.white(`Execution Steps: ${summary?.totalSteps || 0}\n`) +
        chalk_1.default.white(`Contracts Touched: ${summary?.totalContractsTouched || 0}\n`) +
        chalk_1.default.white(`Storage Slots Changed: ${summary?.totalStorageSlotsChanged || 0}\n`) +
        chalk_1.default.red(`Critical Alerts: ${criticalCount}\n`) +
        chalk_1.default.hex('#ff6b6b')(`High Alerts: ${highCount}\n`) +
        chalk_1.default.white(`Total Alerts: ${alerts.length}\n`) +
        chalk_1.default.white(`Gas Efficiency: ${summary?.gasEfficiency.percentage.toFixed(1) || 0}%\n`) +
        chalk_1.default.white(`Duration: ${duration}ms\n`) +
        chalk_1.default.gray(`Output saved to: ${outputDir}`), {
        padding: 1,
        borderColor: verdict === 'pass' ? 'green' : verdict === 'fail' ? 'red' : 'yellow',
        borderStyle: 'round'
    }));
    // If there are critical/high alerts, print quick actions
    if (criticalCount > 0 || highCount > 0) {
        console.log('');
        console.log(chalk_1.default.yellow.bold('Recommended Next Steps:'));
        console.log(chalk_1.default.yellow('  1. Review critical alerts in HTML report'));
        console.log(chalk_1.default.yellow('  2. Check state changes for affected contracts'));
        console.log(chalk_1.default.yellow('  3. Verify oracle prices against external sources'));
        console.log(chalk_1.default.yellow('  4. Re-run with different inputs to confirm findings'));
    }
}
function generateRunId() {
    return `run_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}
//# sourceMappingURL=analyze-command.js.map