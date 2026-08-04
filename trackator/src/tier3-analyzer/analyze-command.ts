// ============================================================
// TRACKATOR Tier 3 - Analyze Command
// Orchestrates runtime trace analysis and triple output
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import boxen from 'boxen';
import {
  TrackatorOutput,
  FoundryTrace,
  StateDiff,
  Alert,
  OracleAnalysis,
  AnalysisSummary,
  RoleJourney
} from '../types';

// Tier 3 imports
import { parseFoundryTrace } from './foundry-trace-parser';
import { computeStateDiffs, generateStateDiffSummary } from './state-diff-engine';
import { analyzeOracles } from './oracle-analyzer';
import { runAnalysis } from './alert-checker';

// Renderer imports
import { renderTerminal } from '../renderers/terminal-renderer';
import { generateMarkdownReport } from '../renderers/md-renderer';
import { generateHtmlReport } from '../renderers/html-renderer';

export interface AnalyzeOptions {
  output: string;
  format: 'all' | 'md' | 'html' | 'terminal';
  alertLevel: string;
  baselineFile?: string;
  focusContract?: string;
  focusFunction?: string;
  gasAnalysis: boolean;
  oracleAnalysis: boolean;
  roleTracking: boolean;
  verbose: boolean;
}

/**
 * Main entry point for `trackator analyze` command
 */
export async function runAnalyze(
  traceFilePath: string,
  options: AnalyzeOptions
): Promise<void> {
  const startTime = Date.now();
  
  console.log('');
  console.log(chalk.blue.bold('╔══════════════════════════════════════════════╗'));
  console.log(chalk.blue.bold('║         TIER 3: RUNTIME ANALYSIS                ║'));
  console.log(chalk.blue.bold('╚══════════════════════════════════════════════╝'));
  console.log('');
  
  // Step 1: Validate trace file exists
  if (!fs.existsSync(traceFilePath)) {
    console.error(chalk.red(`✖ Trace file not found: ${traceFilePath}`));
    process.exit(1);
  }
  
  // Step 2: Load enriched data (from Tier 2) if available
  let enrichedData = null;
  const enrichPath = path.join(options.output, 'trackator-enrich.json');
  
  if (fs.existsSync(enrichPath)) {
    const loadSpinner = ora('Loading enrichment data...').start();
    try {
      enrichedData = JSON.parse(fs.readFileSync(enrichPath, 'utf-8'));
      loadSpinner.succeed(`Loaded enrichment data`);
    } catch (e) {
      loadSpinner.warn('Could not load enrichment data, continuing without it');
    }
  } else if (options.verbose) {
    console.log(chalk.gray('No enrichment data found. Run `trackator enrich` first for enhanced analysis.'));
  }
  
  // Step 3: Parse Foundry trace
  const parseSpinner = ora('Parsing Foundry trace JSON...').start();
  
  let trace: FoundryTrace;
  try {
    trace = parseFoundryTrace(traceFilePath, {
      verbose: options.verbose,
      includeOpcodes: false, // Opcodes are verbose, skip by default
      maxDepth: 50
    });
    parseSpinner.succeed(`Parsed trace: ${trace.trace.length} steps, ${trace.logs.length} logs`);
  } catch (error: any) {
    parseSpinner.fail(`Failed to parse trace: ${error.message}`);
    process.exit(1);
  }
  
  // Step 4: Compare with baseline if provided
  let baselineTrace: FoundryTrace | undefined;
  if (options.baselineFile && fs.existsSync(options.baselineFile)) {
    const baselineSpinner = ora('Loading baseline trace...').start();
    try {
      baselineTrace = parseFoundryTrace(options.baselineFile, { verbose: options.verbose });
      baselineSpinner.succeed('Baseline loaded');
    } catch (e) {
      baselineSpinner.warn('Failed to load baseline, skipping comparison');
    }
  }
  
  // Step 5: Compute state diffs
  const stateSpinner = ora('Computing state differences...').start();
  const stateDiffs = computeStateDiffs(trace, {
    alertRules: enrichedData?.alertRules || [],
    verbose: options.verbose
  });
  
  // If baseline provided, compute differential analysis
  if (baselineTrace) {
    const baselineDiffs = computeStateDiffs(baselineTrace);
    console.log(chalk.gray('\nBaseline comparison available'));
  }
  
  stateSpinner.succeed(`Computed ${stateDiffs.length} contract state diffs, ${stateDiffs.reduce((sum, d) => sum + d.slotChanges.length, 0)} slot changes`);
  
  // Step 6: Oracle analysis (if enabled)
  let oracleAnalysis: OracleAnalysis | undefined;
  if (options.oracleAnalysis) {
    const oracleSpinner = ora('Analyzing oracle interactions...').start();
    
    try {
      oracleAnalysis = analyzeOracles(trace, {
        deviationThreshold: 5,
        twapWindow: 1800,
        verbose: options.verbose
      });
      
      const deviationCount = oracleAnalysis.deviations.filter(d => d.thresholdExceeded).length;
      const manipulationCount = oracleAnalysis.manipulationIndicators.length;
      
      oracleSpinner.succeed(`Oracle analysis: ${oracleAnalysis.pricesObserved.length} observations, ${deviationCount} deviations, ${manipulationCount} manipulation signals`);
    } catch (e) {
      oracleSpinner.warn('Oracle analysis completed with warnings');
      oracleAnalysis = undefined; // Continue without it
    }
  }
  
  // Step 7: Run full analysis with alert checking
  const analysisSpinner = ora('Running alert checks and anomaly detection...').start();
  
  const analysisResult = runAnalysis(trace, {
    alertRules: enrichedData?.alertRules || [],
    minSeverity: options.alertLevel as any || 'info',
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
  const outputData: TrackatorOutput = {
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
    renderTerminal(trace, stateDiffs, alerts, oracleAnalysis, roleJourneys, summary);
  }
  
  // Markdown Output
  if (options.format === 'all' || options.format === 'md') {
    const mdSpinner = ora('Generating Markdown report...').start();
    
    try {
      const mdContent = generateMarkdownReport(
        outputDir,
        trace,
        stateDiffs,
        alerts,
        oracleAnalysis,
        roleJourneys,
        summary
      );
      
      const mdPath = path.join(outputDir, 'trackator-analysis.md');
      fs.writeFileSync(mdPath, mdContent);
      
      mdSpinner.succeed(`Markdown report saved to ${mdPath}`);
    } catch (error: any) {
      mdSpinner.fail(`Failed to generate markdown: ${error.message}`);
    }
  }
  
  // HTML Output
  if (options.format === 'all' || options.format === 'html') {
    const htmlSpinner = ora('Generating interactive HTML report...').start();
    
    try {
      const htmlPath = generateHtmlReport(
        outputDir,
        trace,
        stateDiffs,
        alerts,
        oracleAnalysis,
        roleJourneys,
        summary
      );
      
      htmlSpinner.succeed(`HTML report saved to ${htmlPath}`);
    } catch (error: any) {
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
function printFinalSummary(
  summary: AnalysisSummary | undefined,
  alerts: Alert[],
  outputDir: string,
  duration: number
): void {
  const criticalCount = alerts.filter(a => a.severity === 'critical').length;
  const highCount = alerts.filter(a => a.severity === 'high').length;
  
  const verdict = summary?.verdict || 'pass';
  const verdictColor = verdict === 'pass' ? chalk.green : verdict === 'fail' ? chalk.red : chalk.yellow;
  const verdictIcon = verdict === 'pass' ? '✅' : verdict === 'fail' ? '❌' : '⚠️';
  
  console.log('');
  console.log(boxen(
    verdictColor.bold(`${verdictIcon} ANALYSIS COMPLETE: ${verdict.toUpperCase()}\n`) +
    chalk.white(`Execution Steps: ${summary?.totalSteps || 0}\n`) +
    chalk.white(`Contracts Touched: ${summary?.totalContractsTouched || 0}\n`) +
    chalk.white(`Storage Slots Changed: ${summary?.totalStorageSlotsChanged || 0}\n`) +
    chalk.red(`Critical Alerts: ${criticalCount}\n`) +
    chalk.hex('#ff6b6b')(`High Alerts: ${highCount}\n`) +
    chalk.white(`Total Alerts: ${alerts.length}\n`) +
    chalk.white(`Gas Efficiency: ${summary?.gasEfficiency.percentage.toFixed(1) || 0}%\n`) +
    chalk.white(`Duration: ${duration}ms\n`) +
    chalk.gray(`Output saved to: ${outputDir}`),
    {
      padding: 1,
      borderColor: verdict === 'pass' ? 'green' : verdict === 'fail' ? 'red' : 'yellow',
      borderStyle: 'round'
    }
  ));
  
  // If there are critical/high alerts, print quick actions
  if (criticalCount > 0 || highCount > 0) {
    console.log('');
    console.log(chalk.yellow.bold('Recommended Next Steps:'));
    console.log(chalk.yellow('  1. Review critical alerts in HTML report'));
    console.log(chalk.yellow('  2. Check state changes for affected contracts'));
    console.log(chalk.yellow('  3. Verify oracle prices against external sources'));
    console.log(chalk.yellow('  4. Re-run with different inputs to confirm findings'));
  }
}

function generateRunId(): string {
  return `run_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}
