#!/usr/bin/env node

// ============================================================
// TRACKATOR - CLI Entry Point
// Smart Contract Transaction State Visualizer
// ============================================================

import { Command } from 'commander';
import chalk from 'chalk';
import figlet from 'figlet';
import boxen from 'boxen';
import * as path from 'path';

// Tier 1 imports
import { runInit } from './tier1-parser/init-command';
// Tier 2 imports  
import { runEnrich } from './tier2-enricher/enrich-command';
// Tier 3 imports
import { runAnalyze } from './tier3-analyzer/analyze-command';

const VERSION = '1.0.0';

function printBanner(): void {
  const banner = figlet.textSync('Trackator', {
    font: 'Standard',
    horizontalLayout: 'default',
    verticalLayout: 'default'
  });
  
  const boxed = boxen(
    chalk.cyan(banner) + '\n\n' +
    chalk.white.bold('  Smart Contract Transaction State Visualizer') + '\n' +
    chalk.gray('  For DeFi Protocol Audits') + '\n\n' +
    chalk.green('  v') + VERSION + '  |  ',
    {
      padding: 1,
      margin: 1,
      borderStyle: 'round',
      borderColor: 'cyan'
    }
  );
  
  console.log(boxed);
}

const program = new Command()
  .name('trackator')
  .description('Visualize smart contract transaction states during DeFi protocol audits')
  .version(VERSION)
  .hook('preAction', () => {
    // Only show banner for main commands, not version/help
    const args = process.argv.slice(2);
    if (args.length > 0 && !args.includes('-v') && !args.includes('--version')) {
      printBanner();
    }
  });

// ============================================================
// TIER 1: INIT - Static Analysis
// ============================================================
program
  .command('init')
  .description('Tier 1: Parse Solidity source and generate static analysis (contracts, state vars, call graphs)')
  .argument('<sources>', 'Solidity source files or directory (glob pattern supported)')
  .option('-o, --output <dir>', 'Output directory', './trackator-output')
  .option('--format <format>', 'Output format: all, md, html, terminal', 'all')
  .option('--include-node-modules', 'Include node_modules in scan', false)
  .option('-v, --verbose', 'Verbose output', false)
  .action(async (sources: string, options) => {
    try {
      await runInit(sources, options);
    } catch (error: any) {
      console.error(chalk.red('\n✖ Init failed:'), error.message);
      if (options.verbose && error.stack) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

// ============================================================
// TIER 2: ENRICH - AI Knowledge Base
// ============================================================
program
  .command('enrich')
  .description('Tier 2: Enrich static analysis with X-Ray threat models and Breakdown behavioral analysis')
  .argument('[input]', 'Input directory (output from init)', './trackator-output')
  .option('--xray <file>', 'X-Ray analysis file to ingest')
  .option('--breakdown <file>', 'Protocol Breakdown file to ingest')
  .option('-o, --output <dir>', 'Output directory', './trackator-output')
  .option('--generate-alerts', 'Generate alert rules from X-Ray/Breakdown data', true)
  .option('--protocol-type <type>', 'Override protocol type detection')
  .option('-v, --verbose', 'Verbose output', false)
  .action(async (input: string, options) => {
    try {
      await runEnrich(input, options);
    } catch (error: any) {
      console.error(chalk.red('\n✖ Enrich failed:'), error.message);
      if (options.verbose && error.stack) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

// ============================================================
// TIER 3: ANALYZE - Runtime Trace Analysis
// ============================================================
program
  .command('analyze')
  .description('Tier 3: Analyze Foundry trace JSON and generate state visualization + alerts')
  .argument('<trace>', 'Foundry trace JSON file (--trace output)')
  .option('-i, --input <dir>', 'Input directory with enriched data', './trackator-output')
  .option('-o, --output <dir>', 'Output directory', './trackator-output')
  .option('--format <format>', 'Output format: all, md, html, terminal', 'all')
  .option('--alert-level <level>', 'Minimum alert level: critical, high, medium, low, info', 'low')
  .option('--compare-baseline <file>', 'Compare against baseline trace file')
  .option('--focus-contract <contract>', 'Focus analysis on specific contract')
  .option('--focus-function <function>', 'Focus analysis on specific function')
  .option('--gas-analysis', 'Include detailed gas analysis', true)
  .option('--oracle-analysis', 'Include oracle price deviation analysis', true)
  .option('--role-tracking', 'Track role journeys through execution', true)
  .option('-v, --verbose', 'Verbose output', false)
  .action(async (trace: string, options) => {
    try {
      await runAnalyze(trace, options);
    } catch (error: any) {
      console.error(chalk.red('\n✖ Analyze failed:'), error.message);
      if (options.verbose && error.stack) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

// Parse and execute
program.parse();

// Show help if no command provided
if (!process.argv.slice(2).length) {
  printBanner();
  program.outputHelp();
}
