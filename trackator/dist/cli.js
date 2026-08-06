#!/usr/bin/env node
"use strict";
// ============================================================
// TRACKATOR - CLI Entry Point
// Smart Contract Transaction State Visualizer
// ============================================================
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const chalk_1 = __importDefault(require("chalk"));
const figlet_1 = __importDefault(require("figlet"));
const boxen_1 = __importDefault(require("boxen"));
// Tier 1 imports
const init_command_1 = require("./tier1-parser/init-command");
// Tier 2 imports  
const enrich_command_1 = require("./tier2-enricher/enrich-command");
// Tier 3 imports
const analyze_command_1 = require("./tier3-analyzer/analyze-command");
const VERSION = '1.0.0';
function printBanner() {
    const banner = figlet_1.default.textSync('Trackator', {
        font: 'Standard',
        horizontalLayout: 'default',
        verticalLayout: 'default'
    });
    const boxed = (0, boxen_1.default)(chalk_1.default.cyan(banner) + '\n\n' +
        chalk_1.default.white.bold('  Smart Contract Transaction State Visualizer') + '\n' +
        chalk_1.default.gray('  For DeFi Protocol Audits') + '\n\n' +
        chalk_1.default.green('  v') + VERSION + '  |  ', {
        padding: 1,
        margin: 1,
        borderStyle: 'round',
        borderColor: 'cyan'
    });
    console.log(boxed);
}
const program = new commander_1.Command()
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
    .action(async (sources, options) => {
    try {
        await (0, init_command_1.runInit)(sources, options);
    }
    catch (error) {
        console.error(chalk_1.default.red('\n✖ Init failed:'), error.message);
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
    .option('-o, --output <dir>', 'Output directory (default: same as input dir, so trackator-init.json and trackator-enrich.json land together — required by redteam-trackator Phase 0)')
    .option('--generate-alerts', 'Generate alert rules from X-Ray/Breakdown data', true)
    .option('--skip-advanced', 'Skip storage/coupling/sync/evidence analysis (faster, v1.0-equivalent output)', false)
    .option('--protocol-type <type>', 'Override protocol type detection')
    .option('-v, --verbose', 'Verbose output', false)
    .action(async (input, options) => {
    try {
        // FIX (integration bug): --output previously defaulted to './trackator-output'
        // regardless of `input`, so `trackator enrich <dir>` (no -o) silently split
        // trackator-init.json and trackator-enrich.json across two different directories,
        // breaking redteam-trackator's Phase 0 validateTrackatorOutput() which requires
        // both files in the same outputDir. Default output to the input dir instead.
        if (!options.output) {
            options.output = input;
        }
        await (0, enrich_command_1.runEnrich)(input, options);
    }
    catch (error) {
        console.error(chalk_1.default.red('\n✖ Enrich failed:'), error.message);
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
    .action(async (trace, options) => {
    try {
        await (0, analyze_command_1.runAnalyze)(trace, options);
    }
    catch (error) {
        console.error(chalk_1.default.red('\n✖ Analyze failed:'), error.message);
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
//# sourceMappingURL=cli.js.map