"use strict";
// ============================================================
// TRACKATOR Tier 1 - Init Command
// Orchestrates static analysis and generates output
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
exports.runInit = runInit;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const boxen_1 = __importDefault(require("boxen"));
const contract_extractor_1 = require("./contract-extractor");
const state_inventory_1 = require("./state-inventory");
const function_registry_1 = require("./function-registry");
const call_graph_1 = require("./call-graph");
const diagram_generator_1 = require("./diagram-generator");
const role_extractor_1 = require("./role-extractor"); // NEW: Role extraction
/**
 * Main entry point for `trackator init` command
 */
async function runInit(sourcePattern, options) {
    const startTime = Date.now();
    console.log('');
    console.log(chalk_1.default.cyan.bold('╔══════════════════════════════════════════════╗'));
    console.log(chalk_1.default.cyan.bold('║         TIER 1: STATIC ANALYSIS              ║'));
    console.log(chalk_1.default.cyan.bold('╚══════════════════════════════════════════════╝'));
    console.log('');
    // Step 1: Parse Solidity sources
    const parseSpinner = (0, ora_1.default)('Parsing Solidity source files...').start();
    const parseResult = await (0, contract_extractor_1.extractContracts)(sourcePattern, {
        includeNodeModules: options.includeNodeModules,
        verbose: options.verbose
    });
    if (parseResult.errors.length > 0) {
        parseSpinner.warn('Parsed ' + parseResult.filesProcessed + ' files with ' + parseResult.errors.length + ' errors');
        if (options.verbose) {
            parseResult.errors.forEach(function (e) { console.log(chalk_1.default.yellow('  ⚠ ' + e)); });
        }
    }
    else {
        parseSpinner.succeed('Parsed ' + parseResult.filesProcessed + ' files, found ' + parseResult.contracts.length + ' contracts');
    }
    if (parseResult.contracts.length === 0) {
        console.log(chalk_1.default.yellow('\nNo contracts found. Check your source pattern.'));
        return;
    }
    // Step 2: Generate state inventories
    const stateSpinner = (0, ora_1.default)('Computing storage layouts...').start();
    const inventories = (0, state_inventory_1.generateAllInventories)(parseResult.contracts);
    stateSpinner.succeed('Computed storage layouts for ' + inventories.size + ' contracts');
    // Step 3: Build function registry
    const funcSpinner = (0, ora_1.default)('Building function registry...').start();
    const registry = (0, function_registry_1.buildFunctionRegistry)(parseResult.contracts);
    funcSpinner.succeed('Registered ' + Array.from(registry.values()).flat().length + ' functions');
    // Step 4: Build call graph
    const graphSpinner = (0, ora_1.default)('Building call graph...').start();
    const callGraph = (0, call_graph_1.buildCallGraph)(parseResult.contracts);
    graphSpinner.succeed('Built call graph with ' + callGraph.nodes.size + ' nodes, ' + callGraph.edges.length + ' edges');
    // Step 5: Generate diagrams
    const diagramSpinner = (0, ora_1.default)('Generating Mermaid diagrams...').start();
    const diagramSet = (0, diagram_generator_1.generateAllDiagrams)(parseResult.contracts);
    const totalDiagrams = diagramSet.contractDiagrams.length +
        diagramSet.stateDiagrams.length +
        diagramSet.flowDiagrams.length +
        diagramSet.riskDiagrams.length +
        (diagramSet.valueFlowDiagrams?.length || 0);
    diagramSpinner.succeed('Generated ' + totalDiagrams + ' diagrams');
    // Step 6: Extract protocol roles (NEW)
    const roleSpinner = (0, ora_1.default)('Extracting protocol roles...').start();
    const roleExtraction = (0, role_extractor_1.extractProtocolRoles)(parseResult.contracts, registry);
    roleSpinner.succeed('Extracted ' + roleExtraction.totalRoles + ' roles (' +
        roleExtraction.trustedRoles.length + ' trusted, ' +
        roleExtraction.nonTrustedRoles.length + ' non-trusted)');
    // Prepare output data
    const outputData = {
        runId: generateRunId(),
        command: 'init',
        timestamp: new Date().toISOString(),
        duration: Date.now() - startTime,
        contracts: parseResult.contracts,
        callGraph: Array.from(callGraph.nodes.values()),
        mermaidDiagrams: [
            ...diagramSet.contractDiagrams,
            ...diagramSet.stateDiagrams,
            ...diagramSet.flowDiagrams,
            ...diagramSet.riskDiagrams,
            ...(diagramSet.valueFlowDiagrams || [])
        ],
        valueFlows: diagramSet.valueTransfers || [], // Raw ValueTransfer data for summary tables
        roleExtraction: roleExtraction // NEW: Role extraction results
    };
    // Ensure output directory exists
    const outputDir = path.resolve(options.output);
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    // Generate outputs based on format option
    if (options.format === 'all' || options.format === 'terminal') {
        printTerminalOutput(outputData, registry, callGraph, inventories);
    }
    if (options.format === 'all' || options.format === 'md') {
        await generateMarkdownOutput(outputDir, outputData, diagramSet, registry, callGraph, inventories);
    }
    if (options.format === 'all' || options.format === 'html') {
        await generateHtmlOutput(outputDir, outputData, diagramSet, registry, callGraph, inventories);
    }
    // Save raw JSON data
    const jsonPath = path.join(outputDir, 'trackator-init.json');
    fs.writeFileSync(jsonPath, JSON.stringify(outputData, null, 2));
    // Print summary
    console.log('');
    console.log((0, boxen_1.default)(chalk_1.default.green.bold('✓ Analysis Complete\n') +
        chalk_1.default.white('Contracts: ' + parseResult.contracts.length + '\n') +
        chalk_1.default.white('Functions: ' + Array.from(registry.values()).flat().length + '\n') +
        chalk_1.default.white('Call Edges: ' + callGraph.edges.length + '\n') +
        chalk_1.default.white('Alerts Found: ' + (0, function_registry_1.getHighRiskFunctions)(registry, 25).length + ' high-risk functions\n') +
        chalk_1.default.white('Roles Extracted: ' + roleExtraction.totalRoles +
            ' (' + roleExtraction.summary.trustedCount + ' trusted, ' +
            roleExtraction.summary.nonTrustedCount + ' non-trusted)\n') +
        (roleExtraction.summary.singlePointsOfFailure.length > 0
            ? chalk_1.default.yellow('⚠ Single Points of Failure: ' + roleExtraction.summary.singlePointsOfFailure.join(', ') + '\n')
            : '') +
        chalk_1.default.white('Duration: ' + (Date.now() - startTime) + 'ms\n') +
        chalk_1.default.gray('Output saved to: ' + outputDir), {
        padding: 1,
        borderColor: 'green',
        borderStyle: 'round'
    }));
}
/**
 * Print terminal output with ASCII visualization
 */
function printTerminalOutput(outputData, registry, callGraph, inventories) {
    console.log('\n');
    console.log(chalk_1.default.white.bold('═'.repeat(60)));
    console.log(chalk_1.default.white.bold('           PROTOCOL STRUCTURE OVERVIEW'));
    console.log(chalk_1.default.white.bold('═'.repeat(60)));
    console.log('');
    // Contract Summary Table
    console.log(chalk_1.default.cyan.bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.cyan.bold('│                    CONTRACTS FOUND                         │'));
    console.log(chalk_1.default.cyan.bold('├──────────┬────────┬─────────┬────────┬─────────┬──────────┤'));
    console.log(chalk_1.default.cyan.bold('│ Contract │ Funcs  │ State   │ Events │ Modifiers│  Lines   │'));
    console.log(chalk_1.default.cyan.bold('├──────────┼────────┼─────────┼────────┼─────────┼──────────┤'));
    for (const contract of outputData.contracts || []) {
        const name = contract.name.padEnd(10);
        const funcs = String(contract.functions.length).padStart(6);
        const stateVars = String(contract.stateVariables.length).padStart(7);
        const events = String(contract.events.length).padStart(6);
        const modifiers = String(contract.modifiers.length).padStart(7);
        const lines = String(contract.lineCount).padStart(8);
        console.log(chalk_1.default.white('│ ' + name + ' │ ' + funcs + ' │ ' + stateVars + ' │ ' + events + ' │ ' + modifiers + ' │ ' + lines + '   │'));
    }
    console.log(chalk_1.default.cyan.bold('└──────────┴────────┴─────────┴────────┴─────────┴──────────┘'));
    console.log('');
    // Entry Points
    const entryPoints = (0, function_registry_1.getEntryPoints)(registry);
    if (entryPoints.length > 0) {
        console.log(chalk_1.default.yellow.bold('┌─────────────────────────────────────────────────────────────┐'));
        console.log(chalk_1.default.yellow.bold('│                  ENTRY POINTS (External)                   │'));
        console.log(chalk_1.default.yellow.bold('├─────────────────────────────────────────────────────────────┤'));
        for (const ep of entryPoints.slice(0, 15)) {
            const riskColor = ep.risk.overall === 'critical' ? chalk_1.default.red :
                ep.risk.overall === 'high' ? chalk_1.default.hex('#ff6b6b') :
                    ep.risk.overall === 'medium' ? chalk_1.default.hex('#ffa726') : chalk_1.default.green;
            console.log(chalk_1.default.white('  • ' + ep.contract + '.' + ep.name + '()'));
            console.log(chalk_1.default.gray('     Risk: [' + riskColor(ep.risk.score.toString()) + '] ' + ep.risk.overall.toUpperCase() + ' | Category: ' + ep.category));
        }
        if (entryPoints.length > 15) {
            console.log(chalk_1.default.gray('  ... and ' + (entryPoints.length - 15) + ' more'));
        }
        console.log(chalk_1.default.yellow.bold('└─────────────────────────────────────────────────────────────┘'));
        console.log('');
    }
    // High-Risk Functions Alert
    const highRiskFuncs = (0, function_registry_1.getHighRiskFunctions)(registry, 25);
    if (highRiskFuncs.length > 0) {
        console.log(chalk_1.default.red.bold('┌─────────────────────────────────────────────────────────────┐'));
        console.log(chalk_1.default.red.bold('│               ⚠ HIGH-RISK FUNCTIONS ALERT                   │'));
        console.log(chalk_1.default.red.bold('├─────────────────────────────────────────────────────────────┤'));
        for (const func of highRiskFuncs.slice(0, 10)) {
            console.log(chalk_1.default.red('  \u{1F534} ' + func.contract + '.' + func.name + '()'));
            console.log(chalk_1.default.gray('     Score: ' + func.risk.score + '/100 | Factors:'));
            for (const factor of func.risk.factors.slice(0, 3)) {
                const severityIcon = factor.severity === 'critical' ? '\u{1F534}' :
                    factor.severity === 'high' ? '\u{1F7E0}' :
                        factor.severity === 'medium' ? '\u{1F7E1}' : '\u{1F7E2}';
                console.log(chalk_1.default.gray('       ' + severityIcon + ' ' + factor.description));
            }
        }
        if (highRiskFuncs.length > 10) {
            console.log(chalk_1.default.gray('  ... and ' + (highRiskFuncs.length - 10) + ' more'));
        }
        console.log(chalk_1.default.red.bold('└─────────────────────────────────────────────────────────────┘'));
        console.log('');
    }
    // Call Graph Stats
    console.log(chalk_1.default.magenta.bold('┌─────────────────────────────────────────────────────────────┐'));
    console.log(chalk_1.default.magenta.bold('│                   CALL GRAPH STATISTICS                     │'));
    console.log(chalk_1.default.magenta.bold('├─────────────────────────────────────────────────────────────┤'));
    console.log(chalk_1.default.white('  Total Nodes:          ' + callGraph.nodes.size));
    console.log(chalk_1.default.white('  Total Edges:          ' + callGraph.edges.length));
    console.log(chalk_1.default.white('  Entry Points:         ' + callGraph.entryPoints.length));
    console.log(chalk_1.default.white('  Cycles Detected:      ' + callGraph.cycles.length));
    if (callGraph.cycles.length > 0) {
        console.log(chalk_1.default.yellow('  \u26A0 Recursion detected in:'));
        for (const cycleInfo of callGraph.cycles.slice(0, 3)) {
            const path = Array.isArray(cycleInfo) ? cycleInfo : (cycleInfo.path || []);
            console.log(chalk_1.default.yellow('     - ' + path.join(' \u2192 ')));
        }
        if (callGraph.cycles.length > 3) {
            console.log(chalk_1.default.yellow('     ... and ' + (callGraph.cycles.length - 3) + ' more cycles'));
        }
    }
    console.log(chalk_1.default.magenta.bold('└─────────────────────────────────────────────────────────────┘'));
    console.log('');
    // Protocol Roles (NEW)
    if (outputData.roleExtraction) {
        const roles = outputData.roleExtraction;
        // Trusted Roles
        if (roles.trustedRoles.length > 0) {
            console.log(chalk_1.default.green.bold('┌─────────────────────────────────────────────────────────────┐'));
            console.log(chalk_1.default.green.bold('│                 TRUSTED ROLES EXTRACTED                     │'));
            console.log(chalk_1.default.green.bold('├──────────┬─────────────────┬──────────┬────────────────────┤'));
            console.log(chalk_1.default.green.bold('│ Role     │ Address Source  │ Trust    │ Capabilities       │'));
            console.log(chalk_1.default.green.bold('├──────────┼─────────────────┼──────────┼────────────────────┤'));
            for (const role of roles.trustedRoles) {
                const name = role.name.padEnd(8);
                const source = (role.addressSource || 'N/A').padEnd(15);
                const trust = role.trustLevel.padEnd(8);
                const caps = role.capabilities.length + ' functions';
                const trustColor = role.trustLevel === 'CRITICAL' ? chalk_1.default.red :
                    role.trustLevel === 'HIGH' ? chalk_1.default.hex('#ff6b6b') :
                        role.trustLevel === 'MEDIUM' ? chalk_1.default.hex('#ffa726') : chalk_1.default.green;
                console.log(chalk_1.default.white('│ ' + name + ' │ ' + source + ' │ ' + trustColor(trust) + ' │ ' + caps));
                // Show key capabilities
                for (const cap of role.capabilities.slice(0, 2)) {
                    console.log(chalk_1.default.gray('│          │                 │          │ └─ ' + cap.functionSignature));
                }
                if (role.capabilities.length > 2) {
                    console.log(chalk_1.default.gray('│          │                 │          │ └─ ... +' + (role.capabilities.length - 2)));
                }
            }
            console.log(chalk_1.default.green.bold('└──────────┴─────────────────┴──────────┴────────────────────┘'));
            console.log('');
        }
        // Non-Trusted Roles
        if (roles.nonTrustedRoles.length > 0) {
            console.log(chalk_1.default.cyan.bold('┌─────────────────────────────────────────────────────────────┐'));
            console.log(chalk_1.default.cyan.bold('│               NON-TRUSTED ROLES (Public)                   │'));
            console.log(chalk_1.default.cyan.bold('├──────────────────┬────────────────────────────────────────┤'));
            console.log(chalk_1.default.cyan.bold('│ Role             │ Capabilities                            │'));
            console.log(chalk_1.default.cyan.bold('├──────────────────┼────────────────────────────────────────┤'));
            for (const role of roles.nonTrustedRoles) {
                const name = role.name.padEnd(16);
                console.log(chalk_1.default.white('│ ' + name + ' │ ' + role.capabilities.length + ' public functions'));
                for (const cap of role.capabilities.slice(0, 2)) {
                    console.log(chalk_1.default.gray('│                  │ └─ ' + cap.functionSignature));
                }
            }
            console.log(chalk_1.default.cyan.bold('└──────────────────┴────────────────────────────────────────┘'));
            console.log('');
        }
        // Security Warnings
        if (roles.summary.singlePointsOfFailure.length > 0) {
            console.log(chalk_1.default.yellow.bold('┌─────────────────────────────────────────────────────────────┐'));
            console.log(chalk_1.default.yellow.bold('│              ⚠ SECURITY WARNINGS                           │'));
            console.log(chalk_1.default.yellow.bold('├─────────────────────────────────────────────────────────────┤'));
            console.log(chalk_1.default.yellow('  Single Points of Failure:'));
            for (const spo of roles.summary.singlePointsOfFailure) {
                console.log(chalk_1.default.yellow('    ⚠ ' + spo));
            }
            if (!roles.summary.hasTimelock && roles.summary.highTrustCount > 2) {
                console.log(chalk_1.default.yellow('  ⚠ No timelock detected for high-trust roles'));
            }
            console.log(chalk_1.default.yellow.bold('└─────────────────────────────────────────────────────────────┘'));
            console.log('');
        }
    }
}
/**
 * Generate Markdown output file
 */
async function generateMarkdownOutput(outputDir, outputData, diagramSet, registry, callGraph, inventories) {
    const mdPath = path.join(outputDir, 'trackator-report.md');
    let md = '';
    // Header
    md += '# Trackator Static Analysis Report\n\n';
    md += '**Generated:** ' + new Date().toISOString() + '\n';
    md += '**Contracts Analyzed:** ' + (outputData.contracts?.length || 0) + '\n\n';
    // Table of Contents
    md += '## Table of Contents\n\n';
    md += '- [Protocol Overview](#protocol-overview)\n';
    md += '- [Contract Details](#contract-details)\n';
    md += '- [Function Registry](#function-registry)\n';
    md += '- [State Variables](#state-variables)\n';
    md += '- [Call Graph](#call-graph)\n';
    md += '- [Risk Assessment](#risk-assessment)\n';
    md += '- [Mermaid Diagrams](#mermaid-diagrams)\n\n';
    // Protocol Overview
    md += '## Protocol Overview\n\n';
    md += '| Contract | Functions | State Vars | Events | Lines |\n';
    md += '|----------|-----------|------------|--------|-------|\n';
    for (const contract of outputData.contracts || []) {
        md += '| ' + contract.name + ' | ' + contract.functions.length + ' | ' + contract.stateVariables.length + ' | ' + contract.events.length + ' | ' + contract.lineCount + ' |\n';
    }
    md += '\n';
    // Contract Details
    md += '## Contract Details\n\n';
    for (const contract of outputData.contracts || []) {
        md += '### ' + contract.name + '\n\n';
        if (contract.abstract)
            md += '**Abstract**\n\n';
        if (contract.inherited.length > 0) {
            md += '**Inherits from:** ' + contract.inherited.join(', ') + '\n\n';
        }
        // State Variables
        if (contract.stateVariables.length > 0) {
            md += '#### State Variables\n\n';
            md += '| Name | Type | Visibility | Slot |\n';
            md += '|------|------|------------|------|\n';
            var inventory = inventories.get(contract.name);
            if (inventory === undefined)
                inventory = null;
            for (const sv of contract.stateVariables) {
                const slotInfo = inventory?.variables?.find((v) => v.variable.name === sv.name);
                const bt = String.fromCharCode(96);
                md += '| ' + bt + sv.name + bt + ' | ' + sv.type + ' | ' + sv.visibility + ' | ' + (slotInfo ? slotInfo.computedSlot : '-') + ' |\n';
            }
            md += '\n';
        }
        // Functions
        if (contract.functions.length > 0) {
            md += '#### Functions\n\n';
            md += '| Signature | Visibility | Mutability | Complexity | CEI |\n';
            md += '|-----------|------------|------------|------------|-----|\n';
            for (const func of contract.functions) {
                const params = func.parameters.map(function (p) { return p.type; }).join(', ');
                const ceiStatus = func.body.ceiPattern === 'valid' ? '\u2705' :
                    func.body.ceiPattern === 'violated' ? '\u274C' : '\u23E6\uFE0F';
                const bt = String.fromCharCode(96);
                md += '| ' + bt + func.name + '(' + params + ')' + bt + ' | ' + func.visibility + ' | ' + func.stateMutability + ' | ' + func.complexity + ' | ' + ceiStatus + ' |\n';
            }
            md += '\n';
        }
        // Events
        if (contract.events.length > 0) {
            md += '#### Events\n\n';
            for (const event of contract.events) {
                const bt = String.fromCharCode(96); // backtick
                const params = event.parameters.map(function (p) {
                    return p.indexed ? bt + p.type + ' indexed ' + (p.name || '') + bt : bt + p.type + ' ' + (p.name || '') + bt;
                }).join(', ');
                md += '- **' + event.name + '**(' + params + ')\n';
            }
            md += '\n';
        }
    }
    // Function Registry Summary
    md += '## Function Registry\n\n';
    md += '| Contract | Function | Category | Access Control | Risk Score |\n';
    md += '|----------|----------|----------|----------------|------------|\n';
    for (const [, funcs] of registry) {
        for (const func of funcs) {
            const riskColor = func.risk.score >= 50 ? '\u{1F534}' :
                func.risk.score >= 25 ? '\u{1F7E0}' :
                    func.risk.score >= 10 ? '\u{1F7E1}' : '\u{1F7E2}';
            const bt = String.fromCharCode(96); // backtick
            md += '| ' + func.contract + ' | ' + bt + func.signature + bt + ' | ' + func.category + ' | ' + func.accessControl.level + ' | ' + riskColor + ' ' + func.risk.score + ' |\n';
        }
    }
    md += '\n';
    // Call Graph Section
    md += '## Call Graph\n\n';
    md += '### Overview Diagram\n\n';
    md += String.fromCharCode(96) + String.fromCharCode(96) + String.fromCharCode(96) + 'mermaid\n';
    // Generate a simple call graph representation
    md += 'graph TD\n';
    if (callGraph && callGraph.nodes) {
        const nodeMap = callGraph.nodes;
        const keys = Array.from(nodeMap.keys());
        for (let i = 0; i < keys.length; i++) {
            const name = keys[i];
            const node = nodeMap.get(name);
            if (node) {
                md += '  ' + String(name).replace(/[^a-zA-Z0-9]/g, '_') + '[' + node.contract + '.' + node.function + ']\n';
            }
        }
    }
    md += '\n' + String.fromCharCode(96) + String.fromCharCode(96) + String.fromCharCode(96) + '\n\n';
    // Risk Assessment
    md += '## Risk Assessment\n\n';
    const highRiskFuncs = (0, function_registry_1.getHighRiskFunctions)(registry, 25);
    if (highRiskFuncs.length > 0) {
        md += '### High-Risk Functions\n\n';
        md += '| Function | Risk Score | Severity | Key Issues |\n';
        md += '|----------|------------|----------|-------------|\n';
        for (const func of highRiskFuncs) {
            const issues = func.risk.factors.map(function (f) { return f.type; }).join(', ');
            const bt = String.fromCharCode(96); // backtick
            md += '| ' + bt + func.contract + '.' + func.name + '()' + bt + ' | ' + func.risk.score + ' | ' + func.risk.overall + ' | ' + issues + ' |\n';
        }
        md += '\n';
    }
    // Mermaid Diagrams
    md += '## Mermaid Diagrams\n\n';
    for (const diagram of (diagramSet.contractDiagrams?.slice(0, 5) || [])) {
        md += '### ' + diagram.title + '\n\n';
        md += '' + diagram.description + '\n\n';
        md += String.fromCharCode(96) + String.fromCharCode(96) + String.fromCharCode(96) + 'mermaid\n';
        md += diagram.code;
        md += '\n' + String.fromCharCode(96) + String.fromCharCode(96) + String.fromCharCode(96) + '\n\n';
    }
    // Value Flow Diagrams (NEW FEATURE)
    const valueFlowDiagrams = diagramSet.valueFlowDiagrams || [];
    if (valueFlowDiagrams.length > 0) {
        md += '## Value Flow Diagrams\n\n';
        md += 'Visual representation of how assets move through the protocol.\n\n';
        for (const diagram of valueFlowDiagrams) {
            md += '### ' + diagram.title + '\n\n';
            md += '' + diagram.description + '\n\n';
            md += String.fromCharCode(96) + String.fromCharCode(96) + String.fromCharCode(96) + 'mermaid\n';
            md += diagram.code;
            md += '\n' + String.fromCharCode(96) + String.fromCharCode(96) + String.fromCharCode(96) + '\n\n';
        }
        // Add value flow summary table - use raw ValueTransfer data, not Mermaid diagrams
        const allValueFlows = diagramSet.valueTransfers || [];
        if (allValueFlows.length > 0) {
            md += '### Value Transfer Summary\n\n';
            md += '| From | To | Asset | Via Function | Type |\n';
            md += '|------|-----|-------|-------------|------|\n';
            for (const vf of allValueFlows.slice(0, 30)) {
                md += '| `' + vf.from + '` | `' + vf.to + '` | ' + vf.asset + ' | `' + vf.viaFunction + '()` | ' + vf.type + ' |\n';
            }
            if (allValueFlows.length > 30) {
                md += '\n*... and ' + (allValueFlows.length - 30) + ' more transfers*\n\n';
            }
            md += '\n';
        }
    }
    // Protocol Roles (NEW)
    if (outputData.roleExtraction) {
        const roles = outputData.roleExtraction;
        md += '## Protocol Roles\n\n';
        md += 'Extracted protocol roles from access control patterns, modifiers, and function analysis.\n\n';
        // Summary stats
        md += '**Role Summary:**\n';
        md += '- Trusted Roles: **' + roles.summary.trustedCount + '**\n';
        md += '- Non-Trusted Roles: **' + roles.summary.nonTrustedCount + '**\n';
        md += '- High Trust (CRITICAL+HIGH): **' + roles.summary.highTrustCount + '**\n';
        md += '- Public Functions (No Auth): **' + roles.summary.publicFunctionCount + '**\n';
        if (roles.summary.hasTimelock)
            md += '- Timelock: **Detected** ✅\n';
        else
            md += '- Timelock: **Not Detected** ⚠️\n';
        if (roles.summary.hasMultisig)
            md += '- Multisig: **Detected** ✅\n\n';
        // Trusted Roles Table
        if (roles.trustedRoles.length > 0) {
            md += '### Trusted Roles\n\n';
            md += '| Role | Address Source | Trust Level | Capabilities | SPOF |\n';
            md += '|------|---------------|-------------|--------------|------|\n';
            for (const role of roles.trustedRoles) {
                const trustBadge = role.trustLevel === 'CRITICAL' ? '🔴 ' + role.trustLevel :
                    role.trustLevel === 'HIGH' ? '🟠 ' + role.trustLevel :
                        role.trustLevel === 'MEDIUM' ? '🟡 ' + role.trustLevel : '🟢 ' + role.trustLevel;
                const spofBadge = role.isSinglePointOfFailure ? '⚠️ YES' : '✅ No';
                const caps = role.capabilities.map(c => '`' + c.functionSignature + '`').join(', ');
                md += '| **' + role.name + '** | `' + (role.addressSource || 'N/A') + '` | ' + trustBadge + ' | ' + role.capabilities.length + ' functions | ' + spofBadge + ' |\n';
            }
            md += '\n';
            // Detailed capabilities for each trusted role
            md += '#### Role Capabilities Detail\n\n';
            for (const role of roles.trustedRoles) {
                md += '**' + role.name + '** (' + role.sourceContract + ')\n\n';
                md += '*Trust Reasoning:* ' + role.trustReasoning + '\n\n';
                if (role.capabilities.length > 0) {
                    md += '| Function | Impact | Category | Description |\n';
                    md += '|----------|--------|----------|-------------|\n';
                    for (const cap of role.capabilities) {
                        const impactBadge = cap.impact === 'critical' ? '🔴' :
                            cap.impact === 'high' ? '🟠' :
                                cap.impact === 'medium' ? '🟡' : '🟢';
                        md += '| `' + cap.functionSignature + '` | ' + impactBadge + ' ' + cap.impact + ' | ' + cap.category + ' | ' + cap.description + ' |\n';
                    }
                    md += '\n';
                }
                if (role.constraints.length > 0) {
                    md += '*Constraints:*\n';
                    for (const constraint of role.constraints) {
                        md += '- ' + constraint + '\n';
                    }
                    md += '\n';
                }
                md += '*Risk if Compromised:* ' + role.riskIfCompromised + '\n\n';
                md += '---\n\n';
            }
        }
        // Non-Trusted Roles Table
        if (roles.nonTrustedRoles.length > 0) {
            md += '### Non-Trusted Roles\n\n';
            md += '| Role | Address Source | Capabilities | Risk |\n';
            md += '|------|---------------|--------------|------|\n';
            for (const role of roles.nonTrustedRoles) {
                md += '| **' + role.name + '** | `' + (role.addressSource || 'msg.sender') + '` | ' + role.capabilities.length + ' public functions | ' + role.riskIfCompromised + ' |\n';
            }
            md += '\n';
            // Detailed non-trusted capabilities
            md += '#### Public Function Details\n\n';
            for (const role of roles.nonTrustedRoles) {
                md += '**' + role.name + '**\n\n';
                if (role.capabilities.length > 0) {
                    md += '| Function | Impact | Description |\n';
                    md += '|----------|--------|-------------|\n';
                    for (const cap of role.capabilities.slice(0, 10)) {
                        md += '| `' + cap.functionSignature + '` | ' + cap.impact + ' | ' + cap.description + ' |\n';
                    }
                    if (role.capabilities.length > 10) {
                        md += '| ... +' + (role.capabilities.length - 10) + ' more | | |\n';
                    }
                    md += '\n';
                }
            }
        }
        // Security Warnings
        if (roles.summary.singlePointsOfFailure.length > 0 || !roles.summary.hasTimelock) {
            md += '### ⚠️ Security Warnings\n\n';
            if (roles.summary.singlePointsOfFailure.length > 0) {
                md += '**Single Points of Failure Detected:**\n\n';
                for (const spo of roles.summary.singlePointsOfFailure) {
                    md += '- ⚠️ ' + spo + '\n';
                }
                md += '\n';
            }
            if (!roles.summary.hasTimelock && roles.summary.highTrustCount > 2) {
                md += '> **⚠️ Recommendation:** Consider implementing a timelock for high-trust role operations to allow for emergency response time.\n\n';
            }
            if (roles.summary.publicFunctionCount > 5) {
                md += '> **ℹ️ Note:** ' + roles.summary.publicFunctionCount + ' public functions without explicit access control were detected. Review these for potential unauthorized access vectors.\n\n';
            }
        }
        md += '\n';
    }
    fs.writeFileSync(mdPath, md);
}
/**
 * Generate HTML interactive output
 */
async function generateHtmlOutput(outputDir, outputData, diagramSet, registry, callGraph, inventories) {
    const htmlPath = path.join(outputDir, 'trackator-report.html');
    // Build HTML using string concatenation (no template literals)
    let html = '';
    html += '<!DOCTYPE html>\n';
    html += '<html><head><title>Trackator Report</title></head>\n';
    html += '<body><h1>Analysis Complete</h1>\n';
    html += '<p>' + (outputData.contracts?.length || 0) + ' contracts analyzed.</p>';
    html += '</body></html>';
    fs.writeFileSync(htmlPath, html);
}
function getHighestRisk(registry) {
    let maxScore = 0;
    for (const [, funcs] of registry) {
        for (const func of funcs) {
            if (func.risk.score > maxScore) {
                maxScore = func.risk.score;
            }
        }
    }
    return maxScore >= 50 ? 'critical' : maxScore >= 25 ? 'high' : maxScore >= 10 ? 'medium' : 'safe';
}
function generateRunId() {
    return 'run_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
}
//# sourceMappingURL=init-command.js.map