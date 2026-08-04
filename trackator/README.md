# Trackator

**Smart Contract Transaction State Visualizer for DeFi Protocol Audits**

A powerful CLI tool that provides triple-output (terminal/.md/.html) visualization for smart contract analysis. Trackator operates as a 3-tier analysis pipeline: static parsing, AI enrichment, and runtime trace analysis.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green.svg)](https://nodejs.org/)

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Per-Project Installation (Recommended for Development)](#per-project-installation-recommended-for-development)
  - [Global Installation](#global-installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Tier 1: Static Analysis (`init`)](#tier-1-static-analysis-init)
  - [Tier 2: AI Enrichment (`enrich`)](#tier-2-ai-enrichment-enrich)
  - [Tier 3: Runtime Analysis (`analyze`)](#tier-3-runtime-analysis-analyze)
- [Output Formats](#output-formats)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Examples](#examples)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Tier 1: Static Analysis
- **Contract Extraction**: Parse Solidity source files with inheritance mapping
- **State Inventory**: Compute storage layouts with slot assignments
- **Function Registry**: Build function catalogs with automatic risk scoring
- **Call Graph Generation**: Visualize contract interactions with cycle detection
- **Pattern Detection**: Identify dangerous patterns (reentrancy, `tx.origin`, delegatecall)

### Tier 2: AI Enrichment
- **Protocol Classification**: Auto-detect protocol type (lending, DEX, bridge, etc.)
- **Threat Modeling**: Generate X-Ray threat model integration
- **Invariant Generation**: Create accounting, access-control, ordering, and economic invariants
- **Alert Rules**: Generate detection rules from identified patterns

### Tier 3: Runtime Analysis
- **Foundry Trace Parsing**: Parse Foundry test trace JSON files
- **State Diff Engine**: Compute before/after state differences
- **Oracle Analysis**: Detect price deviations (spot vs TWAP)
- **Role Tracking**: Trace role journeys through execution
- **Gas Analysis**: Measure efficiency metrics with baseline comparison

---

## Installation

### Prerequisites

Ensure you have the following installed:

| Requirement | Minimum Version | Check Command |
|-------------|-----------------|---------------|
| **Node.js** | >= 18.0.0 | `node --version` |
| **npm** | >= 9.0.0 | `npm --version` |
| **Git** | >= 2.0.0 | `git --version` |

#### Installing Node.js

**Using nvm (recommended):**
```bash
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

# Install Node.js 20 LTS
nvm install 20
nvm use 20
```

**Using direct download:**
- Download from [nodejs.org](https://nodejs.org/)
- Choose the LTS version for your operating system

---

### Per-Project Installation (Recommended for Development)

This method installs Trackator locally within a project directory:

```bash
# Clone or navigate to the trackator directory
cd /path/to/trackator

# Install dependencies
npm install

# Build the TypeScript code
npm run build

# Run using npm scripts
npm run init -- "./contracts/**/*.sol"
npm run enrich ./trackator-output
npm run analyze trace.json

# Or run directly
node dist/cli.ts init "./contracts/**/*.sol"
```

**Advantages:**
- Isolated dependencies per project
- Easy to modify and debug
- Version control friendly
- No sudo/admin permissions needed

---

### Global Installation

Install Trackator globally to use the `trackator` command from anywhere:

```bash
# Navigate to the trackator directory
cd /path/to/trackator

# Install dependencies and build
npm install
npm run build

# Link globally
npm link

# Now you can use 'trackator' directly
trackator init "./contracts/**/*.sol"
trackator enrich ./output
trackator analyze trace.json
```

**Or via npm install -g:**
```bash
npm install -g .
```

**Advantages:**
- Use `trackator` command from any directory
- Convenient for frequent usage across multiple projects

**To uninstall global:**
```bash
npm unlink trackator    # If linked
# or
npm uninstall -g trackator  # If installed with -g
```

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-org/trackator.git
cd trackator

# 2. Install dependencies
npm install

# 3. Build the project
npm run build

# 4. Run your first analysis
npm run init -- "examples/sample-lending-protocol/*.sol" --output ./my-analysis --format all

# 5. Enrich with AI analysis
npm run enrich ./my-analysis

# 6. Analyze a Foundry trace (if available)
npm run analyze trace.json --input ./my-analysis
```

---

## Usage

### Tier 1: Static Analysis (`init`)

Parses Solidity contracts and generates structural analysis.

```bash
trackator init <glob-pattern> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `glob-pattern` | Yes | Glob pattern for Solidity files (e.g., `"./contracts/**/*.sol"`) |

**Options:**

| Option | Alias | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `./trackator-output` | Output directory |
| `--format` | | `all` | Output format: `all`, `md`, `html`, `terminal` |
| `--include-node-modules` | | `false` | Include node_modules in scan |
| `--verbose` | `-v` | `false` | Enable verbose output |

**Examples:**

```bash
# Basic usage - analyze all .sol files in contracts folder
trackator init "./contracts/**/*.sol"

# Custom output directory with all formats
trackator init "./src/**/*.sol" --output ./analysis --format all

# Verbose mode for detailed output
trackator init "./contracts/*.sol" --verbose

# Terminal-only output for quick inspection
trackator init "./contracts/**/*.sol" --format terminal
```

---

### Tier 2: AI Enrichment (`enrich`)

Enriches static analysis with threat models and behavioral patterns.

```bash
trackator enrich <input-dir> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `input-dir` | Yes | Directory containing output from `init` command |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--xray` | | Path to X-Ray analysis file to ingest |
| `--breakdown` | | Path to Protocol Breakdown file to ingest |
| `--generate-alerts` | `true` | Generate alert rules from patterns |
| `--protocol-type` | | Override protocol type: `lending`, `dex`, `bridge`, `governance`, `vault`, `other` |
| `--verbose` | `-v` | `false` | Enable verbose output |

**Examples:**

```bash
# Basic enrichment using init output
trackator enrich ./trackator-output

# With external X-Ray report
trackator enrich ./output --xray xray-report.md

# With both external analyses
trackator enrich ./output \
  --xray reports/xray.md \
  --breakdown reports/breakdown.md \
  --protocol-type lending

# Verbose mode
trackator enrich ./output --verbose
```

---

### Tier 3: Runtime Analysis (`analyze`)

Analyzes Foundry trace files and computes state differences.

```bash
trackator analyze <trace-file> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `trace-file` | Yes | Path to Foundry trace JSON file |

**Options:**

| Option | Alias | Default | Description |
|--------|-------|---------|-------------|
| `--input` | `-i` | | Input directory with enriched data |
| `--output` | `-o` | `./results` | Output directory |
| `--format` | | `all` | Output format: `all`, `md`, `html`, `terminal` |
| `--alert-level` | | `medium` | Minimum alert level: `critical`, `high`, `medium`, `low`, `info` |
| `--compare-baseline` | | | Compare against baseline trace file |
| `--focus-contract` | | | Focus analysis on specific contract name |
| `--focus-function` | | | Focus on specific function name |
| `--gas-analysis` | | `true` | Include gas analysis |
| `--oracle-analysis` | | `true` | Include oracle price deviation analysis |
| `--role-tracking` | | `true` | Track role journeys through execution |
| `--verbose` | `-v` | `false` | Enable verbose output |

**Examples:**

```bash
# Basic trace analysis
trackator analyze foundry-trace.json

# Full analysis with enriched input
trackator analyze trace.json \
  --input ./trackator-output \
  --output ./results \
  --format all

# High-priority alerts only
trackator analyze trace.json --alert-level high

# Focus on specific contract
trackator analyze trace.json --focus-contract LendingPool

# Compare with baseline
trackator analyze new-trace.json --compare-baseline baseline.json

# Oracle-focused analysis
trackator analyze trace.json --oracle-analysis --alert-level low
```

---

## Output Formats

Trackator generates three types of output:

### 1. Terminal Output
- ASCII tables with colored output
- Progress spinners for long operations
- Box-drawn summary sections
- Real-time status updates

### 2. Markdown Reports
- Complete analysis report with embedded Mermaid diagrams
- Structured sections for each analysis tier
- Tables for state variables, functions, and alerts
- Copy-paste ready for documentation

### 3. HTML Reports
- Interactive dark-themed interface
- Sortable tables and collapsible sections
- Embedded CSS styling (no external dependencies)
- Browser-ready for sharing

---

## Project Structure

```
trackator/
├── package.json                 # Project config & dependencies
├── tsconfig.json                # TypeScript configuration
├── README.md                    # This file
│
├── src/                         # Source code
│   ├── cli.ts                   # Main CLI entry point (Commander.js)
│   ├── types.ts                 # Core type definitions
│   │
│   ├── parser/
│   │   └── SolidityParser.ts    # Solidity AST parser
│   │
│   ├── tier1-parser/            # TIER 1: Static Analysis
│   │   ├── init-command.ts      # Init command orchestrator
│   │   ├── contract-extractor.ts# Contract extraction engine
│   │   ├── state-inventory.ts   # Storage layout computation
│   │   ├── function-registry.ts # Function catalog & risk scoring
│   │   ├── call-graph.ts        # Call graph builder
│   │   └── diagram-generator.ts # Mermaid diagram generator
│   │
│   ├── tier2-enricher/          # TIER 2: AI Enrichment
│   │   ├── enrich-command.ts    # Enrich command orchestrator
│   │   ├── invariant-generator.ts# Protocol invariant generator
│   │   ├── xray-ingestor.ts     # X-Ray threat model ingester
│   │   └── breakdown-ingestor.ts# Breakdown behavioral ingester
│   │
│   ├── tier3-analyzer/          # TIER 3: Runtime Analysis
│   │   ├── analyze-command.ts   # Analyze command orchestrator
│   │   ├── foundry-trace-parser.ts# Foundry trace parser
│   │   ├── state-diff-engine.ts # State difference calculator
│   │   ├── oracle-analyzer.ts   # Price deviation analyzer
│   │   └── alert-checker.ts     # Alert rule evaluator
│   │
│   ├── renderers/               # Output formatters
│   │   ├── terminal-renderer.ts # Terminal/ASCII output
│   │   ├── md-renderer.ts       # Markdown report generator
│   │   └── html-renderer.ts     # HTML report generator
│   │
│   └── ...                      # Supporting modules
│
├── dist/                        # Compiled JavaScript (after build)
├── examples/                    # Sample contracts for testing
│   └── sample-lending-protocol/
│       ├── SampleLendingProtocol.sol
│       ├── OracleWrapper.sol
│       └── FeeCollector.sol
│
└── node_modules/                # Dependencies (after npm install)
```

---

## Configuration

### TypeScript Configuration

The project uses TypeScript with the following configuration:

```json
{
  "target": "ES2020",
  "module": "commonjs",
  "outDir": "./dist",
  "rootDir": "./src",
  "strict": false,
  "esModuleInterop": true,
  "sourceMap": true,
  "moduleResolution": "node"
}
```

### NPM Scripts

| Script | Command | Description |
|--------|---------|-------------|
| `build` | `tsc` | Compile TypeScript to `dist/` |
| `start` | `node dist/cli.js` | Run compiled CLI |
| `dev` | `ts-node src/cli.ts` | Run directly from TypeScript |
| `test` | `jest` | Run test suite |
| `init` | `ts-node src/cli.ts init` | Quick init command |
| `enrich` | `ts-node src/cli.ts enrich` | Quick enrich command |
| `analyze` | `ts-node src/cli.ts analyze` | Quick analyze command |

---

## Examples

The project includes sample Solidity contracts for testing:

```bash
# Run full analysis on sample contracts
npm run init -- "examples/sample-lending-protocol/*.sol" --output ./sample-output --format all

# View the results
cat ./sample-output/report.md
open ./sample-output/report.html  # macOS
xdg-open ./sample-output/report.html  # Linux
```

### Sample Contracts Included

1. **SampleLendingProtocol.sol** - A lending protocol with borrow/lend functions
2. **OracleWrapper.sol** - Price oracle with spot/TWAP prices
3. **FeeCollector.sol** - Fee collection and distribution

---

## Development

### Setting Up Development Environment

```bash
# Fork/clone the repository
git clone https://github.com/your-org/trackator.git
cd trackator

# Install dependencies
npm install

# Start development mode (auto-restart on changes)
npm run dev -- init "./test-contracts/*.sol"

# Run tests
npm test

# Build for production
npm run build
```

### Code Style Guidelines

- Use TypeScript strict mode for new code
- Follow existing naming conventions (camelCase for variables, PascalCase for types)
- Add JSDoc comments for public APIs
- Include error handling for all async operations

### Adding New Features

1. Create a new module in the appropriate tier directory
2. Export types from `src/types.ts`
3. Add commands to `src/cli.ts` if needed
4. Update this README with new options

---

## Troubleshooting

### Common Issues

**Error: "Cannot find module '@solidity-parser/parser'"**
```bash
npm install
```

**Error: "Command not found: trackator"**
```bash
# For global installation
npm link

# Or use npx instead
npx trackator
```

**Error: "Solidity compilation failed"**
- Ensure `.sol` files are valid Solidity syntax
- Check that solc version matches your contract pragma
- Try updating solc: `npm update solc`

**TypeScript Compilation Errors**
```bash
# Clean rebuild
rm -rf dist
npm run build
```

### Getting Help

```bash
# Show help for main CLI
trackator --help

# Show help for specific command
trackator init --help
trackator enrich --help
trackator analyze --help
```

---

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Contribution Guidelines

- Write tests for new features
- Update documentation for API changes
- Follow the existing code style
- Ensure TypeScript compiles without errors

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```

Copyright (c) 2024 Trackator Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## Acknowledgments

- [Solidity Parser](https://github.com/solidity-parser/parser) - Solidity AST parsing
- [Foundry](https://github.com/foundry-rs/foundry) - Smart contract testing framework
- [Commander.js](https://commander.js/) - CLI framework
- [Mermaid](https://mermaid.js.org/) - Diagram generation
