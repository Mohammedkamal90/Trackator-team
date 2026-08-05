# Phase Summary Reference

> **Part of**: [RedTeam Trackator SKILL.md](../SKILL.md) | **Type**: Quick Reference (load first)
> Load this file first (~10 sec) to understand pipeline state before diving into specific phases.

## Pipeline Flow

```
Phase 0 (Ingestion)
    ↓ hypothesis-list.json
Phase 1 (Intent Filtering)
    ↓ filtered-hypotheses.json
Phase 2 (Pattern Matching)
    ↓ pattern-matches.json (with reachability scores)
Phase 3 (Creative Attack)
    ↓ creative-findings.json + execution-traces.json
Phase 4 (Fuzzing) [optional]
    ↓ fuzz-results.json
Phase 5 (Fork Testing)
    ↓ fork-test-results.json
Phase 6 (Reporting)
    ↓ redteam-trackator-report.md + .json
```

## Phase Signatures

### Phase 0: INGESTION
**Purpose**: Read all Trackator output files, validate structure, build initial hypothesis list from alerts.
**Input**: `trackator-init.json`, `trackator-enrich.json`, optional `trackator-analyze.json` + v2.0 enhanced files
**Output**: `hypotheses-initial.json`, `context-object.json`
**Owner**: System (automated)
**When to load**: Always — this is the entry point

### Phase 1: INTENT FILTERING
**Purpose**: Kill false positives early by distinguishing bugs from design choices and operational errors.
**Input**: Hypothesis list from Phase 0, Trackator enrich data
**Output**: `hypotheses-filtered.json` (only surviving hypotheses)
**Owner**: System + Verifier (uses intended-behavior plugin)
**When to load**: When you have alerts that need filtering

### Phase 2: PATTERN MATCHING
**Purpose**: Match surviving hypotheses against 56+ historical exploit patterns; assess reachability.
**Input**: Filtered hypotheses, Exploits-class-library (optional), Trackator data
**Output**: `pattern-matches.json` with scores and precondition chains
**Owner**: Hacker (matching) → Verifier (reachability BLOCK GATE #1)
**When to load**: When hypotheses survived Phase 1 filtering

### Phase 3: CREATIVE ATTACK
**Purpose**: Find NOVEL vulnerabilities via reverse engineering and assumption breaking. This is where Hacker LIVES.
**Input**: Pattern matches from Phase 2, full Trackator context including v2.0 enhanced data
**Output**: `creative-findings.json` with complete execution traces A→B→C→end
**Owner**: Hacker (PRIMARY) → Verifier (trace validation BLOCK GATE #2)
**When to load**: **Biggest phase (~400 lines)**. Load only when ready for creative analysis.
**v2.0 enhanced data used**: Storage Dependency Analyzer, State Coupling Detector, Sync Analyzer

### Phase 4: FUZZING [OPTIONAL]
**Purpose**: Mechanically validate findings using Echidna/Medusa via Fizz skill; run Disproof Engine.
**Input**: Creative findings with traces from Phase 3
**Output**: `fuzz-results.json` with violation reports and disproof analysis
**Owner**: Hacker (campaign) → Verifier (realism check BLOCK GATE #3)
**When to load**: Optional — skip if Fizz skill unavailable or time-constrained

### Phase 5: FORK TESTING
**Purpose**: Confirm exploits on real mainnet state via Foundry fork. Highest evidence value.
**Input**: Best findings from Phases 3-4, Fork RPC URL, block number
**Output**: `fork-test-results.json` with TX hashes and Trackator visualization
**Owner**: Hacker (iterates) → Verifier (evidence validation BLOCK GATE #4)
**When to load**: When you have findings worth confirming on mainnet

### Phase 6: REPORTING
**Purpose**: Generate final assessment report with confidence scoring and evidence tables.
**Input**: All artifacts from Phases 0-5
**Output**: `redteam-trackator-report.md` + `redteam-trackator-report.json`
**Owner**: System (automated generation)
**When to load**: When all analysis phases complete

---

## Quick Decision Tree

```
Starting assessment?
→ Load SKILL.md + phase-summary.md + phase-0-ingestion.md

Have hypotheses to filter?
→ Load phase-1-intent-filtering.md

Hypotheses survived filtering?
→ Load phase-2-pattern-matching.md

Have pattern matches?
→ Load phase-3-creative-attack.md (biggest file)

Need to confirm on mainnet?
→ Load phase-5-fork-testing.md

Ready to write report?
→ Load phase-6-reporting.md

Need data structure details?
→ Load references/trackator-fields.md

Need full code implementations?
→ Load references/code-examples.md
```

---

## v2.0 Enhanced Data Availability

| Enhanced Data | Source File | Used In | Key Fields |
|---------------|-------------|---------|------------|
| Storage Dependency Analyzer | `trackator-storage.json` | P3 | variableWriters, valueBearingVariables, contendedVariables |
| State Coupling Detector | `trackator-coupling.json` | P3 | functionDependencyMatrix, hiddenCouplings, invariantFunctionMap |
| Sync Analyzer | `trackator-sync.json` | P3, P5 | assumptionDependencyGraph, criticalDesyncRisks |
| Evidence Validator | `trackator-evidence.json` | P2, P4 | classificationRegistry, reachabilityAnalysis |

**Note**: If enhanced files missing, system operates in v1.0 mode (basic Trackator output only).
