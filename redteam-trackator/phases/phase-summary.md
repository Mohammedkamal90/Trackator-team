# Phase Summary (Quick Reference)

> **Load this file first** for an overview of all phases. Then load individual phase files as needed.

## Pipeline Overview

```
PHASE 0 → PHASE 1 → PHASE 2 → PHASE 3 → PHASE 4 → PHASE 5
 Ingestion   Intent    Pattern    Creative    Fork       Report
           Filter    Match      Attack      Test
```

## Phase Overview (One-Line Each)

| # | Phase | Input | Output | Owner | File |
|---|-------|-------|--------|-------|------|
| 0 | **Ingestion** | Trackator JSONs | hypothesis-list.json | System | `phase-0-ingestion.md` |
| 1 | **Intent Filtering** | hypothesis-list | filtered-hypotheses | System + Verifier | `phase-1-intent-filtering.md` |
| 2 | **Pattern Matching** | filtered-hypotheses | pattern-matches | Hacker → Verifier | `phase-2-pattern-matching.md` |
| 3 | **Creative Attack** | pattern-matches | creative-findings + traces | Hacker → Verifier | `phase-3-creative-attack.md` |
| 4 | **Fork Testing** | traced-hypotheses | fork-test-results | Hacker → Verifier | `phase-4-fork-testing.md` |
| 5 | **Reporting** | all-results | final-report.md | System | `phase-5-reporting.md` |

## Key Concepts

### Block Gate Paradigm
- **NOT kill gates** — findings are SAVED, not deleted
- Options: `proceed_to_next_phase`, `return_to_hacker`, `save_for_poc`, `save_for_fork`, `discard`, `report_now`

### Trust Boundaries
- Trusted roles: Admin, Governance, Keeper, Oracle (within documented bounds)
- These are NOT attack targets — focus on code flaws that work even when roles behave correctly

### Execution Trace Requirement
- Full A→B→C→end trace MANDATORY before escalating any hypothesis
- No "signs of bug" without complete proof

## Confidence Scoring (v2.1)

| Component | Weight | Description |
|-----------|--------|-------------|
| Pattern Match | 20% | Historical exploit similarity |
| Trace Complete | 20% | Full A→B→C→end trace completed |
| Fork Success | 50% | Confirmed on mainnet fork (includes former fuzz weight) |
| Economic Feasibility | 10% | Profit exceeds cost (informative only) |

## Verdict Tiers

| Tier | Score Range | Action |
|------|-------------|--------|
| CONFIRMED | ≥70% | Report now |
| PROBABLE | ≥40% | Report with caveats |
| LEAD | ≥20% | Appendix only |
| DISCARDED | <20% | Remove from consideration |

## Quick Phase Details

### Phase 0: INGESTION (~320 lines)
- Read Trackator output files
- Extract enhanced fields (storage, coupling, sync, evidence)
- Build initial hypothesis list from alerts
- **Output**: Structured context object + hypothesis list

### Phase 1: INTENT FILTERING (~90 lines)
- Apply Intended Behavior Plugin
- Distinguish bugs from design choices
- **Decision**: `{keep | downgrade | discard}`

### Phase 2: PATTERN MATCHING (~295 lines)
- Match against historical exploit patterns
- Attack Chain Composer (v2.0)
- Reachability Check (BLOCK GATE #1)
- Evidence Validation (6-class classification)
- **Output**: Pattern matches with confidence scores

### Phase 3: CREATIVE ATTACK (~1,360 lines)
- Reverse Engineering Plugin
- Assumption Breaker Plugin
- State Coupling Analysis (v2.0)
- Root Cause Hypothesizer (v2.2)
- **MANDATORY**: Full execution trace
- Reachability Check (BLOCK GATE #2)
- **Output**: Creative findings with complete traces

### Phase 4: FORK TESTING (~665 lines)
- Evidence Calibration System (v2.1)
- Smoke Fork Test
- Deep Fork Testing with Iteration
- Anti-Pattern Library
- **Output**: Fork test results with TX hashes

### Phase 5: REPORTING (~220 lines)
- Generate comprehensive report
- Include evidence tables, appendices
- Classification distribution
- **Output**: final-report.md + final-report.json

## Plugin Index

| Plugin | Phase | Purpose | File |
|--------|-------|---------|------|
| Intended Behavior | 1 | FP early filtering | `plugins/intended-behavior.md` |
| Pattern Matcher | 2 | Historical exploit matching | `plugins/pattern-matcher.md` |
| Attack Chain Composer | 2 | Chain composition + Gate | `plugins/attack-chain-composer.md` |
| Evidence Validator | 2,4 | Six-class classification | Integrated into phases |
| Reachability | 2,3,4 | Feasibility verification | `plugins/reachability.md` |
| Reverse Engineering | 3 | Value flow tracing | `plugins/reverse-engineering.md` |
| State Coupling Analysis | 3 | Coupling-based attacks | Integrated into phase 3 |
| Root Cause Hypothesizer | 3 | Multi-layer causal analysis | `plugins/root-cause-hypothesizer.md` |
| Assumption Breaker | 3 | Trust assumption testing | `plugins/assumption-breaker.md` |
| Attacker Mindset Simulator | 3 | Attacker psychology | `plugins/attacker-mindset-simulator.md` |
| Fork Test | 4 | Mainnet validation | `plugins/fork-test.md` |
| Anti-Pattern Library | 4 | False positive elimination | `plugins/anti-pattern-library.md` |
| Report Generator | 5 | Output formatting | `templates/report-template.md` |

## Agent Index

| Agent | Role | Primary Phases | File |
|-------|------|----------------|------|
| **Hacker Agent** | Offensive security researcher | 3, 4 | `agents/hacker-agent.md` |
| **Verifier Agent** | Defensive skeptic | 2, 3, 4, 5 | `agents/verifier-agent.md` |

## Reference Files

| Reference | When to Use | File |
|-----------|-------------|------|
| Data Structures | Need field definitions | `references/trackator-fields.md` |
| Evidence Calibration | Need classification logic | `references/evidence-calibration.md` |
| Code Examples | Need full JS implementations | See individual phase files |

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.1.0 | 2026-08-06 | **REFACTOR**: Removed Fuzzing; Modular file structure; 5-phase pipeline |
| 2.0.0 | 2026-07-30 | Trackator Enhanced Integration; Disproof Engine; 6-class classification |
| 1.0.0 | 2026-07-26 | Initial release |
