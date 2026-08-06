---
name: redteam-trackator
description: Offensive security assessment for Solidity/DeFi protocols using Trackator output as input. Two-agent architecture (Creative Hacker + Verifier) with block-gate paradigm. Trigger on "redteam", "security audit", "offensive testing", "vulnerability assessment", "find exploits", "hack smart contract", "redteam-trackator".
version: 2.1.0
---

# Redteam-Trackator v2.1

A two-agent offensive security assessment system that consumes **Trackator** static/runtime analysis output to find **true positive** smart contract vulnerabilities in Solidity/DeFi protocols.

## Core Philosophy

| Old Redteam-Swarm | Redteam-Trackator |
|-------------------|-------------------|
| 50+ agents, 20 kill gates | **2 agents (Hacker + Verifier), Block gates** |
| Kills everything including TPs | **Saves findings for PoC validation** |
| "Everyone is malicious" (kills governance bugs) | **"Roles trusted, setup audited"** |
| Partial execution traces | **Full A→B→C→end trace REQUIRED** |
| Binary bug/no-bug output | **Graded: confirmed/probable/lead/dead** |
| TP survival rate: ~0% | **TP survival rate: estimated 60-80%** |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    REDTEAM-TRACKATOR PIPELINE v2.1                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PHASE 0: INGESTION ──────────┐                                    │
│  ├── Read Trackator output     │                                    │
│  ├── Extract Enhanced Fields  │  ← Storage/Coupling/Sync/Evidence   │
│  └── Build hypothesis list     │                                    │
│              ↓                 │                                    │
│  PHASE 1: INTENT FILTERING     │  ← Kill FPs EARLY                  │
│  ├── Intended Behavior Plugin  │                                    │
│  └── {keep | downgrade | discard}                                   │
│              ↓                 │                                    │
│  PHASE 2: PATTERN MATCHING     │  ← Historical exploit cards        │
│  ├── Pattern Matcher Plugin    │                                    │
│  ├── Attack Chain Composer     │  ← Chain composition + Gate        │
│  ├── Evidence Validation       │  ← 6-class classification         │
│  ├── Reachability Check        │  ← BLOCK GATE #1                   │
│  └── {confirmed | probable | lead | dead}                           │
│              ↓                 │                                    │
│  PHASE 3: CREATIVE ATTACK      │  ← Where Hacker LIVES             │
│  ├── Reverse Engineering       │  ← Storage Dep. data              │
│  ├── Assumption Breaker        │  ← Sync Analyzer data            │
│  ├── State Coupling Analysis   │  ← Coupling-based attacks        │
│  ├── Root Cause Hypothesizer   │  ← Why > What (v2.2)            │
│  ├── Full Execution Trace ★    │  ← MANDATORY                      │
│  └── Reachability Check        │  ← BLOCK GATE #2                   │
│              ↓                 │                                    │
│  PHASE 4: FORK TESTING        │  ← Mainnet check + FP elimination   │
│  ├── Smoke Fork               │                                    │
│  ├── Deep Fork + Iteration ★★ │  ← Hacker lives HERE              │
│  ├── Anti-Pattern Library     │  ← Disproof Engine                │
│  └── Evidence Validation       │  ← 9-criteria proof              │
│              ↓                 │                                    │
│  PHASE 5: REPORTING           │                                    │
│  └── redteam-trackator-report.md ← ENHANCED: Evidence tables      │
│                                                                     │
│  ★ = Full execution trace A→B→C→end MANDATORY before escalation     │
│  ★★ = Hacker iterates on fork until success or max iterations       │
└─────────────────────────────────────────────────────────────────────┘
```

## File Loading Map

> **When to load which file. This table is your navigation system.**

### Phase Files (Load Per-Phase)

| Phase | Name | When to Load | File | Size |
|-------|------|--------------|------|------|
| Summary | Quick Reference | **Always first** (~10 sec) | `phases/phase-summary.md` | ~170 lines |
| 0 | Ingestion | Starting any assessment | `phases/phase-0-ingestion.md` | ~320 lines |
| 1 | Intent Filtering | Have alerts to filter | `phases/phase-1-intent-filtering.md` | ~90 lines |
| 2 | Pattern Matching | Surviving hypotheses from P1 | `phases/phase-2-pattern-matching.md` | ~295 lines |
| 3 | Creative Attack | Matched patterns ready | `phases/phase-3-creative-attack.md` | ~1360 lines |
| 4 | Fork Testing | Traced hypotheses ready | `phases/phase-4-fork-testing.md` | ~665 lines |
| 5 | Reporting | Fork results ready | `phases/phase-5-reporting.md` | ~220 lines |

### Reference Files (Load On-Demand)

| Reference | When to Use | File | Size |
|-----------|-------------|------|------|
| Data Structures | Need field definitions | `references/trackator-fields.md` | ~140 lines |
| Evidence System | Need calibration/classification logic | `references/evidence-calibration.md` | ~320 lines |

### Agent & Plugin Files (Load When Active)

| Component | Primary Phase | File | Size |
|-----------|---------------|------|------|
| Hacker Agent | 3, 4 | `agents/hacker-agent.md` | ~525 lines |
| Verifier Agent | 2, 3, 4, 5 | `agents/verifier-agent.md` | ~660 lines |
| Intended Behavior Plugin | 1 | `plugins/intended-behavior.md` | ~640 lines |
| Pattern Matcher Plugin | 2 | `plugins/pattern-matcher.md` | ~750 lines |
| Attack Chain Composer Plugin | 2 | `plugins/attack-chain-composer.md` | ~1210 lines |
| Reachability Plugin | 2, 3, 4 | `plugins/reachability.md` | ~830 lines |
| Reverse Engineering Plugin | 3 | `plugins/reverse-engineering.md` | ~975 lines |
| Assumption Breaker Plugin | 3 | `plugins/assumption-breaker.md` | ~795 lines |
| Root Cause Hypothesizer Plugin | 3 | `plugins/root-cause-hypothesizer.md` | ~920 lines |
| Attacker Mindset Simulator Plugin | 3 | `plugins/attacker-mindset-simulator.md` | ~1370 lines |
| Fork Test Plugin | 4 | `plugins/fork-test.md` | ~650 lines |
| Anti-Pattern Library Plugin | 4 | `plugins/anti-pattern-library.md` | ~890 lines |
| Report Template | 5 | `templates/report-template.md` | ~890 lines |

**Loading Strategy:**
1. **ALWAYS**: Load this file (`SKILL.md`) + `phases/phase-summary.md`
2. **PER-PHASE**: Load ONLY the current phase file when working on that phase
3. **ON-DEMAND**: Load `references/` only when you need specific data structures or logic
4. **WHEN ACTIVE**: Load agent/plugin files when that component is executing

## Parameters

### Required
- `TRACKATOR_OUTPUT_DIR`: Path containing Trackator JSON files (`trackator-init.json`, `trackator-enrich.json`, optionally `trackator-analyze.json`)
- `TARGET_PROTOCOL`: Name/description of protocol under audit

### Optional (but recommended)
- `EXPLOITS_LIBRARY_PATH`: Path to Exploits-class-library (default: `./Exploits-class-library/`)
- `MAX_FORK_ITERATIONS`: Maximum fork test iterations (default: 10)
- `FORK_BLOCK_NUMBER`: Mainnet block number to fork (default: latest)
- `OUTPUT_DIR`: Trackator tool output directory (default: `./trackator-output/`)

### v2.0: Enhanced Trackator Output (NEW)
When Trackator produces enhanced output (v2.0+), additional files are available:
- `trackator-storage.json` — Storage Dependency Analyzer output
- `trackator-coupling.json` — State Coupling Detector output  
- `trackator-sync.json` — Sync Analyzer output
- `trackator-evidence.json` — Evidence Validator output

## Workflow Rules (Summary)

> Full rules in each phase file. Key principles:

1. **Full Execution Trace**: A→B→C→end MANDATORY before escalating
2. **Trust Role Protection**: Admin/governance/keeper are trusted, not targets
3. **Operational Error Exclusion**: Bad config ≠ Bad code
4. **Block Gate Paradigm**: SAVE findings for PoC, don't DELETE them

## Phase Overview (One-Line Each)

| # | Phase | Input | Output | Owner |
|---|-------|-------|--------|-------|
| 0 | Ingestion | Trackator JSONs | hypothesis-list.json | System |
| 1 | Intent Filtering | hypothesis-list | filtered-hypotheses | System + Verifier |
| 2 | Pattern Matching | filtered-hypotheses | pattern-matches | Hacker → Verifier |
| 3 | Creative Attack | pattern-matches | creative-findings + traces | Hacker → Verifier |
| 4 | Fork Testing | traced-hypotheses | fork-test-results | Hacker → Verifier |
| 5 | Reporting | all-results | final-report.md | System |

**Detailed instructions**: See `phases/phase-N-name.md` for each phase.
**Data structure definitions**: See `references/trackator-fields.md`.
**Evidence calibration logic**: See `references/evidence-calibration.md`.

## Confidence Score Calculation (v2.1)

```javascript
function calculateConfidence(finding) {
    const weights = {
        patternMatch: 0.20,    // Historical exploit similarity
        traceComplete: 0.20,   // Full A→B→C→end trace completed
        forkSuccess: 0.50,     // Confirmed on forked mainnet (includes former fuzz weight)
        economicFeasibility: 0.10  // Profit exceeds cost (informative)
    };
    
    let score = 0;
    score += weights.patternMatch * (finding.patternMatchScore || 0);
    score += weights.traceComplete * (finding.executionTrace?.completed ? 1 : 0);
    score += weights.forkSuccess * (finding.forkTestResult?.deepTest?.success ? 1 : 0);
    score += weights.economicFeasibility * (isEconomicallyViable(finding) ? 1 : 0);
    
    // Map to tier
    if (score >= 0.7) finding.tier = 'CONFIRMED';
    else if (score >= 0.4) finding.tier = 'PROBABLE';
    else if (score >= 0.2) finding.tier = 'LEAD';
    else finding.tier = 'DISCARDED';
    
    return score;
}
```

## Error Handling Summary

| Error | Action |
|-------|--------|
| No Trackator data | Run in degraded mode (basic static analysis only) |
| No Exploits library | Skip pattern matching, proceed with creative attack |
| Fork RPC unavailable | Skip Phase 4, report earlier findings with lower confidence |

## Dependencies

- **Trackator**: Static/runtime analysis tool (required)
- **Exploits-class-library**: Historical exploit patterns (recommended)
- **Foundry**: Fork testing framework (required for Phase 4)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **2.1.0** | 2026-08-06 | **REFACTOR**: Modular file structure; Removed Fuzzing (separate skill); 5-phase pipeline; SKILL.md as navigation hub |
| 2.0.0 | 2026-07-30 | **MAJOR**: Trackator Enhanced Integration; Disproof Engine; 6-class classification; 9-criteria reachability proof |
| 1.0.0 | 2026-07-26 | Initial release with 6-phase pipeline |

## Quality Assurance Checklist (Summary)

Before finalizing report:
- [ ] All confirmed findings have COMPLETE execution traces (A→B→C→end)
- [ ] No finding relies on "admin is malicious" scenario
- [ ] All operational errors properly excluded
- [ ] Fork test TX hashes are valid and verifiable
- [ ] Economic assessments inform but don't block findings
- [ ] **v2.0+**: Enhanced Trackator data utilized where available
- [ ] **v2.0+**: 6-class classification applied to all findings

---
*This is the navigation hub. For detailed instructions, see individual phase files.*
