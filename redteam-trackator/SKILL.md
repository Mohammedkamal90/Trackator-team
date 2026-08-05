---
name: redteam-trackator
description: Offensive security assessment for Solidity/DeFi protocols using Trackator output as input. Two-agent architecture (Creative Hacker + Verifier) with block-gate paradigm. Trigger on "redteam", "security audit", "offensive testing", "vulnerability assessment", "find exploits", "hack smart contract", "redteam-trackator".
---

# Redteam-Trackator

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
│                    REDTEAM-TRACKATOR PIPELINE v2.0                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PHASE 0: INGESTION ──→ Read Trackator output, build hypotheses     │
│  PHASE 1: INTENT FILTERING → Kill FPs early (intended-behavior)     │
│  PHASE 2: PATTERN MATCHING → Historical exploits + reachability     │
│  PHASE 3: CREATIVE ATTACK → Reverse eng. + assumption breaking      │
│  PHASE 4: FUZZING → Echidna/Medusa via Fizz (optional)             │
│  PHASE 5: FORK TESTING → Mainnet fork confirmation                  │
│  PHASE 6: REPORTING → Final assessment report                       │
│                                                                     │
│  ★ = Full execution trace MANDATORY before escalation               │
│  🆕 = New v2.0 capability from Trackator Enhanced Output            │
└─────────────────────────────────────────────────────────────────────┘
```

## Parameters

### Required
- `TRACKATOR_OUTPUT_DIR`: Path containing Trackator JSON files (`trackator-init.json`, `trackator-enrich.json`, optionally `trackator-analyze.json`)
- `TARGET_PROTOCOL`: Name/description of protocol under audit

### Optional (but recommended)
- `EXPLOITS_LIBRARY_PATH`: Path to Exploits-class-library (default: `./Exploits-class-library/`)
- `FIZZ_SKILL_PATH`: Path to Fizz skill for fuzzing integration (optional but recommended)
- `MAX_FORK_ITERATIONS`: Maximum fork test iterations (default: 10)
- `FORK_BLOCK_NUMBER`: Mainnet block number to fork (default: latest)
- `OUTPUT_DIR`: Report output directory (default: `./redteam-output/`)

### v2.0: Enhanced Trackator Output (NEW)
When Trackator produces enhanced output (v2.0+), additional files available:
- `trackator-storage.json` — Storage Dependency Analyzer output
- `trackator-coupling.json` — State Coupling Detector output
- `trackator-sync.json` — Sync Analyzer output
- `trackator-evidence.json` — Evidence Validator output

**Backward Compatibility**: If enhanced files missing, operates in v1.0 mode using basic Trackator output.

## Workflow Rules

1. **Follow phases in order** — each phase produces artifacts consumed by next phase
2. **Never skip execution trace** — partial traces produce false positives
3. **Block gates save, never kill** — unvalidated findings go to PoC queue, not trash
4. **Trust roles are trusted** — admin/keeper/governance are NOT malicious unless code allows privilege escalation TO that role
5. **Operational errors ≠ bugs** — bad config by trusted role is operational, not vulnerability
6. **Trackator is ground truth** — all analysis builds on Trackator observations, not speculation

---

## STRICT RULES (Non-Negotiable)

> ⚠️ These rules stay INLINE — they are guardrails referenced by EVERY phase. Extracting them creates gap risk.

### Rule 1: Full Execution Trace Requirement

> *"Before escalating ANY hypothesis to Verifier, Hacker MUST complete full execution trace A → B → C → end of execution."*

- Trace through ALL downstream function calls until execution returns to caller
- If a later step patches the issue → hypothesis dies BEFORE reaching Verifier
- No exceptions. No shortcuts.
- Use `calls[]` array from Trackator init.json to build complete call graph

### Rule 2: Trust Role Protection

> *"Trusted roles (admin, keeper, governance, oracle operator) are TRUSTED."*

**Trusted actions (NOT bugs):**
- Admin calls privileged function correctly → Operational
- Governance passes proposal following rules → By design
- Keeper triggers liquidation when conditions met → Working as intended
- Oracle returns price within documented bounds → Expected behavior

**BUT these ARE bugs:**
- Code allows privilege escalation TO trusted role without proper process
- Access control check has logic error (wrong variable, bypassable condition)
- Trusted role function has arithmetic overflow on ANY valid input
- Missing access control where spec requires it

### Rule 3: Operational Error Exclusion

> *"Operational errors are NOT smart contract bugs."*

| Scenario | Verdict | Reason |
|----------|---------|--------|
| Admin sets feeRate = 99% | NOT BUG | Trusted role making config choice |
| Admin sets oracle = dead address | NOT BUG | Operational failure |
| Keeper doesn't call liquidate() | NOT BUG | Human oversight |
| Governance passes proposal to drain funds | NOT BUG | Governance working as designed |
| Admin pauses contract forever | NOT BUG | Privileged function doing its job |

**Exception**: If CODE has flaw even for valid inputs (e.g., arithmetic overflow) → IS a bug.

### Rule 4: Block Gate Paradigm

> *"Block gates SAVE findings for PoC validation. Kill gates DELETE findings."*

```
OLD KILL GATE:
Finding → "Can't prove reachability" → DELETE FOREVER ❌

NEW BLOCK GATE:
Finding → "Can't prove reachability yet" → SAVE to PoC queue ✅
→ Later: Fork test proves it works → CONFIRMED ✅
→ Later: Fork test fails → DEAD (but we tried)
```

**Canonical Verdict States (ALL files MUST use these exactly):**

| State | Meaning | Action |
|-------|---------|--------|
| `CONFIRMED` | Proven on forked mainnet with TX hash | Include in report as confirmed finding |
| `PROBABLE` | Strong evidence, partial replication or minor gaps | Include with caveats in report |
| `LEAD` | Interesting pattern worth expert manual review | Appendix only |
| `INCOMPLETE` | Missing information or trace — return to Hacker | Block gate: send back for completion |
| `DEAD` | Proven impossible after thorough investigation | Discard silently |
| `OPERATIONAL_ERROR` | Trusted role using authorized function correctly | Discard with note (not a vulnerability) |
| `DESIGN_CHOICE` | Intentional architecture decision | Note in methodology, don't report as vuln |

**Sub-states (internal tracking only):**
- `CONFIRMED_REACHABLE` → All preconditions met at reachability gate
- `PENDING` → Initial state, awaiting analysis
- `FILTERED` → Passed Phase 1 intent filtering
- `MATCHED` → Has pattern match from Phase 2
- `TESTED` → Has execution trace from Phase 3

**⚠️ CRITICAL**: All agent and plugin files MUST use these exact verdict values. No lowercase variants.

---

## File Loading Map

> **When to load which file. This table is your navigation system.**

| Phase | Name | When to Load | File | Size |
|-------|------|--------------|------|------|
| Summary | Quick Reference | Always first (~10 sec) | `phases/phase-summary.md` | ~117 lines |
| 0 | Ingestion | Starting any assessment | `phases/phase-0-ingestion.md` | ~172 lines |
| 1 | Intent Filtering | Have alerts to filter | `phases/phase-1-intent-filtering.md` | ~176 lines |
| 2 | Pattern Matching | Surviving hypotheses from P1 | `phases/phase-2-pattern-matching.md` | ~215 lines |
| 3 | Creative Attack | Matched patterns ready | `phases/phase-3-creative-attack.md` | ~488 lines |
| 4 | Fuzzing | Traced hypotheses ready | `phases/phase-4-fuzzing.md` | ~373 lines |
| 5 | Fork Testing | Fuzz-validated findings | `phases/phase-5-fork-testing.md` | ~694 lines |
| 6 | Reporting | Fork results ready | `phases/phase-6-reporting.md` | ~281 lines |
| Ref | Data Structures | Need field definitions | `references/trackator-fields.md` | ~1,582 lines |
| Ref | Code Examples | Need full JS implementations | `references/code-examples.md` | ~2,722 lines |

**Loading strategy:**
1. **Always**: SKILL.md (this file) + `phase-summary.md`
2. **Per-phase**: Load ONLY the current phase file
3. **On-demand**: Load `references/` only when need data structures or big code blocks

---

## Phase Overview (One-Line Each)

| # | Phase | Input | Output | Owner |
|---|-------|-------|--------|-------|
| 0 | Ingestion | Trackator JSONs | hypothesis-list.json | System |
| 1 | Intent Filtering | hypothesis-list | filtered-hypotheses | System + Verifier |
| 2 | Pattern Matching | filtered-hypotheses | pattern-matches | Hacker → Verifier |
| 3 | Creative Attack | pattern-matches | creative-findings + traces | Hacker → Verifier |
| 4 | Fuzzing | creative-findings | fuzz-results | Hacker → Verifier |
| 5 | Fork Testing | best-findings | fork-test-results | Hacker → Verifier |
| 6 | Reporting | all-results | final-report.md | System |

**Detailed instructions**: See `phases/phase-N-name.md` for each phase.
**Data structure definitions**: See `references/trackator-fields.md`.
**Full code examples**: See `references/code-examples.md`.

---

## Agent & Plugin Index

### Agents (see `agents/` directory for full specs)

| Agent | Role | Primary Phases |
|-------|------|----------------|
| **Creative Hacker** | Offensive researcher, attacker mindset | Phase 3, Phase 5 |
| **Verifier** | Defensive skeptic, validates findings | Phase 2, 3, 4, 5, 6 |

### Plugins (see `plugins/` directory for full specs)

| Plugin | Phase | Purpose |
|--------|-------|---------|
| Intended Behavior | 1 | FP early filtering |
| Pattern Matcher | 2 | Historical exploit matching |
| Reachability | 2-5 | Feasibility verification (BLOCK GATE) |
| Reverse Engineering | 3 | Value flow tracing |
| Assumption Breaker | 3 | Trust assumption testing |
| State Coupling Analysis | 3 | Coupling-based attacks (v2.0) |
| Realism Check | 4 | Fuzz result validation (BLOCK GATE) |
| Disproof Engine | 4 | False positive elimination (v2.0) |
| Fork Test | 5 | Mainnet validation |

---

## Confidence Score Calculation

```javascript
confidence = (patternMatch × 0.20) + (traceComplete × 0.20) + 
             (fuzzValidation × 0.15) + (forkSuccess × 0.35) + 
             (economicFeasibility × 0.10)
```

| Score Range | Tier | Action |
|-------------|------|--------|
| ≥ 0.7 | CONFIRMED | Report as finding |
| 0.4 - 0.7 | PROBABLE | Report with caveats |
| 0.2 - 0.4 | LEAD | Appendix only |
| < 0.2 | DISCARDED | Don't report |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.1.0 | 2026-08-04 | **SPLIT**: Optimized for reduced token load; phases extracted to separate files |
| 2.0.0 | 2026-07-30 | **MAJOR**: Trackator Enhanced Integration - Storage/Coupling/Sync/Evidence validators |
| 1.0.0 | 2026-07-26 | Initial release with 6-phase pipeline |

---

## Dependencies

### Required
| Dependency | Purpose |
|------------|---------|
| Trackator (any version) | Static/runtime analysis input |
| Foundry (latest) | Fork testing (Phase 5) |
| Node.js 18+ | Script execution |

### Optional (but recommended)
| Dependency | Purpose |
|------------|---------|
| Fizz skill | Echidna/Medusa fuzz integration (Phase 4) |
| Exploits-class-library | Historical pattern matching (Phase 2) |
