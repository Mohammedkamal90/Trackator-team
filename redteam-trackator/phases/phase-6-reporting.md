# Phase 6: REPORTING

> **Part of**: [RedTeam Trackator SKILL.md](../SKILL.md) | **Phase**: 6 of 6
> **Previous**: [Phase 5 - Fork Testing](phase-5-fork-testing.md)
> **Source**: Original SKILL.md Lines 3024-3243 (~220 lines → expanded to ~281 lines with additions)

---

## Objective

Generate comprehensive report of all confirmed and probable findings.

---

## Report Structure

The final output follows a structured markdown format designed for both human readability and machine consumption:

```markdown
# Redteam-Trackator Security Assessment Report

**Protocol:** {PROTOCOL_NAME}
**Assessment Date:** {DATE}
**Trackator Version:** {VERSION}
**Analyst:** Redteam-Trackator v2.0.0

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Hypotheses Generated | {N} |
| Confirmed Vulnerabilities | {N} |
| Probable Findings | {N} |
| Leads for Manual Review | {N} |
| False Positives Discarded | {N} |
| True Positive Rate (Est.) | {X}% |

---

## Critical Findings

### Finding #{ID}: {TITLE}

**Severity:** Critical | High | Medium | Low  
**Status:** CONFIRMED / PROBABLE  
**Category:** {bug_class}  
**Estimated Impact:** ${LOSS_USD} (based on pattern matches)

#### Description
{Clear description of the vulnerability}

#### Discovery Method
- **Phase Detected:** {0-6}
- **Source:** Pattern Match / Creative Attack / Fuzz / Fork
- **Matched Pattern:** {pattern_slug} (if applicable)

#### Technical Details

**Vulnerable Function(s):**
- `{contract}.{function}` (line {N})

**Root Cause:**
{Explanation of why this is a bug, not operational error}

#### Trackator Evidence

**State Diff (from fork test):**
| Variable | Before | After |
|----------|--------|-------|
| {var} | {val} | {val} |

**Alerts Triggered:**
- {ALERT_ID}: {description}

**Invariant Violations:**
- {INV_ID}: {expression}

#### Kill Chain
1. {Step 1}
2. {Step 2}
...
N. {Profit extraction}

#### Execution Trace Summary
{Brief summary of full A→B→C→end trace proving feasibility}

#### Fork Test Proof
- **TX Hash:** `{hash}` (mainnet fork block: {block})
- **Gas Used:** {gas}
- **Attacker Profit:** {profit}

#### Economic Assessment
| Metric | Value |
|--------|-------|
| Capital Required | {amount} |
| Gas Cost | {cost} |
| Estimated Profit | {profit} |
| Feasibility | HIGH / MEDIUM / LOW |

*Note: Economic assessment INFORMS decision, never blocks reporting.*

#### Recommendation
{Recommendation for fix}

---

## Probable Findings
{Same format but marked as PROBABLE}

## Leads for Manual Review
{Brief descriptions of interesting patterns needing human review}
```

---

## Appendices

### Appendix A: Discarded Hypotheses Summary

| Count | Reason |
|-------|--------|
| {N} | Operational Error (trusted role action) |
| {N} | Design Choice (intentional) |
| {N} | Unreachable (proven by trace) |
| {N} | Unrealistic State (fuzz artifact) |

### Appendix B: Trackator Context

- **Protocol Type:** {type}
- **Contracts Analyzed:** {N}
- **Entry Points:** {N}
- **Assets at Risk:** {list}
- **Invariants Checked:** {N}

### Appendix C: Trackator Multi-Phase Evidence (v2.0)

> Present when enhanced Trackator data available

#### C.1 Storage Dependency Evidence
- Value-bearing variables identified: {N}
- Permissionless writers on value-bearing vars: {N}
- Contended variables (race conditions): {N}
- High-risk shared-state entries: {N}

#### C.2 State Coupling Evidence  
- Strong couplings exploitable: {N}
- Hidden couplings discovered: {N}
- Invariant violation chains: {N}

#### C.3 Sync Analyzer Evidence
- Critical desync risks: {N}
- Unverified assumptions (no verifier): {N}
- Race windows identified: {N}

#### C.4 Evidence Validator Classification
- Six-class classification applied: YES/NO
- Confidence scores calculated: YES/NO
- Disproof engine results: {N} findings tested

### Appendix D: Confidence Scoring & Classification (v2.0)

> Detailed scoring breakdown for each finding

#### D.1 Nine-Criteria Reachability Proof

See `templates/report-template.md` Appendix D for full checklist template.

#### D.2 Classification Distribution

| Class | Count | Action |
|-------|-------|--------|
| confirmed-vulnerability | {N} | Report as P0/P1 |
| potential-vulnerability | {N} | Report as P2 |
| false-positive | {N} | Discard |
| by-design | {N} | Note only |
| informational | {N} | Appendix |
| cannot-determine | {N} | Queue for review |

### Appendix E: Methodology Notes

{Notes about methodology, limitations, assumptions}

### Appendix F: Raw Data Index

{Generated artifacts and input data index}

---

## Report Generation Code

> **Full implementation:** See [references/code-examples.md](../references/code-examples.md#report-generation)

### Core Function Signature

```javascript
/**
 * Generate comprehensive security assessment report
 * @param {Array} allHypotheses - All hypotheses from Phases 1-5
 * @param {Object} context - Trackator analysis context
 * @returns {Object} Complete report object with metadata, findings, and appendices
 */
function generateReport(allHypotheses, context);
```

### Output Structure

```javascript
{
    metadata: {
        protocol: string,      // Protocol type identifier
        date: string,          // ISO timestamp
        version: string        // Trackator version
    },
    executiveSummary: {
        totalHypotheses: number,
        confirmedCount: number,
        probableCount: number,
        leadsCount: number,
        discardedCount: number,
        truePositiveRate: number  // Estimated percentage
    },
    findings: {
        critical: Array,       // CONFIRMED critical severity
        high: Array,           // CONFIRMED/PROBABLE high severity
        medium: Array,         // PROBABLE medium severity
        leads: Array           // Items needing manual review
    },
    appendix: {
        discardedSummary: Object,   // Categorized discard reasons
        trackatorContext: Object,   // Full analysis context
        methodology: Object         // Methodology notes
    }
}
```

### Filtering Logic

| Category | Filter Criteria |
|----------|-----------------|
| **Confirmed** | `forkTestResult.deepTest.finalVerdict === 'CONFIRMED'` |
| **Probable** | `forkTestResult.deepTest.finalVerdict === 'PROBABLE'` |
| **Leads** | `status === 'LEAD'` OR `reachabilityResult.verdict === 'lead'` |
| **Discarded** | Status in `['DISCARDED', 'DEAD', 'OPERATIONAL_ERROR']` |

### Output Formats

The generator produces two output files:

1. **Markdown Report** (`redteam-trackator-report.md`)
   - Human-readable formatted report following template structure above
   
2. **JSON Report** (`redteam-trackator-report.json`)
   - Machine-consumable structured data for tooling integration

### Helper Functions Referenced

| Function | Purpose |
|----------|---------|
| `severityFilter(level)` | Filter findings by severity level |
| `estimateTPRate(confirmed, probable, total)` | Calculate estimated true positive rate |
| `categorizeDiscarded(discarded)` | Group discarded items by reason |
| `renderReportToMarkdown(report)` | Convert report object to markdown string |
| `getMethodologyNotes()` | Extract methodology metadata |

---

## Key Principles

1. **Economic assessment INFORMS decision, never blocks reporting** — Even low-feasibility exploits should be documented if technically valid

2. **Evidence hierarchy** — Fork test proof > Execution trace > Pattern match > Hypothesis

3. **Classification drives action** — Use the six-class system to determine reporting priority

4. **Dual output format** — Markdown for humans, JSON for machines/tooling

---

*End of Phase 6: Reporting*
