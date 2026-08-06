## Phase 5: REPORTING

### Objective
Generate comprehensive report of all confirmed and probable findings.

### Report Structure

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
- **Source:** Pattern Match / Creative Attack / Fork
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

## Appendix A: Discarded Hypotheses Summary
| Count | Reason |
|-------|--------|
| {N} | Operational Error (trusted role action) |
| {N} | Design Choice (intentional) |
| {N} | Unreachable (proven by trace) |

## Appendix B: Trackator Context
- **Protocol Type:** {type}
- **Contracts Analyzed:** {N}
- **Entry Points:** {N}
- **Assets at Risk:** {list}
- **Invariants Checked:** {N}

## Appendix C: Trackator Multi-Phase Evidence (v2.0)
> Present when enhanced Trackator data available

### C.1 Storage Dependency Evidence
- Value-bearing variables identified: {N}
- Permissionless writers on value-bearing vars: {N}
- Contended variables (race conditions): {N}
- High-risk shared-state entries: {N}

### C.2 State Coupling Evidence  
- Strong couplings exploitable: {N}
- Hidden couplings discovered: {N}
- Invariant violation chains: {N}

### C.3 Sync Analyzer Evidence
- Critical desync risks: {N}
- Unverified assumptions (no verifier): {N}
- Race windows identified: {N}

### C.4 Evidence Validator Classification
- Six-class classification applied: YES/NO
- Confidence scores calculated: YES/NO
- Disproof engine results: {N} findings tested

## Appendix D: Confidence Scoring & Classification (v2.0)
> Detailed scoring breakdown for each finding

### D.1 Nine-Criteria Reachability Proof
See `templates/report-template.md` Appendix D for full checklist template

### D.2 Classification Distribution
| Class | Count | Action |
|-------|-------|--------|
| confirmed-vulnerability | {N} | Report as P0/P1 |
| potential-vulnerability | {N} | Report as P2 |
| false-positive | {N} | Discard |
| by-design | {N} | Note only |
| informational | {N} | Appendix |
| cannot-determine | {N} | Queue for review |

## Appendix E: Methodology Notes  <!-- Renamed from C -->
{Notes about methodology, limitations, assumptions}

## Appendix F: Raw Data Index  <!-- Renamed from D -->
{Generated artifacts and input data index}
```

### Report Generation Code

```javascript
function generateReport(allHypotheses, context) {
    const confirmed = allHypotheses.filter(h => 
        h.forkTestResult?.deepTest?.finalVerdict === 'CONFIRMED'
    );
    const probable = allHypotheses.filter(h => 
        h.forkTestResult?.deepTest?.finalVerdict === 'PROBABLE'
    );
    const leads = allHypotheses.filter(h => 
        h.status === 'LEAD' || h.reachabilityResult?.verdict === 'lead'
    );
    const discarded = allHypotheses.filter(h => 
        ['DISCARDED', 'DEAD', 'OPERATIONAL_ERROR'].includes(h.status)
    );
    
    const report = {
        metadata: {
            protocol: context.protocolType,
            date: new Date().toISOString(),
            version: '2.0.0'
        },
        executiveSummary: {
            totalHypotheses: allHypotheses.length,
            confirmedCount: confirmed.length,
            probableCount: probable.length,
            leadsCount: leads.length,
            discardedCount: discarded.length,
            truePositiveRate: estimateTPRate(confirmed.length, probable.length, allHypotheses.length)
        },
        findings: {
            critical: confirmed.filter(severityFilter('critical')),
            high: confirmed.filter(severityFilter('high')).concat(probable.filter(severityFilter('high'))),
            medium: probable.filter(severityFilter('medium')),
            leads: leads
        },
        appendix: {
            discardedSummary: categorizeDiscarded(discarded),
            trackatorContext: context,
            methodology: getMethodologyNotes()
        }
    };
    
    // Write markdown report
    const markdown = renderReportToMarkdown(report);
    writeFileSync(`${OUTPUT_DIR}/redteam-trackator-report.md`, markdown);
    
    // Also write JSON for machine consumption
    writeFileSync(`${OUTPUT_DIR}/redteam-trackator-report.json`, JSON.stringify(report, null, 2));
    
    return report;
}
```

---

