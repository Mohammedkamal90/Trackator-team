# Redteam-Trackator Report Template

**Version**: 2.0.0
**Format**: Markdown (primary) + JSON (machine-readable supplement)
**Compliance**: Uses canonical verdict states from SKILL.md Rule 4
**v2.0 Enhancement**: Includes Trackator multi-phase evidence (Storage, Coupling, Sync, Evidence Validator)

---

## Complete Report Structure

```markdown
# Redteam-Trackator Security Assessment Report

**Protocol:** {PROTOCOL_NAME}
**Assessment Date:** {ISO_DATE_STRING}
**Trackator Version:** {TRACKATOR_VERSION}
**Assessor:** Redteam-Trackator v2.0.0 (Automated + Human-in-the-loop)
**Pipeline Completion:** Phases 0-6 {FULLY_COMPLETE | PARTIAL (Phases X, Y skipped)}

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Assessment Scope & Methodology](#scope--methodology)
3. [Critical Findings (CONFIRMED)](#critical-findings-confirmed)
4. [High Severity Findings](#high-severity-findings)
5. [Medium Severity Findings](#medium-severity-findings)
6. [Probable Findings](#probable-findings)
7. [Leads for Manual Review](#leads-for-manual-review)
8. [Appendix A: Discarded Hypotheses Summary](#appendix-a-discarded-hypotheses)
9. [Appendix B: Trackator Context](#appendix-b-trackator-context)
10. [Appendix C: Trackator Multi-Phase Evidence (v2.0)](#appendix-c-trackator-multi-phase-evidence-v20)  <!-- NEW -->
11. [Appendix D: Confidence Scoring & Classification (v2.0)](#appendix-d-confidence-scoring--classification-v20)  <!-- NEW -->
12. [Appendix E: Methodology Notes & Limitations](#appendix-e-methodology-notes--limitations)
13. [Appendix F: Raw Data Index](#appendix-f-raw-data-index)

---
```

---

## Section Templates

### 1. Executive Summary Template

```markdown
## Executive Summary

### Assessment Statistics

| Metric | Value |
|--------|-------|
| **Total Hypotheses Generated** | {N} |
| **CONFIRMED Vulnerabilities** | {N} |
| **PROBABLE Findings** | {N} |
| **LEADs for Manual Review** | {N} |
| **False Positives Discarded** | {N} |
| **Estimated True Positive Rate** | {X}% |

### Severity Distribution

| Severity | CONFIRMED | PROBABLE | LEAD | Total |
|----------|-----------|----------|------|-------|
| Critical | {N} | {N} | {N} | {N} |
| High | {N} | {N} | {N} | {N} |
| Medium | {N} | {N} | {N} | {N} |
| Low | {N} | {N} | {N} | {N} |

### Key Findings Summary

{Brief paragraph (3-5 sentences) summarizing most critical findings and overall risk posture}

### Assets at Risk

| Asset Type | Location | Estimated Value at Risk | Confidence |
|------------|----------|----------------------|------------|
| {ERC20/LP/Shares} | {Contract.Variable} | ${USD_ESTIMATE} | {HIGH/MEDIUM/LOW} |

### Recommendations Priority Matrix

| Priority | Action | Affected Finding(s) |
|----------|--------|---------------------|
| P0 - Immediate | {Action description} | {Finding IDs} |
| P1 - 7 Days | {Action description} | {Finding IDs} |
| P2 - 30 Days | {Action description} | {Finding IDs} |
```

---

### 2. Assessment Scope & Methodology Template

```markdown
## Assessment Scope & Methodology

### In-Scope

- **Protocol:** {Name} v{version}
- **Contracts Analyzed:** {N} contracts
- **Network:** {Mainnet/Goerli/etc} at block #{block_number}
- **Assessment Period:** {Start Date} to {End Date}

### Out of Scope

{List what was NOT assessed, e.g.:}
- Centralized backend/off-chain components
- Social engineering / governance capture scenarios
- Operational security of node operators
- Economic modeling beyond individual transaction feasibility

### Methodology

This assessment used the **Redteam-Trackator** pipeline:

```
Phase 0: INGESTION → Trackator output parsed, {N} hypotheses generated
Phase 1: INTENT FILTERING → {N} FPs discarded, {N} survived
Phase 2: PATTERN MATCHING → {N} pattern matches found
Phase 3: CREATIVE ATTACK → {N} novel attack ideas generated
Phase 4: FUZZING → {N} fuzz campaigns run ({N} violations)
Phase 5: FORK TESTING → {N} fork test sessions completed
Phase 6: REPORTING → This document
```

### Tools & Data Sources

| Tool/Data Source | Version/Purpose |
|------------------|-----------------|
| Trackator (Static Analysis) | {version} — Contract structure, invariants, alerts |
| Exploits-class-library | {card_count} patterns — Historical exploit matching |
| Foundry (Fork Testing) | {version} — Mainnet state validation |
| Echidna/Medusa (Fuzzing) | {version} — State space exploration |
| Fizz Skill | {version} — Property generation |

### Rules Applied

✅ Full execution trace required before escalation (A→B→C→end)
✅ Block gates save findings, don't kill them
✅ Trusted roles (admin/governance/keeper) are trusted, not compromised
✅ Operational errors distinguished from code bugs
✅ Economic assessment informs but never blocks reporting
```

---

### 3. Finding Template (CRITICAL/HIGH)

```markdown
### Finding #{ID}: {SHORT_TITLE}

**Severity:** 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW  
**Status:** ✅ CONFIRMED / ⚠️ PROBABLE  
**Category:** {reentrancy | access-control | oracle-manipulation | flash-loan | accounting-error | ...}  
**CVSS Score (Estimate):** {X.X}  
**Estimated Impact:** ${LOSS_USD_RANGE} (based on pattern matches and TVL)  
**Discovery Phase:** {0-6}  
**Discovery Method:** {Pattern Match / Creative Attack / Fuzz / Fork Test}

---

#### Description

{Clear 2-4 paragraph description of the vulnerability:
- What is the bug?
- What allows it to exist?
- What can an attacker achieve?
- Why is this not an operational error or design choice?}

#### Technical Details

**Vulnerable Contract(s):**
- `{CONTRACT_NAME}` ({file.sol}:{line_range})

**Vulnerable Function(s):**
| Function | Visibility | Modifiers | Issue |
|----------|------------|-----------|-------|
| `{functionName()`} | {public/external} | `{modifier1}, {modifier2}` | {CEI violation / Missing check / ...} |

**Root Cause:**
{1-2 sentence explanation of the fundamental flaw}

**Code Snippet (Vulnerable Pattern):**
```solidity
// Show the vulnerable code pattern (anonymized if needed)
function vulnerable() external {
    // Line 1: Does something bad
    // Line 2: External call here
    // Line 3: State update AFTER call (CEI violation!)
}
```

#### Trackator Evidence

**Alerts Triggered:**
| Alert ID | Name | Severity | How It Relates |
|----------|------|----------|----------------|
| {ALERT_X} | {Alert name} | {severity} | {Explanation} |

**Invariants Violated:**
| Invariant ID | Expression | Expected | Actual (in exploit) |
|--------------|------------|----------|-------------------|
| {INV_X} | {expression} | {should hold} | {what happened} |

**State Diff (from fork test):**
| Variable | Address/Location | Before | After | Change |
|----------|------------------|--------|-------|--------|
| {var_name} | {address} | {value} | {value} | {Δ} |

**Money Flow Impact:**
{Which money flows were affected? Where did value leak?}

#### v2.0: Trackator Multi-Phase Evidence (Enhanced)

> **Note:** This section appears when Trackator's enhanced analysis phases (Storage, Coupling, Sync, Evidence Validator) are available.

**Storage Dependency Evidence (Phase 1):**
| Field | Value | Significance |
|------|-------|--------------|
| Target Variable | {var_name} | Value-bearing: {YES/NO} |
| Variable Type | {erc20-balance/collateral/lp-shares/...} | Holds user funds |
| Permissionless Writers | {N} | {CRITICAL if >0} |
| Contended (Race Condition) | {YES/NO} | {writer_count} writers |
| Shared-State Risk Score | {X.X} | {HIGH if >0.7} |

**State Coupling Evidence (Phase 2):**
| Field | Value | Significance |
|------|-------|--------------|
| Atomicity Violation | {YES/NO} | Can functions be called separately? |
| Coupling Strength | {STRONG/MEDIUM/WEAK} | Exploitable coupling exists |
| Hidden Coupling Type | {transient/conditional/timestamp-dependent/null} | Undocumented dependency |
| Invariant Impact | {invariants_affected} | Cascade risk if exploited |

**Sync Analyzer Evidence (Phase 3):**
| Field | Value | Significance |
|------|-------|--------------|
| Desync Risk Type | {stale-price/stale-approval/state-drift/race-window/null} | Timing/state issue |
| Desync Severity | {critical/high/medium/low} | Risk level |
| Stale Window | {X}ms | Time available for exploitation |
| Unverified Assumptions | {N} | Assumptions without verifiers |

**Evidence Validator Classification (Phase 4):**
| Field | Value |
|------|-------|
| 6-Class Category | {confirmed-vulnerability/potential/false-positive/by-design/informational/cannot-determine} |
| Confidence Score | {X}% (0-100) |
| 9-Criteria Met | {X}/9 |
| Disproof Attempted | {YES/NO} |
| Pre-Classified As | {class_from_trackator} |

#### Kill Chain (Attack Steps)

| Step | Action | Function | Target | Details |
|------|--------|----------|--------|---------|
| 1 | {e.g., "Flash loan $50M"} | {DEX.swap()} | {Pool address} | {Move price X%} |
| 2 | {e.g., "Call vulnerable function"} | {Target.func()} | {Contract} | {With manipulated state} |
| 3 | {e.g., "Extract profit"} | {Withdraw/Transfer} | {Attacker} | {Capture value} |
| N | {e.g., "Repay flash loan"} | {Flash.repay()} | {Provider} | {+ fee} |

**Total Profit Estimation:** ${amount} (after gas/fees)

#### Execution Trace Summary

{2-3 sentence summary proving full A→B→C→end trace was completed:
- Entry point: {function}
- Call chain: A → B → C → ... → return
- Why vulnerability survives to end of execution}

#### Fork Test Proof

| Field | Value |
|-------|-------|
| **TX Hash** | `0x{hash}` (verifiable on Etherscan) |
| **Fork Block** | #{block_number} |
| **Gas Used** | {gas} |
| **Attacker Address** | `0x{address}` |
| **Profit Achieved** | {ETH/USD amount} |
| **Iterations to Confirm** | {N} |

**Trackator Visualization Summary:**
- State diff shows attacker balance: {before} → {after}
- Alerts fired during exploit: {list}
- Oracle deviation (if applicable): {X}%
- Invariants broken: {list}

#### Economic Assessment

| Metric | Value | Notes |
|--------|-------|-------|
| Capital Required | ${amount} or Flash loan | {Source} |
| Gas Cost (Est.) | {ETH amount} | At current gas prices |
| Net Profit | ${amount} | After all costs |
| Feasibility | HIGH / MEDIUM / LOW | {Reasoning} |
| Repeatable? | YES / NO / LIMITED | {Why?} |

*Note: Economic assessment INFORMS decision, never blocks reporting.*

#### Recommendation

**Immediate Mitigation:**
{What should be done RIGHT NOW to protect users}

**Recommended Fix:**
```solidity
// Show corrected code pattern
function fixed() external {
    // 1. Checks first
    // 2. Effects (state updates)
    // 3. Interactions (external calls) last
    // Or: Add nonReentrant modifier
    // Or: Add proper access control
}
```

**Long-term Considerations:**
{Any architectural improvements that would prevent this class of bug}
```

---

### 4. Probable Finding Template

```markdown
### Probable Finding #{ID}: {TITLE}

**Severity:** 🟠 HIGH / 🟡 MEDIUM  
**Status:** ⚠️ PROBABLE  
**Confidence Score:** {X}%  
**Caveat:** {Why this isn't fully confirmed}

---

#### Description

{Same as finding template but note why confidence is lower}

#### Evidence Summary

{What evidence supports this finding, what's missing}

#### Why Not CONFIRMED?

{Specific reason: couldn't replicate on fork / missing precondition / requires unlikely state / etc.}

#### Recommended Next Steps

1. {Step 1 to confirm or rule out}
2. {Step 2...}

---
```

---

### 5. Lead Template

```markdown
### Lead #{ID}: {INTERESTING_PATTERN}

**Category:** {bug_class}  
**Interest Reason:** {Why this is worth manual review}

---

#### Observation

{What pattern looks interesting but lacks full evidence}

#### Potential Attack Vector (Speculative)

{If this were exploitable, how might it work?}

#### What Would Need to Be Verified

- [ ] {Condition 1}
- [ ] {Condition 2}
- [ ] {Condition 3}

#### Suggested Manual Review Approach

{How a human auditor should investigate this lead}
```

---

### 6. Appendix Templates

#### Appendix A: Discarded Hypotheses Summary

```markdown
## Appendix A: Discarded Hypotheses Summary

### Discard Reason Distribution

| Reason | Count | Percentage |
|--------|-------|------------|
| Operational Error (trusted role action) | {N} | {X}% |
| Design Choice (intentional architecture) | {N} | {X}% |
| Unreachable (proven by execution trace) | {N} | {X}% |
| Unrealistic State (fuzz artifact) | {N} | {X}% |
| False Positive (intent filter caught it) | {N} | {X}% |

### Notable Discards (Learning Examples)

| Original Alert | Discard Reason | Why It Looked Interesting |
|----------------|---------------|--------------------------|
| {ALERT_X} | Operational Error | {Explanation} |
| {ALERT_Y} | Design Choice | {Explanation} |
| {ALERT_Z} | Unreachable Trace | {Explanation} |
```

#### Appendix B: Trackator Context

```markdown
## Appendix B: Trackator Context

### Protocol Classification
- **Type:** {lending/dex/vault/staking/dao/...}
- **Components Analyzed:** {N}

### Threat Model Summary
- **Assets at Risk:** {N} assets totaling ~${TVL}
- **Entry Points Identified:** {N} ({public}/{role-based}/{internal})
- **Trust Assumptions Documented:** {N}
- **Attack Vectors Mapped:** {N}

### Invariant Coverage
| Category | Count Checked | Violations Found |
|----------|---------------|------------------|
| Accounting | {N} | {N} |
| Bounds | {N} | {N} |
| Oracle | {N} | {N} |
| Permission | {N} | {N} |

### Alert Rules Evaluated
| Tier | Total Alerts | Survived Phase 1 | Matched Pattern | Confirmed |
|------|-------------|------------------|-----------------|----------|
| Tier 1 (Static) | {N} | {N} | {N} | {N} |
| Tier 2 (Enriched) | {N} | {N} | {N} | {N} |
```

#### Appendix C: Trackator Multi-Phase Evidence (v2.0)  <!-- NEW -->

```markdown
## Appendix C: Trackator Multi-Phase Evidence (v2.0)

> **Note:** This appendix appears when Trackator's enhanced analysis phases (Storage Dependency Analyzer, State Coupling Detector, Sync Analyzer, Evidence Validator) are available.

### C.1 Enhanced Data Availability Summary

| Data Layer | File Source | Available | Records Count |
|------------|-------------|-----------|---------------|
| Storage Dependency Analyzer | trackator-storage.json | {YES/NO} | {N} variables mapped |
| State Coupling Detector | trackator-coupling.json | {YES/NO} | {N}×{N} matrix entries |
| Sync Analyzer | trackator-sync.json | {YES/NO} | {N} desync risks identified |
| Evidence Validator | trackator-evidence.json | {YES/NO} | {N} findings classified |

### C.2 Storage Dependency Evidence Summary

**Value-Bearing Variables Identified:**
| Variable | Type | Location | Permissionless Writers | Risk Level |
|----------|------|----------|----------------------|------------|
| {_varName} | {erc20-balance/collateral/lp-shares} | {Contract.var} | {N} (CRITICAL if >0) | {CRITICAL/HIGH/MEDIUM} |

**Contended Variables (Race Condition Candidates):**
| Variable | Writer Count | Permissionless Writers | Exploitable? |
|----------|-------------|----------------------|-------------|
| {_varName} | {N} | {N} | {YES/NO} |

**Shared-State Matrix (High-Risk Entries):**
| Entry Point | Shared Variables | Has Value-Bearing | Risk Score |
|-------------|-----------------|-------------------|------------|
| {func()} | {var1, var2, ...} | {YES/NO} | {X.XX} |

### C.3 State Coupling Evidence Summary

**Strong Couplings Exploitable:**
| Function Pair | Coupling Strength | Shared Variables | Both Accessible? | Attack Generated? |
|---------------|------------------|------------------|------------------|-------------------|
| {funcA ↔ funcB} | STRONG | {vars...} | {YES/NO} | {YES/NO} |

**Hidden Couplings Discovered:**
| Functions | Coupling Type | Strength | Exploitation Potential |
|----------|--------------|----------|---------------------|
| {funcA → funcB} | {transient/conditional/timestamp-dependent} | {STRONG/MEDIUM/WEAK} | {HIGH/MEDIUM/LOW} |

**Invariant Violation Chains Identified:**
| Invariant | Violator Function | Dependent Function | Chain Feasibility |
|-----------|-------------------|--------------------|--------------------|
| {invId} | {funcViolator} | {funcDependent} | {HIGH/MEDIUM/LOW} |

### C.4 Sync Analyzer Evidence Summary

**Critical Desynchronization Risks:**
| Risk ID | Risk Type | Severity | Producer | Consumer | Stale Window | Status |
|---------|-----------|----------|----------|----------|-------------|--------|
| {riskId} | {stale-price/stale-approval/state-drift/race-window} | {CRITICAL/HIGH/MEDIUM} | {funcProd} | {funcCons} | {X}ms | {EXPLOITED/MITIGATED/LEAD} |

**Assumption Dependency Graph Summary:**
| Metric | Count |
|--------|-------|
| Total assumptions tracked | {N} |
| Assumptions WITH verifiers | {N} |
| Assumptions WITHOUT verifiers (exploitable) | {N} |
| Critical unverified assumptions | {N} |

**Desynchronization Analysis Results:**
| Analysis Type | Findings | Highest Severity |
|---------------|----------|------------------|
| Stale data detections | {N} | {severity} |
| Drift analysis findings | {N} | {severity} |
| Missing verifiers | {N} | {severity} |
| Race windows identified | {N} | {severity} |

### C.5 Evidence Validator Classification Summary

**Six-Class Classification Distribution:**
| Class | Count | Percentage | Action Taken |
|-------|-------|------------|--------------|
| confirmed-vulnerability | {N} | {XX}% | Report as P0/P1 |
| potential-vulnerability | {N} | {XX}% | Report with caveats |
| false-positive | {N} | {XX}% | Discard with documentation |
| by-design | {N} | {XX}% | Note in methodology |
| informational | {N} | {XX}% | Appendix only |
| cannot-determine | {N} | {XX}% | Queue for manual review |

**Confidence Score Distribution:**
| Confidence Range | Count | Average Score |
|-----------------|-------|---------------|
| 90-100% (High Confidence) | {N} | {XX}% |
| 70-89% (Medium-High) | {N} | {XX}% |
| 50-69% (Medium) | {N} | {XX}% |
| 30-49% (Low-Medium) | {N} | {XX}% |
| 0-29% (Low) | {N} | {XX}% |

**Disproof Engine Results:**
| Metric | Value |
|--------|-------|
| Total disproof attempts | {N} |
| Successful disproofs (false positives caught) | {N} |
| Findings that survived disproof | {N} |
| Inconclusive disproofs | {N} |
| False positive rate from disproof | {XX}% |

### C.6 Cross-Phase Correlation Matrix

This matrix shows which findings were identified by multiple analysis phases (higher correlation = higher confidence):

| Finding ID | Storage Alert | Coupling Alert | Sync Risk | Evidence Class | Correlation Score |
|------------|--------------|----------------|-----------|----------------|-------------------|
| {FINDING_1} | ✅ | ✅ | ❌ | confirmed-vulnerability | HIGH (3/4 phases) |
| {FINDING_2} | ❌ | ✅ | ✅ | potential-vulnerability | MEDIUM (2/4 phases) |
| {FINDING_3} | ✅ | ❌ | ✅ | confirmed-vulnerability | MEDIUM (2/4 phases) |
```

#### Appendix D: Confidence Scoring & Classification (v2.0)  <!-- NEW -->

```markdown
## Appendix D: Confidence Scoring & Classification (v2.0)

### D.1 Nine-Criteria Reachability Proof Checklist

For each CONFIRMED or PROBABLE finding, the following 9 criteria are evaluated:

| # | Criterion | Weight | Description | Finding #{ID} |
|---|-----------|--------|-------------|--------------|
| 1 | Entry Point Accessible | 15% | Attacker can reach the vulnerable function | {SATISFIED/NOT-SATISIFIED/N/A} |
| 2 | No Auth Bypass Needed | 10% | No privilege escalation required | {SATISFIED/NOT-SATISIFIED/N/A} |
| 3 | State Achievable | 15% | Required preconditions can be met on mainnet | {SATISFIED/NOT-SATISIFIED/N/A} |
| 4 | No Revert on Path | 15% | Execution path won't revert under realistic conditions | {SATISFIED/NOT-SATISIFIED/N/A} |
| 5 | Gas Feasible | 10% | Attack fits within block gas limit | {SATISFIED/NOT-SATISIFIED/N/A} |
| 6 | No Prior Fix | 10% | Vulnerability hasn't been patched | {SATISFIED/NOT-SATISIFIED/N/A} |
| 7 | Not Duplicate | 10% | This is a unique finding, not a duplicate | {SATISFIED/NOT-SATISIFIED/N/A} |
| 8 | Economic Incentive | 10% | Attacker has financial motivation to exploit | {SATISFIED/NOT-SATISIFIED/N/A} |
| 9 | Technically Feasible | 5% | Exploit can be implemented with available tools | {SATISFIED/NOT-SATISIFIED/N/A} |

**Criteria Score:** {XX}/100 (Sum of weights for satisfied criteria)

### D.2 Confidence Score Components Breakdown

For each finding, confidence is calculated from multiple components:

| Component | Weight | This Finding | Notes |
|-----------|--------|--------------|-------|
| Pattern Match Strength | 20% | {XX}% | Historical exploit similarity |
| Code Coverage | 15% | {XX}% | How much attack surface is covered |
| Trace Completeness | 20% | {XX}% | Full A→B→C→end trace completed |
| Fuzz Validation | 15% | {XX}% | Echidna/Medusa reproduced issue |
| Fork Test Result | 25% | {XX}% | Confirmed on mainnet fork |
| Economic Feasibility | 5% | {XX}% | Profit exceeds cost (informative only) |

**Composite Confidence Score:** {XX}/100

### D.3 Classification Justification

**Finding #{ID}:** {TITLE}

**Assigned Class:** `{confirmed-vulnerability | potential-vulnerability | false-positive | by-design | informational | cannot-determine}`

**Justification:**
- Primary reason for classification: {reason}
- Key evidence supporting classification: {evidence}
- Counter-evidence considered: {counter-evidence}
- Why not classified as {alternative class}: {reason}

**Classification Criteria Met:**
| Criterion | Required for this Class | Met? | Evidence |
|-----------|------------------------|-----|----------|
| {criterion_name} | {YES/NO} | {YES/NO} | {reference} |

### D.4 Confidence Calibration Table

This table shows how confidence scores map to report status and recommended actions:

| Confidence Range | Report Status | Recommended Action | Review Requirement |
|-----------------|---------------|--------------------|--------------------|
| 85-100% | ✅ CONFIRMED | Include in report as P0/P1 | Optional human review |
| 70-84% | ⚠️ PROBABLE | Include with caveats as P2 | Human review recommended |
| 50-69% | 📋 LEAD | Appendix - expert review needed | Expert review required |
| 30-49% | ❓ INFORMATIONAL | Low priority - note only | Automated sufficient |
| 0-29% | 🔬 CANNOT DETERMINE | Insufficient evidence | Manual investigation needed |

### D.5 Disproof Engine Audit Trail

For findings that underwent disproof analysis:

**Finding:** #{ID} ({title})

**Disproof Attempts Made:**

| Attempt # | Type | Result | Evidence Found | Residual Risk |
|-----------|------|--------|----------------|--------------|
| 1 | Guard Code Search | {FOUND/NOT_FOUND} | {description} | {level} |
| 2 | Semantic Analysis | {DISPROVED/NOT_DISPROVED} | {description} | {level} |
| 3 | Historical Cross-Check | {MATCH/NO_MATCH} | {N} similar patterns | {level} |
| 4 | Invariant Consistency | {PROTECTING/NEUTRAL} | {N} invariants | {level} |

**Final Disproof Verdict:** {DISPROVED / NOT_DISPROVED / CANNOT_DETERMINE}

**Recommendation:** {Based on disproof result}
```

#### Appendix E: Methodology Notes & Limitations  <!-- RENAMED FROM C -->

```markdown
## Appendix E: Methodology Notes & Limitations

### What This Assessment Does Well
- {Strength 1: e.g., finding code-level bugs via pattern matching}
- {Strength 2: e.g., validating exploits against real mainnet state}

### Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| {Limitation 1} | {What it affects} | {How we addressed it} |
| {Limitation 2} | {What it affects} | {How we addressed it} |

### Known Gaps
- {Gap 1: e.g., cross-protocol interactions not analyzed}
- {Gap 2: e.g., economic attack simulations limited}

### Assumptions Made
1. {Assumption 1 about protocol behavior}
2. {Assumption 2 about market conditions}
3. {Assumption 3 about trusted role integrity}

### Future Work Recommendations
1. {Recommendation 1 for deeper analysis}
2. {Recommendation 2 for additional tooling}
```

#### Appendix F: Raw Data Index  <!-- RENAMED FROM D -->

```markdown
## Appendix F: Raw Data Index

### Generated Artifacts

| Artifact | Format | Location | Description |
|----------|--------|----------|-------------|
| hypotheses-initial.json | JSON | {path} | Phase 0 output |
| hypotheses-filtered.json | JSON | {path} | Phase 1 output |
| pattern-matches.json | JSON | {path} | Phase 2 output |
| creative-findings.json | JSON | {path} | Phase 3 output |
| fuzz-results.json | JSON | {path} | Phase 4 output (if run) |
| fork-test-results.json | JSON | {path} | Phase 5 output (if run) |

### Input Data

| Source | Version/Date | Path |
|--------|-------------|------|
| Trackator Init Output | {date} | {path} |
| Trackator Enrich Output | {date} | {path} |
| Exploits Library | {card_count} cards | {path} |
```

---

## JSON Output Schema

For machine consumption, report data is also exported as JSON:

```javascript
{
    "metadata": {
        "protocol": string,
        "assessmentDate": ISODateString,
        "trackatorVersion": string,
        "redteamVersion": "2.0.0",
        "phasesCompleted": number[],
        "pipelineStatus": "FULL" | "PARTIAL",
        // v2.0: Enhanced data availability
        "enhancedDataAvailable": {
            "storage": boolean,     // Trackator Phase 1
            "coupling": boolean,    // Trackator Phase 2
            "sync": boolean,        // Trackator Phase 3
            "evidence": boolean     // Trackator Phase 4 (Evidence Validator)
        }
    },

    "executiveSummary": {
        "totalHypotheses": number,
        "confirmedCount": number,
        "probableCount": number,
        "leadsCount": number,
        "discardedCount": number,
        "estimatedTPRate": number,  // 0-100
        "riskPosture": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
        // v2.0: Enhanced breakdown by source
        "v2Breakdown": {
            "storageBasedFindings": number,
            "couplingBasedFindings": number,
            "syncBasedFindings": number,
            "evidenceValidatedFindings": number
        }
    },

    "findings": [
        {
            "id": string,
            "title": string,
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "status": "CONFIRMED" | "PROBABLE",  // CANONICAL
            "category": string,
            "confidenceScore": number,  // 0-100

            "description": {
                "what": string,
                "impact": string,
                "whyNotOperationalError": string
            },

            "technicalDetails": {
                "contracts": [{ "name": string, "file": string, "lines": string }],
                "functions": [{ "name": string, "issue": string }],
                "rootCause": string,
                "codePattern": string  // Anonymized snippet
            },

            "trackatorEvidence": {
                "alertsTriggered": [{ "id": string, "relevance": string }],
                "invariantsViolated": [{ "id": string, "expression": string }],
                "stateDiff": [{ "variable": string, "before": any, "after": any }]
            },

            // v2.0: Multi-Phase Evidence from Trackator
            "v2Evidence": {
                "storageDependency": {
                    "targetVariable": string | null,
                    "isValueBearing": boolean,
                    "variableType": string | null,
                    "permissionlessWriterCount": number,
                    "isContended": boolean,
                    "sharedStateRiskScore": number | null
                },
                "stateCoupling": {
                    "hasAtomicityViolation": boolean,
                    "couplingStrength": "STRONG" | "MEDIUM" | "WEAK" | "NONE",
                    "hiddenCouplingType": string | null,
                    "invariantsImpacted": string[]
                },
                "syncAnalyzer": {
                    "desyncRiskType": string | null,
                    "desyncSeverity": string | null,
                    "staleWindowMs": number | null,
                    "unverifiedAssumptionCount": number
                },
                "evidenceValidator": {
                    "sixClassCategory": "confirmed-vulnerability" | "potential-vulnerability" | "false-positive" | "by-design" | "informational" | "cannot-determine",
                    "confidenceScore": number,  // 0-100
                    "nineCriteriaMet": number,  // 0-9
                    "disproofAttempted": boolean,
                    "preClassification": string | null
                }
            },

            "killChain": [
                { "step": number, "action": string, "function": string }
            ],

            "executionTrace": {
                "summary": string,
                "entryPoint": string,
                "callChain": string[],
                "completed": boolean
            },

            "forkTestProof": {
                "txHash": string,
                "forkBlock": number,
                "profit": string,
                "iterationsRequired": number
            } | null,  // Null if not fork-tested

            "economicAssessment": {
                "capitalRequired": string,
                "gasCost": string,
                "netProfit": string,
                "feasibility": "HIGH" | "MEDIUM" | "LOW"
            },

            "recommendation": {
                "immediate": string,
                "fix": string,
                "longTerm": string
            }
        }
    ],
    
    "probableFindings": [...],  // Same schema, status = "PROBABLE"
    
    "leads": [
        {
            "id": string,
            "title": string,
            "category": string,
            "observation": string,
            "potentialVector": string,
            "verificationChecklist": string[]
        }
    ],
    
    "appendix": {
        "discardedSummary": {
            "byReason": { "operational_error": number, "design_choice": number, ... },
            "notableExamples": [{ "alertId": string, "reason": string }]
        },
        
        "trackatorContext": {
            "protocolType": string,
            "componentsAnalyzed": number,
            "assetsAtRisk": number,
            "entryPoints": number,
            "trustAssumptions": number,
            "invariantsChecked": { "total": number, "violated": number }
        },
        
        "methodologyNotes": {
            "strengths": string[],
            "limitations": [{ "limitation": string, "impact": string }],
            "assumptions": string[],
            "futureWork": string[]
        }
    ],
    
    "rawDataIndex": {
        "artifacts": [{ "name": string, "format": string, "location": string }],
        "inputs": [{ "source": string, "version": string, "location": string }]
    }
}
```

---

## Quality Checklist

Before finalizing report, verify:

- [ ] All CONFIRMED findings have COMPLETE execution traces (A→B→C→end)
- [ ] No finding relies on "admin is malicious" scenario
- [ ] No finding relies on "key compromised" scenario
- [ ] All OPERATIONAL_ERROR discards properly documented in Appendix A
- [ ] All DESIGN_CHOICE notes included in methodology
- [ ] Fork test TX hashes are valid and verifiable format
- [ ] Economic assessments present but never used to block reporting
- [ ] Report clearly distinguishes CONFIRMED vs PROBABLE vs LEAD
- [ ] Trackator evidence cited for each finding (alerts, invariants, state diffs)
- [ ] Kill chains are technically accurate and complete
- [ ] Recommendations are actionable and specific
- [ ] Canonical verdict states used throughout (no lowercase variants)
- [ ] Both Markdown and JSON outputs generated
