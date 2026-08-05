# Phase 1: INTENT FILTERING

> **Part of**: [RedTeam Trackator SKILL.md](../SKILL.md) | **Phase**: 1 of 6
> **Previous**: [Phase 0 - Ingestion](phase-0-ingestion.md) | **Next**: [Phase 2 - Pattern Matching](phase-2-pattern-matching.md)

---

## Objective

Kill false positives EARLY by comparing against intended behavior, design choices, and operational patterns.

---

## Plugin: Intended Behavior Plugin

**Purpose**: Determine if an alert points at intentional design rather than bug.

> 📖 **Full plugin documentation**: See [`plugins/intended-behavior.md`](../plugins/intended-behavior.md) for complete implementation details, edge cases, and examples.

### Inputs

| Input | Source | Description |
|-------|--------|-------------|
| Hypothesis list | Phase 0 output | List of hypotheses to evaluate |
| Trackator protocol context | Protocol file | Full protocol structure with components, functions, trust assumptions |
| Protocol documentation | External docs | Design docs, README, audits (if available) |

### Logic

```javascript
function intentFilter(hypothesis, context) {
    const alert = hypothesis.sourceAlert;
    
    // CHECK 1: Is this a known trust assumption?
    if (isTrustAssumptionViolation(alert, context.trustAssumptions)) {
        const assumption = findMatchingAssumption(alert, context.trustAssumptions);
        
        // If low confidence assumption AND enables attack chain → keep
        if (assumption.confidence === 'low' && enablesAttackChain(alert, context)) {
            return { verdict: 'keep', reason: 'Low-confidence assumption, attack-enabling' };
        }
        
        // Otherwise downgrade to info
        return { verdict: 'downgrade_to_info', reason: 'Known trust assumption' };
    }
    
    // CHECK 2: Does component responsibility explain this?
    const component = findComponentForField(alert, context.components);
    if (component && isWorkingAsDesigned(alert, component)) {
        return { verdict: 'discard', reason: 'Working as designed per component responsibility' };
    }
    
    // CHECK 3: Is this about trusted role using authorized function?
    if (isOperationalError(alert, context)) {
        return { verdict: 'discard', reason: 'Operational error: trusted role action' };
    }
    
    // CHECK 4: CRITICAL - Even if "intended", is it exploitable?
    if (isExploitableDesignChoice(alert, context)) {
        return { verdict: 'keep_with_note', reason: 'Design choice but exploitable' };
    }
    
    return { verdict: 'keep', reason: 'Genuine anomaly' };
}
```

### Trackator Field Mappings for Intent Filter

| Check | Trackator Fields Used |
|-------|----------------------|
| Trust assumption | `trustAssumptions[].category`, `trustAssumptions[].confidence` |
| Component responsibility | `components[].responsibility`, `components[].interfaces[].accessControl` |
| Operational error | `functions[].modifiers[]` (contains onlyRole/onlyOwner) |
| Exploitable design | `attackVectors[].prerequisite[]`, `entryPoints[].access` |

---

## Intent Filter Decision Matrix

| Alert Type | Has Access Control? | In Trust Assumptions? | Enables Attack Chain? | Verdict |
|------------|---------------------|------------------------|----------------------|---------|
| CEI violation | Yes (onlyRole) | No | No | `downgrade_to_info` |
| CEI violation | No | No | Yes | `keep` |
| Missing auth | N/A | N/A | Yes | `keep` (critical!) |
| Anomalous value change | Yes (admin) | Yes | No | `discard` (operational) |
| Oracle deviation | N/A | Yes (low conf) | Yes | `keep` |

### Verdict Explanations

| Verdict | Meaning | Action |
|---------|---------|--------|
| `keep` | Genuine anomaly requiring investigation | Pass to Phase 2 |
| `downgrade_to_info` | Known pattern, low risk | Log as informational, exclude from attack surface |
| `discard` | False positive - working as designed | Remove from hypothesis list |
| `keep_with_note` | Intended but potentially exploitable | Flag for deeper analysis in later phases |

---

## Phase 1 Output

Update hypotheses with filter results:

```javascript
hypothesis.status = 'FILTERED';  // or DISCARDED
hypothesis.intentFilterResult = {
    verdict: 'keep' | 'downgrade_to_info' | 'discard' | 'keep_with_note',
    reason: string,
    checkedAt: timestamp
};
```

### Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 1: INTENT FILTERING                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Phase 0 Hypotheses                                            │
│         │                                                        │
│         ▼                                                        │
│   ┌─────────────┐                                               │
│   │ Trust Assump.│──Yes──▶ Low conf + Attack? ──Yes──▶ KEEP     │
│   │ Check       │                        │                      │
│   └─────────────┘                        ├──No──▶ DOWNGRADE     │
│         │ No                              │                      │
│         ▼                                ▼                       │
│   ┌─────────────┐     ┌──────────────────────────────┐          │
│   │ Component   │──Yes──▶ Working as designed? ──Yes──▶ DISCARD  │
│   │ Responsib.  │        │                              │          │
│   └─────────────┘        ├──No──▶ Continue              │          │
│         │ No             │                              │          │
│         ▼                ▼                              │          │
│   ┌─────────────┐     ┌──────────────────────────────┐ │          │
│   │ Operational │──Yes──▶ Trusted role action? ──Yes──▶ DISCARD  │
│   │ Error Check │        │                              │          │
│   └─────────────┘        ├──No──▶ Continue              │          │
│         │                │                              │          │
│         ▼                ▼                              │          │
│   ┌─────────────┐     ┌──────────────────────────────┐ │          │
│   │ Exploitable │──Yes──▶ Design choice? ──Yes──▶ KEEP+NOTE      │
│   │ Design      │        │                              │          │
│   └─────────────┘        ├──No──▶ KEEP (genuine)        │          │
│                          │                              │          │
│                          ▼                              │          │
│                   Surviving Hypotheses                  │          │
│                   → Phase 2 Input                       │          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Metrics to Track

| Metric | Description | Target |
|--------|-------------|--------|
| Filter rate | % of hypotheses discarded as false positives | 40-60% |
| Keep rate | % passing to Phase 2 | 40-60% |
| Downgrade rate | % downgraded to info | 10-20% |
| Keep-with-note rate | % flagged as exploitable design | 5-10% |

---

## Cross-References

| Reference | Link |
|-----------|------|
| Main SKILL.md | [`../SKILL.md`](../SKILL.md) |
| Phase 0 - Ingestion | [`phase-0-ingestion.md`](phase-0-ingestion.md) |
| Phase 2 - Pattern Matching | [`phase-2-pattern-matching.md`](phase-2-pattern-matching.md) |
| Intended Behavior Plugin (full) | [`../plugins/intended-behavior.md`](../plugins/intended-behavior.md) |
| Phase Summary | [`phase-summary.md`](phase-summary.md) |

---

*This file is auto-extracted from RedTeam Trackator SKILL.md - Phase 1 of 6*
