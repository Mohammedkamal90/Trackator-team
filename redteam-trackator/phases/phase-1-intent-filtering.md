## Phase 1: INTENT FILTERING

### Objective
Kill false positives EARLY by comparing against intended behavior, design choices, and operational patterns.

### Plugin: Intended Behavior Plugin

**Purpose**: Determine if an alert points at intentional design rather than bug.

**Inputs**:
- Hypothesis list from Phase 0
- Trackator protocol context
- Protocol documentation (if available)

**Logic**:

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

**Trackator Field Mappings for Intent Filter**:

| Check | Trackator Fields Used |
|-------|----------------------|
| Trust assumption | `trustAssumptions[].category`, `trustAssumptions[].confidence` |
| Component responsibility | `components[].responsibility`, `components[].interfaces[].accessControl` |
| Operational error | `functions[].modifiers[]` (contains onlyRole/onlyOwner) |
| Exploitable design | `attackVectors[].prerequisite[]`, `entryPoints[].access` |

### Intent Filter Decision Matrix

| Alert Type | Has Access Control? | In Trust Assumptions? | Enables Attack Chain? | Verdict |
|------------|---------------------|------------------------|----------------------|---------|
| CEI violation | Yes (onlyRole) | No | No | `downgrade_to_info` |
| CEI violation | No | No | Yes | `keep` |
| Missing auth | N/A | N/A | Yes | `keep` (critical!) |
| Anomalous value change | Yes (admin) | Yes | No | `discard` (operational) |
| Oracle deviation | N/A | Yes (low conf) | Yes | `keep` |

### Phase 1 Output

Update hypotheses with filter results:

```javascript
hypothesis.status = 'FILTERED';  // or DISCARDED
hypothesis.intentFilterResult = {
    verdict: 'keep' | 'downgrade_to_info' | 'discard' | 'keep_with_note',
    reason: string,
    checkedAt: timestamp
};
```

Surviving hypotheses → Phase 2 input.

---

