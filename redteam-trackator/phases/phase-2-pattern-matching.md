## Phase 2: PATTERN MATCHING

### Objective
Cross-reference surviving hypotheses against historical exploit pattern cards to find matches and assess reachability.

### Plugin: Pattern Matcher Plugin

**Purpose**: Match current alerts against known exploit patterns from Exploits-class-library.

**Input**: Exploits-class-library directory structure

**Library Structure**:
```
Exploits-class-library/
├── card-index.csv                    # All cards with metadata
├── protocol-type-to-exploit-patterns.json  # Protocol type → applicable patterns
└── exploit-pattern-cards/
    ├── reentrancy-state-update-after-external-call.md
    ├── flash-loan-spot-price-manipulation-single-tx.md
    ├── missing-modifier-privileged-function.md
    └── ... (56 total pattern cards)
```

**Pattern Matching Algorithm**:

```javascript
async function patternMatch(hypothesis, context, exploitsLibPath) {
    const protocolType = context.protocolType;
    const alert = hypothesis.sourceAlert;
    
    // Step 1: Get applicable patterns for this protocol type
    const applicablePatterns = loadPatternsForProtocolType(protocolType, exploitsLibPath);
    
    const matches = [];
    
    for (const pattern of applicablePatterns) {
        const matchScore = calculatePatternMatch(alert, pattern);
        
        if (matchScore > THRESHOLD) {
            matches.push({
                patternSlug: pattern.slug,
                primaryBugClass: pattern.primary_bug_class,
                matchScore: matchScore,
                representativeLoss: pattern.representative_loss_usd,
                detectionHeuristic: pattern.detection_heuristic,
                preconditionChain: pattern.precondition_chain
            });
        }
    }
    
    return matches.length > 0 ? matches : null;
}
```

**Match Scoring Factors**:

| Factor | Weight | Trackator Mapping |
|--------|--------|-------------------|
| Bug class match (reentrancy ↔ CEI violation) | 30% | `alert.category` ↔ `pattern.primary_bug_class` |
| Protocol type match | 25% | `context.protocolType` ↔ `pattern.protocol_types` |
| Detection heuristic match | 25% | `alert.condition` ↔ `pattern.detection_checklist` |
| Severity alignment | 10% | `alert.severity` ↔ historical loss |
| Prerequisite satisfaction | 10% | `context.entryPoints` ↔ `pattern.prerequisites` |

### v2.0 ENHANCED: Additional Scoring Factors (Factors 6-9)

When Trackator's enhanced analysis phases are available, the Pattern Matcher applies **4 additional scoring factors** via `calculateMatchScore_v2()` (see `plugins/pattern-matcher.md`):

| Factor | Weight | Source Data | Description |
|--------|--------|-------------|-------------|
| **Factor 6: Storage Dependency Alignment** | +10% bonus | `context.storage` | Does pattern target value-bearing variables with permissionless writers? |
| **Factor 7: State Coupling Signal** | +10% bonus | `context.coupling` | Does pattern exploit strong couplings between accessible functions? |
| **Factor 8: Synchronization Risk** | +10% bonus | `context.sync` | Is this a timing-based attack supported by desync analysis? |
| **Factor 9: Evidence Validator Pre-Classification** | adjusts confidence | `context.evidence` | Has this finding been pre-validated as confirmed/FP? |

**Maximum possible score with v2.0 bonuses**: 1.0 (base) + 0.35 (bonuses) = **1.35 (capped at 1.0)**

**Key v2.0 scoring functions**:
- `checkStorageAlignment(alert, pattern, storage)` → Returns 0-1 storage alignment score
- `checkCouplingSignal(alert, pattern, coupling)` → Returns 0-1 coupling signal score  
- `checkSyncRisk(alert, pattern, sync)` → Returns 0-1 sync risk score
- `checkPreClassification(alert, evidence)` → Returns {class, criteriaMet} for adjustment

### Example: Reentrancy Pattern Match

**Trackator Alert**:
```json
{
  "id": "ALERT_1",
  "name": "CEI Pattern Violation - Potential Reentrancy",
  "category": "reentrancy",
  "condition": { "type": "pattern", "field": "ceiPattern", "operator": "eq", "value": "violated" },
  "severity": "critical"
}
```

**Matching Exploit Card**: `reentrancy-state-update-after-external-call.md`

**Detection Heuristic from Card**:
> A function performs `.call{value: x}("")`, `.transfer()`, ERC20 transfer to externally-supplied address, and ONLY AFTER writes to balance/debt/share storage. Function lacks `nonReentrant` modifier.

**Match Result**:
```javascript
{
    patternSlug: 'reentrancy-state-update-after-external-call',
    primaryBugClass: 'reentrancy',
    matchScore: 0.92,  // High match!
    representativeLoss: 4750000,  // $4.75M from DeltaPrime
    detectionHeuristic: { signature: "...", grepPatterns: [...], checklist: [...] },
    preconditionChain: [
        "External call before state update",
        "No reentrancy guard OR wrong scope",
        "Attacker-controlled callback target",
        "Re-entry reads stale state"
    ]
}
```

### Plugin: Reachability Check (BLOCK GATE #1)

**Purpose**: Verify if matched pattern is actually reachable by attacker.

**IMPORTANT**: This is a **BLOCK GATE**, not kill gate!

```javascript
function reachabilityCheck(hypothesis, patternMatch, context) {
    const preconditions = patternMatch.preconditionChain;
    const satisfied = [];
    const unsatisfied = [];
    const unknown = [];
    
    for (const precondition of preconditions) {
        const result = checkPrecondition(precondition, context);
        
        if (result.satisfied) {
            satisfied.push(precondition);
        } else if (result.unsatisfied === false) {
            unsatisfied.push(precondition);  // Proven unreachable
        } else {
            unknown.push(precondition);  // Needs further testing
        }
    }
    
    // BLOCK GATE LOGIC: Don't kill, just grade
    if (unsatisfied.length > 0 && unknown.length === 0) {
        return {
            verdict: 'dead',
            reason: `Unsatisfied preconditions: ${unsatisfied.join(', ')}`,
            satisfiedPreconditions: satisfied,
            unsatisfiedPreconditions: unsatisfied
        };
    }
    
    if (satisfied.length === preconditions.length) {
        return {
            verdict: 'confirmed_pattern',
            reason: 'All preconditions satisfied',
            satisfiedPreconditions: satisfied,
            confidence: 'high'
        };
    }
    
    // Some unknowns → save for PoC
    return {
        verdict: unknown.length > satisfied.length ? 'lead' : 'probable',
        reason: `${satisfied.length}/${preconditions.length} satisfied, ${unknown.length} need testing`,
        satisfiedPreconditions: satisfied,
        unknownPreconditions: unknown,
        saveForPoC: true  // BLOCK GATE: Save, don't kill!
    };
}
```

**Reachability Checks Using Trackator Data**:

| Precondition Type | Trackator Fields to Check |
|-------------------|----------------------------|
| External call exists | `functions[].body.hasExternalCall === true` |
| No reentrancy guard | `functions[].modifiers[]` does NOT include `nonReentrant` |
| Attacker-controlled target | `functions[].parameters[]` includes address type, OR calls `msg.sender` |
| Public entry point | `entryPoints[].access === 'anyone'` |
| Value at risk | `assetsAtRisk[]` includes target asset |

### Phase 2 Output

```javascript
hypothesis.status = 'MATCHED';  // or DEAD if proven unreachable
hypothesis.patternMatches = [/* array of matches */];
hypothesis.reachabilityResult = {
    verdict: 'confirmed_pattern' | 'probable' | 'lead' | 'dead',
    preconditions: {/* satisfied/unsatisfied/unknown */},
    saveForPoC: boolean
};
```

### Plugin: Attack Chain Composer (NEW - v2.0 Upgrade)

**Purpose**: Compose individual pattern matches into coherent multi-step attack chains with **mandatory Execution Path Gate** validation.

**Phase**: 2b (Pattern Matching → Chain Composition)

**Core Philosophy**: *"A fast false positive wastes everyone's time. A slow true positive saves the protocol."*

**Input**: Pattern Matcher output (individual matches)

**Output**: Composed attack chains (only those passing Execution Path Gate escalate to Phase 3)

**Key Files**:
- Plugin spec: `plugins/attack-chain-composer.md`
- Templates: `Exploits-class-library/attack-chain-templates.json`
- Field map: `Exploits-class-library/exploit-trackator-field-map.json`

**What It Does**:

1. **Collects viable patterns** from Pattern Matcher (score ≥ 0.6)
2. **Finds chainable pairs** where pattern A's output enables pattern B's precondition
3. **Builds attack chains** (2-5 steps) with full execution tracing
4. **Runs Execution Path Gate** (4 mandatory checks before escalation)
5. **Classifies chains** against known archetypes from historical incidents

**The Execution Path Gate (MANDATORY)**:

Before ANY chain can escalate to Phase 3, ALL 4 gates must pass:

| Gate | Check | Failure Means |
|------|-------|---------------|
| **Precondition Trace** | Every precondition has verified execution path | Can't prove how attacker reaches vulnerability |
| **State Change Verification** | All state changes tracked or manually verified | Untracked state = unverified claim |
| **Attacker Control** | Attacker-controlled inputs identified and traceable | No clear attack vector |
| **No Conflicting Assumptions** | No internal contradictions in chain logic | Chain is self-inconsistent |

```javascript
// Gate result structure
{
    canEscalate: true/false,       // ALL gates must pass
    maxAllowedStatus: 'PROBABLE' | 'LEAD',  // Status ceiling if blocked
    gateResults: [...],           // Individual gate results
    blockedBy: [...]              // Names of failing gates (empty if all pass)
}
```

**Known Chain Archetypes** (from `attack-chain-templates.json`):

| Archetype | Steps | Execution | Historical Loss Range |
|-----------|-------|-----------|---------------------|
| Flash Loan Price Manipulation | 3 | Single TX | $50K - $5M |
| Reentrancy Drain | 3 | Single TX | $100K - $150M |
| Access Control Takeover | 3 | 1-3 TX | $50K - $150M |
| Oracle/Governance Manipulation | 3 | Multi-TX (hours) | $500K - $150M |
| Cross-Contract Coupling | 3 | 1-2 TX (close timing) | $10K - $5M |

**Chain Composition Algorithm**:

```
Pattern Matches → Find Chainable Pairs → Build Chains → Trace Execution → Run Gate → Output Validated Chains
```

See `plugins/attack-chain-composer.md` for complete algorithm specification.

**Integration Point**:

```
Phase 2 Pipeline (Enhanced):
┌──────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│ Pattern Matcher   │────▶│ Attack Chain         │────▶│ Execution Path   │
│ (finds matches)   │     │ Composer (composes)  │     │ Gate (validates) │
└──────────────────┘     └──────────────────────┘     └────────┬─────────┘
                                                                  │
                                                    Only PASSING chains ▼
                                                         Phase 3: Hacker
```

### Phase 2 Output (Enhanced)

```javascript
hypothesis.status = 'MATCHED';  // or DEAD if proven unreachable
hypothesis.patternMatches = [/* array of matches */];
hypothesis.reachabilityResult = {
    verdict: 'confirmed_pattern' | 'probable' | 'lead' | 'dead',
    preconditions: {/* satisfied/unsatisfied/unknown */},
    saveForPoC: boolean
};
// NEW: Attack chain composition results
hypothesis.attackChains = [/* array of composed chains from attack-chain-composer.md */];
hypothesis.chainCompositionResult = {
    totalChainsComposed: N,
    chainsPassingGate: M,  // Only these escalate to Phase 3
    chainsBlockedByGate: K,  // Saved for analysis, not escalating
    topChainArchetype: string
};
```

---

