# Redteam-Trackator Skill Reference

## Quick Start

```
redteam-trackator --trackator-output /path/to/trackator-output \
                  --protocol "MyProtocol" \
                  --exploits-library /path/to/Exploits-class-library \
                  --output ./assessment
```

## File Structure

```
skills/redteam-trackator/
├── SKILL.md                          # Main skill definition (v2.0 COMPLETE pipeline)
├── README.md                         # This file
├── agents/
│   ├── hacker-agent.md               # Creative Hacker agent spec (v2.0 ENHANCED)
│   └── verifier-agent.md             # Verifier agent spec (v2.0 ENHANCED)
├── plugins/
│   ├── intended-behavior.md          # Phase 1: Intent filtering plugin
│   ├── pattern-matcher.md            # Phase 2: Historical exploit matching
│   ├── reachability.md               # Block gate plugin (all phases)
│   ├── reverse-engineering.md        # Phase 3: Value flow tracing (v2.0 ENHANCED)
│   ├── assumption-breaker.md         # Phase 3: Trust assumption testing (v2.0 ENHANCED)
│   └── fork-test.md                  # Phase 5: Mainnet fork validation
├── templates/
│   └── report-template.md            # Report output format
└── references/
    └── (external dependencies)
        ├── ../fizz/                   # Fuzz skill (optional, for Phase 4)
        └── /path/to/Exploits-class-library/  # Exploit patterns (optional, for Phase 2)
```

## Dependencies

### Required

| Dependency | Version | Purpose |
|-----------|---------|---------|
| Trackator | Any | Static/runtime analysis input |
| Foundry | Latest | Fork testing (Phase 5) |
| Node.js | 18+ | Script execution |

### Recommended (but optional)

| Dependency | Purpose |
|-----------|---------|
| Fizz skill | Echidna/Medusa fuzz integration (Phase 4) |
| Exploits-class-library | Historical pattern matching (Phase 2) |

## Pipeline Phases Summary

| Phase | Name | Agent Owner | Key Output | Plugin(s) Used |
|-------|------|-------------|------------|----------------|
| 0 | Ingestion | System | Hypothesis list from alerts | — |
| 1 | Intent Filtering | System + Verifier | Filtered hypotheses | intended-behavior.md |
| 2 | Pattern Matching | Hacker → Verifier | Pattern matches + reachability | pattern-matcher.md, reachability.md |
| 3 | Creative Attack | Hacker → Verifier | New attack ideas + traces | reverse-engineering.md, assumption-breaker.md, **state-coupling (v2.0)**, reachability.md |
| 4 | Fuzzing | Hacker → Verifier | Mechanically-validated findings | Fizz skill (external), **disproof-engine (v2.0)** |
| 5 | Fork Testing | Hacker → Verifier | Mainnet-confirmed exploits | fork-test.md, reachability.md |
| 6 | Reporting | System | Final assessment report | report-template.md |

### v2.0 Enhanced Data Layers (from Trackator)

| Trackator Phase | RedTeam Integration | Key Capabilities |
|---------------|-------------------|----------------|
| **Storage Dependency Analyzer** | Phase 3 (Reverse Eng.), Phase 5 (Fork) | Variable writers map, value-bearing variables, shared-state matrix, race condition detection |
| **State Coupling Detector** | Phase 3 (NEW: Coupling Analysis) | Function dependency N×N matrix, hidden couplings, invariant→function mapping, top attack intersections |
| **Sync Analyzer** | Phase 3 (Assumption Breaker), Phase 5 | Assumption dependency graph, stale data detection, critical desync risks (TOCTOU, oracle, race windows) |
| **Evidence Validator** | Phase 2 (Classification), Phase 4 (Disproof) | 6-class classification system, 9-criteria reachability proof, disproof engine, confidence scoring |

## Key Rules Reference

### Rule 1: Full Execution Trace
- **Before** escalating to Verifier, trace A→B→C→end
- **No shortcuts**, no partial analysis
- Use `calls[]` array from Trackator init.json

### Rule 2: Trust Role Protection
- Admin/Keeper/Governance are **trusted**
- Don't attack "admin is evil" scenarios
- DO attack privilege escalation paths TO roles

### Rule 3: Operational Error Exclusion
- Bad config ≠ Bad code
- Trusted role using authorized function = operational
- Code flaw on valid input = bug (even for admin)

### Rule 4: Block Gate Paradigm
- **SAVE** for PoC, don't KILL
- Only `DEAD` if proven impossible after thorough test
- Grade confidence, don't give binary pass/fail

## Canonical Verdict States (from SKILL.md)

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

## Trackator Field Quick Reference

### For Phase 0 (Ingestion)

```javascript
// Init data structure
{
    contracts: [{
        name: string,
        functions: [{
            name: string,
            modifiers: string[],
            body: {
                hasExternalCall: boolean,
                hasRevert: boolean,
                hasLoop: boolean,
                hasTransfer: boolean,
                hasDelegateCall: boolean,
                ceiPattern: 'valid' | 'violated' | 'not-applicable'
            },
            calls: string[],
            stateVariablesRead: string[],
            stateVariablesWritten: string[],
            parameters: [{ name: string, type: string }]
        }],
        stateVariables: [{
            name: string,
            type: string,
            slot: number,
            visibility: string
        }]
    }],
    callGraph: { edges: [], nodes: [] }
}

// Enrich data structure  
{
    xray: {
        protocolType: string,  // lending, dex, vault, etc.
        threatModel: {
            assetsAtRisk: [{ type: string, name: string, location: string }],
            entryPoints: [{ name: string, contract: string, access: string, criticality: string }],
            trustAssumptions: [{ id: string, category: string, assumption: string, confidence: string }],
            attackVectors: [{ id: string, name: string, prerequisite: [] }],
            adversaryProfiles: [{ type: string, capabilities: [], goals: [] }]
        }
    },
    invariants: [{
        id: string,
        category: string,
        template: string,
        instance: string,
        severity: string,
        expression: string,
        relatedFunctions: [],
        relatedStateVars: []
    }],
    alertRules: [{
        id: string,
        name: string,
        category: string,
        severity: string,
        condition: { type: string, field: string, operator: string, value: any },
        tier: string  // tier1 or tier2
    }],
    components: [{
        name: string,
        type: string,  // core or peripheral
        responsibility: string,
        riskLevel: string,
        interfaces: [{
            name: string,
            accessControl: string,
            sideEffects: []
        }],
        stateOwned: []
    }],
    moneyFlows: [{
        id: string,
        name: string,
        steps: [],
        conditions: []
    }]
}
```

## Confidence Score Calculation

```javascript
confidence = (
    (patternMatch * 0.20) +
    (traceComplete * 0.20) +
    (fuzzValidation * 0.15) +
    (forkSuccess * 0.35) +
    (economicFeasibility * 0.10)
)
```

| Score Range | Tier | Action |
|------------|------|--------|
| ≥ 0.7 | CONFIRMED | Report as finding |
| 0.4 - 0.7 | PROBABLE | Report with caveats |
| 0.2 - 0.4 | LEAD | Appendix only |
| < 0.2 | DISCARDED | Don't report |

## Common Workflows

### Workflow 1: Standard Assessment

```
Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 → Phase 6
```

### Workflow 2: Fizz Integration (Recommended)

```
Phase 0 → Phase 1 → Phase 2 → Phase 3 → [Phase 4 with Fizz] → Phase 5 → Phase 6
```

### Workflow 3: Fast Track (No Fuzz, No Fork)

```
Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 6
# Result: Lower confidence findings, faster turnaround
```

### Workflow 4: Deep Dive (Extended Fork Iteration)

```
Phase 0 → ... → Phase 5 [with MAX_ITERATIONS=20] → Phase 6
# Result: Highest confidence, longest runtime
```

## Troubleshooting

### Issue: No Trackator Output

**Symptom**: `Missing required file: trackator-enrich.json`

**Solution**: 
1. Run Trackator on target protocol first
2. Ensure all JSON files are in specified directory
3. Check file permissions

### Issue: No Exploits Library

**Symptom**: `⚠️ No exploits library - skipping pattern matching`

**Solution**:
1. Download Exploits-class-library
2. Set `--exploits-library` path correctly
3. Continue without it (Phase 2 will be weaker)

### Issue: Fuzz Not Available

**Symptom**: `⚠️ Fizz skill not available - skipping fuzz phase`

**Solution**:
1. Install Fizz skill
2. Or continue without fuzzing (Phase 4 skipped)
3. Rely more heavily on fork testing

### Issue: Fork RPC Failure

**Symptom**: `❌ Fork RPC unavailable - skipping Phase 5`

**Solution**:
1. Check `MAINNET_RPC_URL` environment variable
2. Ensure RPC provider supports archive access
3. Or run without fork testing (lower confidence)

### Issue: Too Many False Positives

**Symptom**: Report filled with operational errors

**Solutions**:
1. Verify Phase 1 intent filtering is running
2. Check operational error exclusion is active
3. Review trust role protection rules

### Issue: Too Few Findings

**Symptom**: Everything discarded as DEAD

**Solutions**:
1. Check block gates aren't too aggressive
2. Verify reachability checks aren't killing prematurely
3. Review execution trace requirements (might be too strict)

## Integration Examples

### Example 1: Lending Protocol

```bash
redteam-trackator \
    --trackator-output ./trackator-output/falcon-protocol \
    --protocol "Falcon Lending" \
    --exploits-library ./Exploits-class-library \
    --output ./falcon-assessment
```

**Expected behavior**:
- Protocol type detected: `lending`
- Relevant patterns loaded: self-liquidation, oracle dependency, health factor bugs
- Focus areas: collateral valuation, liquidation logic, reward accounting

### Example 2: DEX Protocol

```bash
redteam-trackator \
    --trackator-output ./trackator-output/uniswap-fork \
    --protocol "MyDEX" \
    --output ./dex-assessment
```

**Expected behavior**:
- Protocol type detected: `dexes`
- Relevant patterns loaded: AMM manipulation, flash loan price, callback attacks
- Focus areas: swap pricing, LP tokens, fee calculation

### Example 3: Governance DAO

```bash
redteam-trackator \
    --trackator-output ./trackator-output/gov-dao \
    --protocol "GovernanceDAO" \
    --output ./gov-assessment
```

**Expected behavior**:
- Protocol type detected: `dao` (or governance)
- Note: Governance-specific patterns limited in library
- Focus areas: Timelock bypass, proposal execution, voting logic
- Extra care: Don't flag "governance can do X" as vulnerability

## Output Files

After successful run:

```
./redteam-output/
├── redteam-trackator-report.md      # Main report (human-readable)
├── redteam-trackator-report.json    # Machine-readable data
├── hypotheses-initial.json         # Phase 0 output
├── hypotheses-filtered.json       # Phase 1 output
├── pattern-matches.json           # Phase 2 output
├── creative-findings.json         # Phase 3 output
├── fuzz-results.json              # Phase 4 output (if run)
└── fork-test-results.json         # Phase 5 output (if run)
```

## Plugin Quick Reference

| Plugin File | Phase | Purpose | Key Feature |
|-------------|------|---------|-------------|
| `intended-behavior.md` | 1 | Kill FPs early | Distinguishes bugs from design choices |
| `pattern-matcher.md` | 2 | Historical matching | 56+ exploit pattern cards |
| `reachability.md` | 2-5 | Block gate validation | Saves findings instead of killing |
| `reverse-engineering.md` | 3 | Novel bug discovery | Traces value flows backwards |
| `assumption-breaker.md` | 3 | Assumption testing | Breaks external-attacker-breakable assumptions |
| `fork-test.md` | 5 | Mainnet validation | Iterative exploitation with visualization |
| `report-template.md` | 6 | Output formatting | Complete Markdown + JSON schema |

## Support & Contributing

For issues, questions, or contributions:
- Check SKILL.md for detailed specifications (canonical rules, verdict states)
- Review agent specs for behavioral guidelines and I/O formats
- See plugin specs for implementation details
- All files use canonical verdict states from SKILL.md Rule 4
