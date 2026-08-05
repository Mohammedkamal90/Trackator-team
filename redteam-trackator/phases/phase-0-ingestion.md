# Phase 0: INGESTION

> **Part of**: [RedTeam Trackator SKILL.md](../SKILL.md) | **Phase**: 0 of 6
> **Next**: [Phase 1 - Intent Filtering](phase-1-intent-filtering.md) | **Summary**: [phase-summary.md](phase-summary.md)

---

## Objective

Read and parse all Trackator output files to build initial hypothesis list.

## Inputs Required

| File | Description |
|------|-------------|
| `trackator-init.json` | Contract structure, functions, state variables, call graph |
| `trackator-enrich.json` | Threat model, invariants, attack vectors, alert rules, money flows |
| `trackator-analyze.json` *(optional)* | Runtime alerts if Foundry traces available |

---

## Steps

### Step 0.1: Validate Trackator Output

Ensure required files exist and contain valid structure:

```javascript
function validateTrackatorOutput(outputDir) {
    const requiredFiles = ['trackator-init.json', 'trackator-enrich.json'];
    for (const file of requiredFiles) {
        if (!existsSync(`${outputDir}/${file}`)) {
            throw new Error(`Missing required file: ${file}`);
        }
    }
    
    const initData = readJson(`${outputDir}/trackator-init.json`);
    const enrichData = readJson(`${outputDir}/trackator-enrich.json`);
    
    // Validate core structure exists
    if (!initData.contracts?.length) throw new Error('No contracts found');
    if (!enrichData.xray?.protocolType) throw new Error('Missing protocol type');
    
    return { initData, enrichData };
}
```

### Step 0.2: Build Priority-Ranked Hypothesis List

Extract alerts from Trackator and rank by severity, condition type, and source:

```javascript
function buildHypothesisList(enrichData) {
    const hypotheses = (enrichData.alertRules || []).map(alert => ({
        id: `HYP_${alert.id}`,
        sourceAlert: alert,
        priorityScore: calculatePriorityScore(alert),
        status: 'PENDING',  // Lifecycle: PENDING → FILTERED → MATCHED → TESTED → CONFIRMED/DEAD
        phase: 0,
        evidence: [],
        executionTrace: null,
        forkResult: null,
        createdAt: Date.now()
    }));
    
    return hypotheses.sort((a, b) => b.priorityScore - a.priorityScore);
}

// Priority scoring weights:
// - Severity: critical=30, high=20, medium=10
// - Condition type: pattern=20, presence/absence=15, threshold=10
// - Source: runtime=15, tier1=10
```

### Step 0.3: Extract Protocol Context

Build context object for downstream phases:

```javascript
function extractProtocolContext(initData, enrichData) {
    return {
        protocolType: enrichData.xray.protocolType,
        contracts: initData.contracts,
        assetsAtRisk: enrichData.xray.threatModel?.assetsAtRisk || [],
        entryPoints: enrichData.xray.threatModel?.entryPoints || [],
        invariants: enrichData.invariants || [],
        trustAssumptions: enrichData.xray.threatModel?.trustAssumptions || [],
        attackVectors: enrichData.xray.threatModel?.attackVectors || [],
        adversaryProfiles: enrichData.xray.threatModel?.adversaryProfiles || [],
        alertRules: enrichData.alertRules || [],
        components: enrichData.breakdown?.components || [],
        moneyFlows: enrichData.moneyFlows || [],
        ...extractEnhancedContext(outputDir)  // v2.0 enhanced data
    };
}
```

### Step 0.4: Extract Enhanced Trackator Data (v2.0 NEW)

Load optional enhanced Trackator outputs when available:

```javascript
function extractEnhancedContext(outputDir) {
    const enhanced = { hasEnhancedData: false, storage: null, coupling: null, sync: null, evidence: null };
    const enhancedFiles = [
        ['trackator-storage.json', 'storage', 'Storage Dependency Analyzer'],
        ['trackator-coupling.json', 'coupling', 'State Coupling Detector'],
        ['trackator-sync.json', 'sync', 'Sync Analyzer'],
        ['trackator-evidence.json', 'evidence', 'Evidence Validator']
    ];
    
    for (const [file, key, label] of enhancedFiles) {
        if (existsSync(`${outputDir}/${file}`)) {
            enhanced[key] = readJson(`${outputDir}/${file}`);
            enhanced.hasEnhancedData = true;
            console.log(`✅ Loaded ${label} data`);
        }
    }
    return enhanced;
}
```

---

## Enhanced Context Structure (v2.0)

When enhanced Trackator data is available, the context object includes additional fields.

> **Full data structure**: See [references/trackator-fields.md](../references/trackator-fields.md) for complete field definitions.

### Key Enhanced Fields Summary

| Module | Key Fields | Purpose |
|--------|------------|---------|
| **Storage** | `variableWriters`, `contendedVariables`, `valueBearingVariables`, `sharedStateMatrix` | Identify race conditions & value-bearing state |
| **Coupling** | `functionDependencyMatrix`, `hiddenCouplings`, `invariantFunctionMap`, `topIntersections` | Find hidden state dependencies between functions |
| **Sync** | `criticalDesyncRisks`, `syncRelationships`, `desynchronizationAnalysis` | Detect stale data & desync vulnerabilities |
| **Evidence** | `classificationRegistry`, `reachabilityAnalysis`, `confidenceAssessments` | Validate findings & assess exploitability |

### Critical Risk Types (Sync Analyzer)

```javascript
// criticalDesyncRisks.riskType enum values:
['stale-price', 'stale-approval', 'state-drift', 'missing-verifier', 'race-window']

// Evidence classification categories:
['confirmedVulnerability', 'potentialVulnerability', 'falsePositive', 
 'byDesign', 'informational', 'cannotDetermine']
```

---

## Phase 0 Output Artifacts

| Artifact | Format | Description |
|----------|--------|-------------|
| `hypotheses-initial.json` | JSON | Priority-ranked hypothesis list from Trackator alerts |
| `protocol-context.json` | JSON | Extracted protocol context for downstream use |
| `enhanced-context.json` | JSON | v2.0: Enhanced Trackator data (storage/coupling/sync/evidence) |

---

## Cross-References

| Direction | Link | Description |
|-----------|------|-------------|
| ↑ Parent | [SKILL.md](../SKILL.md) | Main skill document |
| → Next | [phase-summary.md](phase-summary.md) | Phase index & navigation |
| ↗ Reference | [references/trackator-fields.md](../references/trackator-fields.md) | Complete field definitions |

---

*Last extracted from SKILL.md (lines 245-564)*
