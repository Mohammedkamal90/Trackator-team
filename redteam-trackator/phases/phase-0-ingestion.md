## Phase 0: INGESTION

### Objective
Read and parse all Trackator output files to build initial hypothesis list.

### Inputs Required
- `trackator-init.json` — Contract structure, functions, state variables, call graph
- `trackator-enrich.json` — Threat model, invariants, attack vectors, alert rules, money flows
- `trackator-analyze.json` (optional) — Runtime alerts if Foundry traces available

### Steps

#### Step 0.1: Validate Trackator Output

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
    
    // Validate structure
    if (!initData.contracts || !initData.contracts.length) {
        throw new Error('No contracts found in init data');
    }
    if (!enrichData.xray || !enrichData.xray.protocolType) {
        throw new Error('Missing protocol type in enrich data');
    }
    
    return { initData, enrichData };
}
```

#### Step 0.2: Build Priority-Ranked Hypothesis List

Extract all alerts from Trackator and rank by priority:

```javascript
function buildHypothesisList(enrichData) {
    const hypotheses = [];
    
    for (const alert of enrichData.alertRules || []) {
        const score = calculatePriorityScore(alert);
        
        hypotheses.push({
            id: `HYP_${alert.id}`,
            sourceAlert: alert,
            priorityScore: score,
            status: 'PENDING',  // PENDING → FILTERED → MATCHED → TESTED → CONFIRMED/DEAD
            phase: 0,  // Which phase created/last-touched this
            evidence: [],
            executionTrace: null,
            forkResult: null,
            createdAt: Date.now()
        });
    }
    
    // Sort by priority score descending
    return hypotheses.sort((a, b) => b.priorityScore - a.priorityScore);
}

function calculatePriorityScore(alert) {
    let score = 0;
    
    // Severity weighting
    if (alert.severity === 'critical') score += 30;
    else if (alert.severity === 'high') score += 20;
    else if (alert.severity === 'medium') score += 10;
    
    // Condition type weighting (pattern = strong signal)
    if (alert.condition?.type === 'pattern') score += 20;
    else if (alert.condition?.type === 'presence') score += 15;
    else if (alert.condition?.type === 'absence') score += 15;
    else if (alert.condition?.type === 'threshold') score += 10;
    
    // Source weighting (runtime/static > inferred)
    if (alert.source === 'runtime') score += 15;
    else if (alert.tier === 'tier1') score += 10;
    
    return score;
}
```

#### Step 0.3: Extract Protocol Context

Build context object for downstream phases:

```javascript
function extractProtocolContext(initData, enrichData) {
    const baseContext = {
        protocolType: enrichData.xray.protocolType,  // lending, dex, vault, etc.
        contracts: initData.contracts,
        assetsAtRisk: enrichData.xray.threatModel?.assetsAtRisk || [],
        entryPoints: enrichData.xray.threatModel?.entryPoints || [],
        invariants: enrichData.invariants || [],
        trustAssumptions: enrichData.xray.threatModel?.trustAssumptions || [],
        attackVectors: enrichData.xray.threatModel?.attackVectors || [],
        adversaryProfiles: enrichData.xray.threatModel?.adversaryProfiles || [],
        alertRules: enrichData.alertRules || [],
        components: enrichData.breakdown?.components || [],
        moneyFlows: enrichData.moneyFlows || []
    };
    
    // v2.0: Try to load enhanced Trackator output
    return { ...baseContext, ...extractEnhancedContext() };
}
```

#### Step 0.4: Extract Enhanced Trackator Data (v2.0 NEW)

```javascript
function extractEnhancedContext(outputDir) {
    const enhanced = {
        hasEnhancedData: false,
        storage: null,
        coupling: null,
        sync: null,
        evidence: null
    };
    
    try {
        // Phase 1: Storage Dependency Analyzer
        // NOTE (integration fix): real trackator-storage.json nests these fields under
        // `storageWriteGraph`, not at top level, and has no `valueBearingVariables` array —
        // value-bearing-ness is a per-writer boolean (`isValueBearing`) that must be filtered.
        if (existsSync(`${outputDir}/trackator-storage.json`)) {
            enhanced.storage = readJson(`${outputDir}/trackator-storage.json`);
            enhanced.hasEnhancedData = true;
            const swg = enhanced.storage.storageWriteGraph || {};
            // variableWriters is exported as an array of {key, ...VariableWriterInfo}, not a Map.
            const valueBearingCount = (swg.variableWriters || [])
                .filter((v) => v.isValueBearing).length;
            console.log('✅ Loaded Storage Dependency Analyzer data');
            console.log(`   - ${(swg.variableWriters || []).length} variable writers mapped`);
            console.log(`   - ${swg.contendedVariables?.length || 0} contended variables`);
            console.log(`   - ${valueBearingCount} value-bearing variables`);
        }
        
        // Phase 2: State Coupling Detector
        // NOTE (integration fix): real key names are `variableClassification` (not
        // `storageVariableClassification`) and `topStateIntersections` (not `topIntersections`).
        // functionDependencyMatrix is {functions, dependencies, statistics, couplingClusters}
        // (not directly keyed/countable). hiddenCouplings is {couplings, summary}, not a
        // flat array.
        if (existsSync(`${outputDir}/trackator-coupling.json`)) {
            enhanced.coupling = readJson(`${outputDir}/trackator-coupling.json`);
            enhanced.hasEnhancedData = true;
            const fdm = enhanced.coupling.functionDependencyMatrix || {};
            console.log('✅ Loaded State Coupling Detector data');
            console.log(`   - ${fdm.functions?.length || 0} functions, ${fdm.dependencies?.length || 0} dependency edges`);
            console.log(`   - ${enhanced.coupling.hiddenCouplings?.couplings?.length || 0} hidden couplings found`);
        }
        
        // Phase 3: Sync Analyzer
        // NOTE (integration fix): real key is `topSyncRelationships.relationships`
        // (not a top-level `syncRelationships` array).
        if (existsSync(`${outputDir}/trackator-sync.json`)) {
            enhanced.sync = readJson(`${outputDir}/trackator-sync.json`);
            enhanced.hasEnhancedData = true;
            console.log('✅ Loaded Sync Analyzer data');
            console.log(`   - ${enhanced.sync.criticalDesyncRisks?.length || 0} critical desync risks`);
            console.log(`   - ${enhanced.sync.topSyncRelationships?.relationships?.length || 0} sync relationships mapped`);
        }
        
        // Phase 4: Evidence Validator
        // NOTE (integration fix): classificationRegistry is {entries[], statistics}, not
        // a set of per-class arrays — count findings via statistics/entries, not Object.keys.
        if (existsSync(`${outputDir}/trackator-evidence.json`)) {
            enhanced.evidence = readJson(`${outputDir}/trackator-evidence.json`);
            enhanced.hasEnhancedData = true;
            console.log('✅ Loaded Evidence Validator data');
            console.log(`   - Classification registry: ${enhanced.evidence.classificationRegistry?.entries?.length || 0} findings classified`);
            console.log(`   - ${enhanced.evidence.proofRequirementsList?.length || 0} findings with 9-criteria proof requirements`);
        }
        
    } catch (error) {
        console.warn('⚠️ Error loading enhanced Trackator data:', error.message);
        console.warn('   Continuing in v1.0 compatibility mode');
    }
    
    return enhanced;
}
```

### Enhanced Context Structure (v2.0)

When enhanced data is available, the context object includes:

```javascript
{
    // ... base fields from Step 0.3 ...
    
    // Storage Dependency Analyzer (Trackator Phase 1)
    // ACTUAL SHAPE (corrected — was previously documented flat, but trackator nests
    // these three under `storageWriteGraph`, and has no standalone `valueBearingVariables`
    // array; derive it by filtering `variableWriters` entries where `isValueBearing === true`):
    storage: {
        storageWriteGraph: {
            // exported as Array<{key, ...fields}> (NOT a Map) — key is the variable name
            variableWriters: Array<{
                key: string,
                writers: Array<{
                    function: string,
                    contract: string,
                    writeReasonCategory: string,  // 'direct-user-action', 'protocol-admin', ...
                    accessControlLevel: string,     // 'none', 'role-based', 'permissionless'
                    ceiPatternMatch: boolean
                }>,
                isValueBearing: boolean          // filter on this for "value-bearing" vars
            }>,
            multiVariableWriters: Array<{        // Functions touching multiple vars
                function: string,
                variablesWritten: string[],
                isComplexStateChange: boolean
            }>,
            // NOTE: exported key is `contendedVariables` (this spelling), even though the
            // internal TS field is named `contentedVariables` — export renames it.
            contendedVariables: Array<{         // Race condition candidates
                variable: string,
                writerCount: number,
                writers: Array<{ function, accessControlLevel }>
            }>
        },
        // ACTUAL SHAPE (corrected — object with cells nested two levels: entry-point row →
        // per-variable cell; not a flat array with riskScore, which doesn't exist per-cell):
        sharedStateMatrix: {
            entryPoints: Array<{ functionName: string, contract: string, ... }>,
            sharedVariables: Array<{ variableName: string, ... }>,
            cells: Array<{
                entryPoint: string,
                cells: Array<{
                    variable: string,
                    accessType: 'read' | 'write' | 'read-write' | 'none',
                    dependencyType: string[],
                    riskFactors: string[],       // use length>0 as an elevated-risk signal
                    ceiCompliant: boolean,
                    hasExternalCallBefore: boolean,
                    hasExternalCallAfter: boolean,
                    crossContractImpact?: string,
                    invariantImpacted?: string[]
                }>
            }>,
            riskSummary: object
        }
    },
    
    // State Coupling Detector (Trackator Phase 2)
    // ACTUAL SHAPE (corrected key names — trackator emits `variableClassification` and
    // `topStateIntersections`, not `storageVariableClassification` / `topIntersections`;
    // functionDependencyMatrix, hiddenCouplings, and invariantFunctionMap are also nested
    // objects, not the flat arrays/maps previously documented here):
    coupling: {
        functionDependencyMatrix: {
            functions: Array<{ id: string, ... }>,          // "Contract.functionName"
            dependencies: Array<{                             // key = "funcA→funcB"
                key: string,
                sourceFunction: string,
                targetFunction: string,
                dependencyType: 'write-read' | 'read-write' | 'write-write' | 'shared-state',
                sharedVariables: string[],
                couplingStrength: number,      // 0-100 (NOT 0-1 — no 'STRONG'/'MEDIUM' enum)
                isDirect: boolean,
                isCrossContract: boolean,
                description: string,
                riskFactors: string[]
            }>,
            statistics: object,
            couplingClusters: Array<object>
        },
        hiddenCouplings: {
            couplings: Array<{
                id: string,
                type: string,     // e.g. 'proxy-storage-conflict', 'delegatecall-context-leak', ...
                severity: 'critical' | 'high' | 'medium' | 'low',
                source: { contract: string, function?: string, variable?: string },
                target: { contract: string, function?: string, variable?: string },
                mechanism: string,
                sharedState?: string[],
                description: string,
                exploitationScenario?: string,
                recommendation: string,
                detectionConfidence: 'certain' | 'likely' | 'possible' | 'speculative'
            }>,
            summary: object
        },
        invariantFunctionMap: {
            mappings: Array<object>,        // NOT establishes/dependsOn/canViolate
            violationPaths: Array<object>,
            protectionGaps: Array<object>
        },
        variableClassification: {
            classifications: object,          // Map-like; not a bare Map<string,...>
            summary: object
        },
        topStateIntersections: {              // object, not a bare array
            intersections: Array<object>,
            rankingMethodology: string,
            generatedAt: string
        },
        hiddenAssumptions: {                  // HiddenAssumptionReport — also the source
            assumptions: Array<{...}>,          // Phase4 evidence-validator now reads from here
            summary: object
        }
    },
    
    // Sync Analyzer (Trackator Phase 3)
    sync: {
        assumptionDependencyGraph: {
            nodes: Array<object>,
            edges: Array<object>,
            // ACTUAL SHAPE (corrected — these are keyed by nodeId, and the fields are the
            // real ProducerInfo/ConsumerInfo/VerifierInfo shapes, not assumptionId-based):
            producers: Array<{
                nodeId: string,
                producerFunctions: Array<{ functionId: string, ... }>,
                productionMechanism: string,
                outputVariables: string[],
                establishedInvariants: string[]
            }>,
            consumers: Array<{
                nodeId: string,
                consumerFunctions: Array<{ functionId: string, ... }>,
                assumptionMade: string,
                validationPerformed: string,
                isBlindTrust: boolean,
                impactIfWrong: string
            }>,
            verifiers: Array<{
                nodeId: string,
                verifierFunctions: Array<{ functionId: string, ... }>,
                verificationMechanism: string,
                coverage: 'complete' | 'partial' | 'sampling' | 'none'
            }>,
            graphStatistics: object
        },
        desynchronizationAnalysis: {
            synchronizationGroups: Array<object>,
            desyncSources: Array<object>,
            detectedRisks: Array<object>,
            summary: object
        },
        criticalDesyncRisks: Array({
            riskType: 'stale-price' | 'stale-approval' | 'state-drift' | 'missing-verifier' | 'race-window',
            severity: 'critical' | 'high' | 'medium',
            impact: string,
            attackScenario: string,
            producerFunction: string,
            consumerFunction: string,
            staleWindowMs: number,
            mitigationSuggestion: string
        }),
        // ACTUAL SHAPE (corrected — real key is `topSyncRelationships.relationships`,
        // not a top-level `syncRelationships` array):
        topSyncRelationships: {
            relationships: Array({
                id: string,
                producer: string,
                consumer: string,
                verifier: string | null,
                stalenessWindow: number,
                exploitability: number,  // 0-100
                attackComplexity: 'easy' | 'medium' | 'hard'
            })
        }
    },
    
    // Evidence Validator (Trackator Phase 4)
    // ACTUAL SHAPE (corrected — was previously documented as camelCase per-class arrays;
    // real classificationRegistry is a single flat entries[] list using the kebab-case
    // 6-class FindingClassification vocabulary. reachabilityAnalysis and disproofEngine
    // were also documented wrong — see fixes below. proofRequirementsList was previously
    // missing from trackator's own export entirely — now fixed and included):
    evidence: {
        classificationRegistry: {
            entries: Array<{
                findingId: string,
                originalSource: 'phase1-storage' | 'phase2-coupling' | 'phase3-sync' | 'external' | 'manual',
                originalFindingId?: string,
                title: string,
                description: string,
                location: object,
                category: string,
                classification: 'proven-property' | 'potential-bug' | 'reachable-bug' |
                                 'false-positive' | 'by-design' | 'insufficient-evidence',
                confidence: number   // 0-100
            }>,
            statistics: object
        },
        reachabilityAnalysis: {              // object, NOT a bare array — go through .paths
            paths: Array<{
                pathId: string,
                findingId: string,
                entryPoint: {
                    function: string, contract: string, visibility: string,
                    accessControl: string, isPermissionless: boolean
                },
                callChain: Array<object>,
                statePrerequisites: Array<{ variable, requiredValue, canBeSatisfied }>,
                crossContractPrereqs: Array<{ targetContract, requiredState, canBeSatisfied }>,
                exploitationComplexity: 'trivial' | 'easy' | 'moderate' | 'difficult' | 'impossible',
                reachabilityReason: string
            }>,
            unreachableFindings: Array<{ findingId: string, reason: string }>,
            prerequisites: object,
            summary: object
        },
        disproofAnalysis: {                  // NOT `disproofEngine` — that key never existed
            disproofAttempts: Array<{
                attemptId: string, targetFindingId: string, strategy: string,
                executed: boolean, successful: boolean, evidenceFound: Array<object>,
                conclusion: string, timestamp: string
            }>,
            results: Array<{
                resultId: string, findingId: string,
                originalClassification: string, newClassification: string,
                disproofStrategy: string, disproofEvidence: Array<object>,
                reasoning: string, confidence: number
            }>,
            summary: object
        },
        confidenceAssessments: Array<{
            assessmentId: string,
            findingId: string,
            overallConfidence: number,       // 0-100 composite
            evidenceStrength: number,
            reachabilityConfidence: number,
            impactConfidence: number,
            falsePositiveRisk: number,       // higher = more likely FP
            scoreBreakdown: object,
            remainingUnknowns: Array<{ factor, whyUnknown, impactIfWrong, suggestedInvestigation }>,
            recommendation: string,
            nextSteps: string[]
        }>,
        // ACTUAL FIELD (was computed internally but never exported by trackator until this
        // audit's fix — see evidence-validator.ts. One entry per finding that has a
        // reachability path; findings with no path are skipped, not zero-filled):
        proofRequirementsList: Array<{
            findingId: string,
            requirements: Array<{
                reqId: string, requirement: string,
                category: 'entry-point-exists' | 'execution-path-exists' | 'state-prerequisites' |
                          'storage-prerequisites' | 'no-validation-blocks' | 'no-invariant-prevents' |
                          'no-reconciliation' | 'observable-impact' | 'poc-constructible',
                status: 'met' | 'not-met' | 'partial' | 'unknown',
                evidence?: object, explanation: string, findingId?: string
            }>,
            overallStatus: 'proven-reachable' | 'not-proven' | 'insufficient-evidence',
            metRequirements: number,
            totalRequirements: number,       // always 9
            missingRequirements: Array<object>
        }>,
        finalVerdict: { verdicts: Array<object>, generatedAt: string, methodology: string, summary: object },
        summary: object
    }
}
```

### Phase 0 Output Artifacts

| Artifact | Format | Description |
|----------|--------|-------------|
| `hypotheses-initial.json` | JSON | Priority-ranked hypothesis list from Trackator alerts |
| `protocol-context.json` | JSON | Extracted protocol context for downstream use |
| `enhanced-context.json` | JSON | v2.0: Enhanced Trackator data (storage/coupling/sync/evidence) |

---

