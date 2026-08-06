### Enhanced Context Structure (v2.0)

When enhanced data is available, the context object includes:

```javascript
{
    // ... base fields from Step 0.3 ...
    
    // Storage Dependency Analyzer (Trackator Phase 1)
    storage: {
        variableWriters: Map<string, Array<{          // varName → [writers]
            function: string,
            contract: string,
            writeReasonCategory: string,  // 'direct-user-action', 'protocol-admin', ...
            accessControlLevel: string,     // 'none', 'role-based', 'permissionless'
            ceiPatternMatch: boolean
        }>>,
        multiVariableWriters: Array<{        // Functions touching multiple vars
            function: string,
            variablesWritten: string[],
            isComplexStateChange: boolean
        }>,
        contentedVariables: Array<{         // Race condition candidates
            variable: string,
            writerCount: number,
            writers: Array<{ function, accessControlLevel }>
        }>,
        valueBearingVariables: Array<{       // Holds user funds!
            variable: string,
            type: string,                     // 'erc20-balance', 'lp-shares', 'collateral', ...
            location: string,
            estimatedValue?: string
        }>,
        sharedStateMatrix: Array<{          // permissionless × shared storage
            entryPoint: string,
            sharedVariables: string[],
            hasValueBearing: boolean,
            riskScore: number
        }>
    },
    
    // State Coupling Detector (Trackator Phase 2)
    coupling: {
        functionDependencyMatrix: object,     // N×N matrix: funcA → funcB coupling
        hiddenCouplings: Array({
            functionA: string,
            functionB: string,
            couplingType: 'transient' | 'conditional' | 'timestamp-dependent',
            sharedVariables: string[],
            strength: 'STRONG' | 'MEDIUM' | 'WEAK'
        }),
        invariantFunctionMap: {
            establishes: Map<string, string[]>,   // invariantId → [functions that establish]
            dependsOn: Map<string, string[]>,    // invariantId → [functions that depend]
            canViolate: Map<string, string[]>    // invariantId → [functions that can break]
        },
        storageVariableClassification: Map<string, {
            class: 'core' | 'derived' | 'control-flow' | 'metadata',
            reason: string
        }>,
        topIntersections: Array({             // Highest-value attack surfaces
            functionPair: [string, string],
            intersectionValue: number,
            sharedCriticalVars: string[],
            exploitationPotential: string
        })
    },
    
    // Sync Analyzer (Trackator Phase 3)
    sync: {
        assumptionDependencyGraph: {
            producers: Array<{ assumptionId, function, stalenessWindow }>,
            consumers: Array<{ assumptionId, function, validationGap }>,
            verifiers: Array<{ assumptionId, function, verificationType }>
        },
        desynchronizationAnalysis: {
            staleDataDetections: Array({ variable, validWindow, expiryCondition }),
            driftAnalysis: Array({ variable, expectedValue, actualValueRange }),
            missingVerifiers: Array({ assumptionId, consumerFunctions }),
            raceWindows: Array({ windowMs, exploitPrerequisite })
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
        syncRelationships: Array({
            id: string,
            producer: string,
            consumer: string,
            verifier: string | null,
            stalenessWindow: number,
            exploitability: number,  // 0-100
            attackComplexity: 'easy' | 'medium' | 'hard'
        })
    },
    
    // Evidence Validator (Trackator Phase 4)
    evidence: {
        classificationRegistry: {
            confirmedVulnerability: Array<{ findingId, criteriaMet }>,
            potentialVulnerability: Array<{ findingId, criteriaMet }>,
            falsePositive: Array<{ findingId, disproofEvidence }>,
            byDesign: Array<{ findingId, designRationale }>,
            informational: Array<{ findingId, note }>,
            cannotDetermine: Array<{ findingId, reason }>
        },
        reachabilityAnalysis: Array({
            findingId: string,
            executionPath: string[],
            prerequisites: Array({ condition, achievable, evidence }),
            blockers: Array({ type, description, bypassable }),
            gasCostEstimate: number,
            feasibleInSingleTx: boolean
        }),
        disproofEngine: {
            attemptedDisproofs: number,
            successfulDisproofs: number,  // False positives caught
            disproofEvidence: Array({ findingId, guardCodeFound, reasonSafe })
        },
        confidenceAssessments: Array({
            findingId: string,
            score: number,  // 0-100
            components: {
                patternMatchStrength: number,
                codeCoverage: number,
                historicalAccuracy: number,
                expertAdjustment: number
            }
        })
    }
}
```

