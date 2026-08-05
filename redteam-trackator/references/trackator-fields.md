# Trackator Fields Reference

> **Comprehensive data structures reference for Redteam-Trackator v2.1**
> 
> This file is loaded ON-DEMAND when the model needs field definitions for Trackator data structures.
> Organized by phase/source for quick lookup.

---

## Table of Contents

1. [Hypothesis Base Structure](#1-hypothesis-base-structure-phase-0)
2. [Protocol Context Structure](#2-protocol-context-structure-phase-0)
3. [Enhanced Context Structure (v2.0+)](#3-enhanced-context-structure-v20)
   - 3.1 [Storage Dependency Analyzer](#31-storage-dependency-analyzer)
   - 3.2 [State Coupling Detector](#32-state-coupling-detector)
   - 3.3 [Sync Analyzer](#33-sync-analyzer)
   - 3.4 [Evidence Validator](#34-evidence-validator)
4. [Phase 1 Output: Intent Filter Result](#4-phase-1-output-intent-filter-result)
5. [Phase 2 Output: Pattern Match & Reachability](#5-phase-2-output-pattern-match--reachability)
6. [Phase 3 Output: Creative Attack Findings](#6-phase-3-output-creative-attack-findings)
7. [Phase 4 Output: Fuzz Results](#7-phase-4-output-fuzz-results)
8. [Phase 5 Output: Fork Test Results](#8-phase-5-output-fork-test-results)
9. [Phase 6 Output: Final Report](#9-phase-6-output-final-report)
10. [Classification Classes (6-Class System)](#10-classification-classes-6-class-system)
11. [Verdict States & Status Values](#11-verdict-states--status-values)

---

## 1. Hypothesis Base Structure (Phase 0)

Core hypothesis object created from Trackator alerts.

```typescript
interface Hypothesis {
    // Identity
    id: string;                          // Format: `HYP_${alert.id}` or `CREATIVE_N`
    sourceAlert?: Alert;                 // Original Trackator alert (for alert-based hypotheses)
    
    // Priority & Status
    priorityScore: number;               // 0-100 calculated priority
    status: HypothesisStatus;            // See Verdict States section
    phase: number;                       // Which phase created/last-touched this (0-6)
    
    // Phase 1: Intent Filtering
    intentFilterResult?: IntentFilterResult;
    
    // Phase 2: Pattern Matching
    patternMatches?: PatternMatch[];
    reachabilityResult?: ReachabilityResult;
    
    // Phase 3: Creative Attack
    creativeFindings?: CreativeFinding[];
    assumptionBreaks?: AssumptionBreak[];
    couplingAttacks?: CouplingAttack[];       // v2.0+: State coupling analysis
    desyncAttacks?: DesyncAttack[];           // v2.0+: Sync analyzer attacks
    executionTrace?: ExecutionTrace;
    traceConclusion?: TraceConclusion;
    pluginRouting?: PluginRoutingResult;      // v2.1+: Intelligent routing
    
    // Phase 3 v2.1: Evidence Calibration
    evidenceCalibration?: EvidenceCalibration;
    
    // Phase 4: Fuzz Testing
    fuzzResults?: FuzzResult;
    
    // Phase 5: Fork Testing
    forkTestResult?: ForkTestResult;
    
    // Metadata
    createdAt: number;                   // Unix timestamp
}
```

### Hypothesis Status Values

| Status | Meaning | Set By |
|--------|---------|--------|
| `PENDING` | Initial state, not yet processed | Phase 0 |
| `FILTERED` | Passed intent filter | Phase 1 |
| `DISCARDED` | Failed intent filter (FP) | Phase 1 |
| `MATCHED` | Has pattern matches | Phase 2 |
| `DEAD` | Proven unreachable | Phase 2 |
| `TESTED` | Creative attack completed | Phase 3 |
| `LEAD` | Interesting but needs review | Phase 2-5 |
| `CONFIRMED` | Validated on fork | Phase 5 |

---

## 2. Protocol Context Structure (Phase 0)

Base protocol context extracted for downstream phases.

```typescript
interface ProtocolContext {
    // Protocol Identification
    protocolType: string;                // 'lending' | 'dex' | 'vault' | 'bridge' | 'governance' | ...
    
    // Contract Data
    contracts: ContractData[];           // All analyzed contracts
    
    // Threat Model
    assetsAtRisk: AssetAtRisk[];         // Assets that could be lost/stolen
    entryPoints: EntryPoint[];           // Publicly accessible functions
    invariants: Invariant[];             // Protocol invariants (should always hold)
    trustAssumptions: TrustAssumption[]; // Assumptions about trusted roles/entities
    attackVectors: AttackVector[];       // Potential attack paths
    adversaryProfiles: AdversaryProfile[];// Attacker capabilities
    
    // Analysis Data
    alertRules: AlertRule[];             // Trackator alerts/rules
    components: Component[];             // Protocol component breakdown
    moneyFlows: MoneyFlow[];             // Value flow paths
    
    // Enhanced Data (v2.0+) - see Section 3
    storage?: StorageData;
    coupling?: CouplingData;
    sync?: SyncData;
    evidence?: EvidenceData;
}
```

---

## 3. Enhanced Context Structure (v2.0+)

When enhanced Trackator output is available, these structures are populated.

### 3.1 Storage Dependency Analyzer

From `trackator-storage.json` - analyzes variable write patterns.

```typescript
interface StorageData {
    // Variable → Writers mapping
    variableWriters: Map<string, VariableWriter[]>;
    
    // Functions touching multiple variables
    multiVariableWriters: MultiVariableWriter[];
    
    // Race condition candidates
    contendedVariables: ContendedVariable[];
    
    // Variables holding user funds (HIGH VALUE TARGETS)
    valueBearingVariables: ValueBearingVariable[];
    
    // Permissionless functions × shared storage matrix
    sharedStateMatrix: SharedStateEntry[];
}

interface VariableWriter {
    function: string;                    // Function name writing this variable
    contract: string;                    // Contract containing function
    writeReasonCategory: WriteReasonCategory;
    accessControlLevel: AccessControlLevel;
    ceiPatternMatch: boolean;            // Does writer follow CEI pattern?
}

type WriteReasonCategory = 
    | 'direct-user-action'      // User-triggered write
    | 'protocol-admin'          // Admin/governance action
    | 'internal-calculation'    // Derived value update
    | 'external-callback'       // External call result
    | 'oracle-update';          // Price/data feed update

type AccessControlLevel = 
    | 'none'                    // Permissionless
    | 'role-based'              // Requires specific role
    | 'permissionless';         // Anyone can call

interface MultiVariableWriter {
    function: string;
    variablesWritten: string[];
    isComplexStateChange: boolean;      // True = potential atomicity issue
}

interface ContendedVariable {
    variable: string;
    writerCount: number;
    writers: Array<{ function: string; accessControlLevel: string }>;
}

interface ValueBearingVariable {
    variable: string;
    type: ValueType;                     // What kind of value
    location: string;                   // Contract.location
    estimatedValue?: string;             // e.g., "$2.5M" if calculable
}

type ValueType = 
    | 'erc20-balance'           // Token balance mapping
    | 'lp-shares'               // Liquidity provider shares
    | 'collateral'              // Posted collateral
    | 'debt'                    // Borrowed amount
    | 'reserve'                 // Protocol reserves
    | 'supply'                  // Total token supply
    | 'reward-accrued'          // Unclaimed rewards
    | 'price-feed';             // Oracle price storage

interface SharedStateEntry {
    entryPoint: string;                 // Permissionless function
    sharedVariables: string[];          // Variables it can modify
    hasValueBearing: boolean;           // Any value-bearing vars involved?
    riskScore: number;                  // 0-100 risk assessment
}
```

### 3.2 State Coupling Detector

From Trackator Phase 2 - detects hidden dependencies between functions.

```typescript
interface CouplingData {
    // N×N dependency matrix
    functionDependencyMatrix: FunctionDependencyMatrix;
    
    // Non-obvious dependencies
    hiddenCouplings: HiddenCouplingContainer;
    
    // Invariant → Function mappings
    invariantFunctionMap: InvariantFunctionMap;
    
    // Variable classification
    storageVariableClassification: Map<string, VariableClassification>;
    
    // Highest-value attack surfaces
    topIntersections: TopIntersection[];     // v2.0 original
    topStateIntersections?: StateIntersectionContainer;  // v2.1 enhanced
    
    // v2.1 NEW: Quick-access priority arrays
    criticalFindings?: CriticalFinding[];
    hiddenAssumptions?: HiddenAssumptionContainer;
}

interface FunctionDependencyMatrix {
    // v2.1: Full matrix structure
    dependencies: Map<string, DependencyRelation>;
    functions: FunctionInfo[];
    couplingClusters?: CouplingCluster[];        // v2.1 NEW
    statistics?: MatrixStatistics;               // v2.1 NEW
}

interface DependencyRelation {
    sourceFunction: string;
    targetFunction: string;
    couplingStrength: number;            // 0-100 how tightly coupled
    dependencyType: DependencyType;
    sharedVariables: string[];
    riskFactors: string[];
    isCrossContract: boolean;
}

type DependencyType =
    | 'direct-read'              // A reads what B writes
    | 'indirect-through-call'    // A calls B which modifies state
    | 'shared-modifier'          // Both use same modifier
    | 'event-consumer'          // A emits event B acts on
    | 'inheritance'              // Parent-child contract state
    | 'proxy-delegation'         // Proxy implementation pattern
    | 'callback-dependence';    // External callback affects state

interface HiddenCouplingContainer {
    couplings: HiddenCoupling[];
    summary: {
        total: number;
        criticalCount: number;
        highCount: number;
    };
}

interface HiddenCoupling {
    type: HiddenCouplingType;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    source: { contract: string; function?: string };
    target: { contract: string; function?: string };
    mechanism: string;
    detectionConfidence: 'certain' | 'likely' | 'possible' | 'speculative';
    exploitationScenario?: string;
    recommendation?: string;
    stateState?: string[];               // State variables involved
}

// v2.1: All 13 hidden coupling types
type HiddenCouplingType =
    | 'proxy-storage-conflict'
    | 'delegatecall-context-leak'
    | 'callback-state-dependence'
    | 'storage-slot-collision'
    | 'cross-contract-assumed-state'
    | 'struct-layout-assumption'
    | 'transient'
    | 'timestamp-dependent'
    | 'inheritance-storage-overlap'
    | 'library-storage-sharing'
    | 'multi-contract-consistency'
    | 'protocol-dependent'
    | 'immutable-pattern-violation';

interface InvariantFunctionMap {
    establishes: Map<string, string[]>;      // invariantId → [functions that establish]
    dependsOn: Map<string, string[]>;        // invariantId → [functions that depend]
    canViolate: Map<string, string[]>;       // invariantId → [functions that can break]
    
    // v2.1 NEW: Enhanced structures
    mappings?: InvariantMapping[];
    violationPaths?: ViolationPath[];
    protectionGaps?: ProtectionGap[];
}

interface ViolationPath {
    pathId: string;
    invariantId: string;
    entryFunction: string;
    feasibility: 'trivial' | 'easy' | 'moderate' | 'difficult' | 'impossible';
    impactIfViolated: string;
    executionSteps: ExecutionStep[];
    prerequisiteState: string[];
}

interface ProtectionGap {
    gapId: string;
    invariantId: string;
    missingProtection: string;               // e.g., 'reentrancy-guard', 'access-control'
    affectedFunctions: string[];
    severity: 'critical' | 'high' | 'medium';
    recommendedFix?: string;
}

interface VariableClassification {
    class: VariableClass;
    reason: string;
}

type VariableClass =
    | 'core'                   // Essential accounting state
    | 'derived'                // Calculated from other vars
    | 'control-flow'           // Affects execution path
    | 'metadata';              // Informational only

interface TopIntersection {
    functionPair: [string, string];
    intersectionValue: number;
    sharedCriticalVars: string[];
    exploitationPotential: string;
}

// v2.1 ENHANCED: Full state intersection with participants
interface StateIntersectionContainer {
    intersections: StateIntersection[];
}

interface StateIntersection {
    rank: number;
    intersectionType: IntersectionType;
    variables: string[];
    contracts: string[];
    riskScore: number;                   // 0-100
    valueAtRisk: string;
    exploitationComplexity: DifficultyLevel;
    exploitationPotential?: string;
    specificFindings?: string[];
    recommendations?: string[];
    functions: IntersectionParticipant[];  // v2.1: Full participant data
}

type IntersectionType =
    | 'accounting-conflict'
    | 'liquidity-manipulation'
    | 'solvency-bypass'
    | 'permission-elevation'
    | 'value-drain';

interface IntersectionParticipant {
    functionId: string;
    role: 'reader' | 'writer' | 'both';
    isPermissionless: boolean;
    contract: string;
}

// v2.1 NEW: Critical findings queue
interface CriticalFinding {
    id: string;
    type: 'coupling' | 'violation-path' | 'protection-gap' | 'assumption' | 'classification';
    title: string;
    description: string;
    location: string;
    impact: string;
    remediation: string;
    evidence: any;
    priority: 'immediate' | 'short-term' | 'long-term';
    severity: 'critical' | 'high' | 'medium' | 'low';
}

// v2.1 NEW: Hidden assumptions with exploitability
interface HiddenAssumptionContainer {
    assumptions: HiddenAssumption[];
}

interface HiddenAssumption {
    id: string;
    assumption: string;
    category: string;
    heldBy: string[];
    validatedBy: string[];
    ifWrong: string;
    detectability: Detectability;
    exploitability: ExploitabilityLevel;
    severity: 'critical' | 'high' | 'medium' | 'low';
    location: { contract: string; function?: string };
    recommendation?: string;
}

type Detectability = 'easy' | 'moderate' | 'difficult' | 'very-difficult';
type ExploitabilityLevel = 'trivial' | 'easy' | 'moderate' | 'difficult';

// v2.1 NEW: Variable classification with security sensitivity
interface VariableClassificationEntry {  // From variableClassification.classifications[]
    variableName: string;
    contract: string;
    type: string;
    primaryCategory: VariablePrimaryCategory;
    secondaryCategories: string[];
    classificationRationale: string;
    securitySensitivity: 'critical' | 'high' | 'medium' | 'low';
    integrityRequirement: IntegrityRequirement;
    writerFunctions: string[];
    readerFunctions: string[];
    crossContractImpact: CrossContractImpact[];
    relatedInvariants: string[];
}

type VariablePrimaryCategory =
    | 'accounting'       // Balance/debt tracking
    | 'liquidity'        // LP/pool shares
    | 'solvency'         // Health factor/collateral
    | 'access-control'   // Permissions/roles
    | 'configuration'    // Parameters/settings
    | 'oracle'           // Price feeds
    | 'temporal'         // Timestamps/block numbers
    | 'metadata';        // Auxiliary data

type IntegrityRequirement =
    | 'monotonic'        // Only increase or decrease
    | 'bounded'          // Must stay within range
    | 'atomic'           // Updates must be atomic
    | 'immutable-after-set'  // Cannot change after initialization
    | 'consistent-across-contracts';  // Same value everywhere

interface CrossContractImpact {
    targetContract: string;
    impactType: 'read-dependency' | 'write-propagation' | 'invariant-involvement';
    relatedFunctions: string[];
}
```

### 3.3 Sync Analyzer

From Trackator Phase 3 - analyzes assumption synchronization gaps.

```typescript
interface SyncData {
    // Assumption producer/consumer/verifier graph
    assumptionDependencyGraph: AssumptionDependencyGraph;
    
    // Desynchronization analysis results
    desynchronizationAnalysis: DesynchronizationAnalysis;
    
    // Pre-computed critical risks (PRIORITY QUEUE)
    criticalDesyncRisks: CriticalDesyncRisk[];
    
    // All sync relationships
    syncRelationships: SyncRelationship[];
}

interface AssumptionDependencyGraph {
    producers: Array<{ assumptionId: string; function: string; stalenessWindow: number }>;
    consumers: Array<{ assumptionId: string; function: string; validationGap: number }>;
    verifiers: Array<{ assumptionId: string; function: string; verificationType: string }>;
}

interface DesynchronizationAnalysis {
    staleDataDetections: StaleDataDetection[];
    driftAnalysis: DriftAnalysisItem[];
    missingVerifiers: MissingVerifier[];
    raceWindows: RaceWindow[];
}

interface StaleDataDetection {
    variable: string;
    validWindow: number;                 // ms until data is stale
    expiryCondition: string;
}

interface DriftAnalysisItem {
    variable: string;
    expectedValue: string;
    actualValueRange: string;
}

interface MissingVerifier {
    assumptionId: string;
    consumerFunctions: string[];
}

interface RaceWindow {
    windowMs: number;
    exploitPrerequisite: string;
}

interface CriticalDesyncRisk {
    id: string;
    riskType: CriticalDesyncRiskType;
    severity: 'critical' | 'high' | 'medium';
    impact: string;
    attackScenario: string;
    producerFunction: string;
    consumerFunction: string;
    staleWindowMs: number;
    mitigationSuggestion: string;
    assumptionId?: string;               // For missing-verifier type
}

type CriticalDesyncRiskType =
    | 'stale-price'              // Price oracle not fresh enough
    | 'stale-approval'           // Allowance may be changed
    | 'state-drift'              // Expected state diverged
    | 'missing-verifier'         // No validation between prod/consume
    | 'race-window';             // Timing attack possible

interface SyncRelationship {
    id: string;
    producer: string;                   // Function that sets assumption
    consumer: string;                   // Function that uses assumption
    verifier: string | null;            // Function that validates (if any)
    stalenessWindow: number;            // ms of acceptable delay
    exploitability: number;              // 0-100 how exploitable
    attackComplexity: DifficultyLevel;
}

type DifficultyLevel = 'easy' | 'medium' | 'hard';
```

### 3.4 Evidence Validator

From Trackator Phase 4 - classification and confidence scoring.

```typescript
interface EvidenceData {
    // 6-Class Classification System
    classificationRegistry: ClassificationRegistry;
    
    // Reachability analysis per finding
    reachabilityAnalysis: ReachabilityAnalysisEntry[];
    
    // Disproof engine results
    disproofEngine: DisproofEngineResult;
    
    // Confidence assessments
    confidenceAssessments: ConfidenceAssessment[];
    
    // v2.1 NEW: Proof requirements (9-criteria)
    proofRequirementsList?: ProofRequirementEntry[];
    
    // v2.1 NEW: Final verdicts
    finalVerdict?: FinalVerdictContainer;
}

interface ClassificationRegistry {
    // v2.1: Uses entries array
    entries?: ClassificationEntry[];
    
    // Legacy structure (still supported)
    confirmedVulnerability?: Array<{ findingId: string; criteriaMet: string[] }>;
    potentialVulnerability?: Array<{ findingId: string; criteriaMet: string[] }>;
    falsePositive?: Array<{ findingId: string; disproofEvidence: string[] }>;
    byDesign?: Array<{ findingId: string; designRationale: string }>;
    informational?: Array<{ findingId: string; note: string }>;
    cannotDetermine?: Array<{ findingId: string; reason: string }>;
}

// v2.1: Full classification entry
interface ClassificationEntry {
    findingId: string;
    title?: string;
    originalFindingId?: string;
    classification: ClassificationClass;     // 6-class enum
    confidence: number;                      // 0-100%
    supportingEvidence?: EvidenceItem[];
    blockingEvidence?: EvidenceItem[];
}

type ClassificationClass =
    | 'proven-property'           // Intentional, working as designed
    | 'potential-bug'             // Likely bug but needs more evidence
    | 'reachable-bug'            // Confirmed reachable vulnerability
    | 'false-positive'           // Not actually exploitable
    | 'by-design'                // Intentional security trade-off
    | 'insufficient-evidence'   // Cannot determine
    | 'informational';           // Not a bug but worth noting (code smell, anti-pattern) — Appendix only

interface EvidenceItem {
    itemId: string;
    type: string;
    description: string;
}

interface ReachabilityAnalysisEntry {
    findingId: string;
    
    // v2.1: Enhanced structure
    isReachable?: boolean;
    callChain?: ExecutionPath[];            // Full execution path
    crossContractPrereqs?: CrossContractPrereq[];
    blockingRequirement?: BlockingRequirement;
    
    // Legacy structure
    executionPath?: string[];
    prerequisites?: Array<{ condition: string; achievable: boolean; evidence: string }>;
    blockers?: Array<{ type: string; description: string; bypassable: boolean }>;
    gasCostEstimate?: number;
    feasibleInSingleTx?: boolean;
}

interface CrossContractPrereq {
    targetContract: string;
    requiredState: string;
    dependencyType: string;
    canBeSatisfied: boolean;
}

interface BlockingRequirement {
    requirement: string;
    type: string;
    whyBlocking: string;
    potentialBypass: string;
}

interface DisproofEngineResult {
    attemptedDisproofs: number;
    successfulDisproofs: number;            // False positives caught
    disproofEvidence: DisproofEvidenceItem[];
    
    // v2.1: Enhanced
    results?: DisproofResult[];
    disproofAttempts?: DisproofAttempt[];
}

interface DisproofEvidenceItem {
    findingId: string;
    guardCodeFound: string;
    reasonSafe: string;
}

// v2.1: Detailed disproof result
interface DisproofResult {
    findingId: string;
    newClassification?: ClassificationClass;
    confidence: number;                     // 0-100%
    strategiesSuccessful: string[];
    evidence: DisproofStrategyEvidence[];
}

interface DisproofAttempt {
    targetFindingId: string;
    strategy: DisproofStrategy;
    result: 'success' | 'partial' | 'failed';
    evidence?: string;
}

type DisproofStrategy =
    | 'guard-code-search'          // Look for protective code
    | 'semantic-analysis'          // Check if pattern leads to loss
    | 'historical-cross-check'     // Similar patterns disproved before
    | 'invariant-consistency'      // Would exploiting violate safety invariants?
    | 'boundary-analysis'          // Check edge cases
    | 'state-machine-validation'   // Verify against expected transitions
    | 'access-control-verification' // Confirm auth requirements
    | 'economic-feasibility'       // Would attack be profitable?
    | 'gas-limit-analysis'         // Within block gas limits?
    | 'mev-competition'            // Would MEV bots front-run?
    | 'time-window-constraint';    // Is there enough time?

interface DisproofStrategyEvidence {
    strategy: DisproofStrategy;
    found: boolean;
    details: string;
}

interface ConfidenceAssessment {
    findingId: string;
    score: number;                        // 0-100 overall
    
    // v2.1: Breakdown components
    overallConfidence?: number;
    evidenceStrength?: number;            // 0-100
    reachabilityConfidence?: number;      // 0-100
    impactConfidence?: number;            // 0-100
    falsePositiveRisk?: number;           // 0-100 (higher = more likely FP)
    
    // Legacy structure
    components?: {
        patternMatchStrength: number;
        codeCoverage: number;
        historicalAccuracy: number;
        expertAdjustment: number;
    };
    
    // v2.1: Remaining unknowns
    remainingUnknowns?: UnknownFactor[];
}

interface UnknownFactor {
    factor: string;
    whyUnknown: string;
    impactIfWrong: string;
    suggestedInvestigation: string;
}

// v2.1: 9-Criteria proof requirements
interface ProofRequirementEntry {
    findingId: string;
    metRequirements: number;
    totalRequirements: number;            // Always 9
    overallStatus: ProofStatus;
    requirements: ProofCriterion[];
}

type ProofStatus = 'proven-reachable' | 'not-proven' | 'disproven' | 'insufficient-evidence';

interface ProofCriterion {
    reqId: string;
    requirement: string;
    category: string;
    status: 'met' | 'not-met' | 'partial' | 'n/a';
    evidence?: any;
    explanation: string;
}

// v2.1: Final verdict container
interface FinalVerdictContainer {
    verdicts: FinalVerdictEntry[];
}

interface FinalVerdictEntry {
    findingId: string;
    finalVerdict: FinalVerdictType;
    recommendedAction: RecommendedAction;
    confidence: number;
    rationale: string;
}

type FinalVerdictType =
    | 'confirmed-vulnerability'
    | 'potential-vulnerability'
    | 'false-positive'
    | 'by-design'
    | 'cannot-determine'
    | 'deferred';

type RecommendedAction =
    | 'immediate-fix'
    | 'short-term-investigation'
    | 'long-term-monitoring'
    | 'accept-risk'
    | 'dismiss'
    | 'escalate-to-auditor'
    | 'defer';
```

---

## 4. Phase 1 Output: Intent Filter Result

Applied to each hypothesis after intent filtering.

```typescript
interface IntentFilterResult {
    verdict: IntentVerdict;
    reason: string;
    checkedAt: number;                    // Timestamp
}

type IntentVerdict =
    | 'keep'                    // Genuine anomaly, continue analysis
    | 'downgrade_to_info'       // Known trust assumption, low severity
    | 'discard'                 // Working as designed / operational error
    | 'keep_with_note';         // Design choice but potentially exploitable
```

---

## 5. Phase 2 Output: Pattern Match & Reachability

### Pattern Match Result

```typescript
interface PatternMatch {
    patternSlug: string;                // e.g., 'reentrancy-state-update-after-external-call'
    primaryBugClass: string;            // Bug category from exploit card
    matchScore: number;                 // 0-1 similarity score (can exceed 1.0 with v2.0 bonuses)
    representativeLoss: number;         // USD loss from historical exploit
    detectionHeuristic: DetectionHeuristic;
    preconditionChain: string[];        // Required conditions for exploitation
}

interface DetectionHeuristic {
    signature: string;                  // Code pattern signature
    grepPatterns: string[];             // Search patterns
    checklist: string[];                // Manual checklist items
}
```

### Match Scoring Factors

| Factor | Weight | Source |
|--------|--------|--------|
| Bug class match | 30% | `alert.category` ↔ `pattern.primary_bug_class` |
| Protocol type match | 25% | `context.protocolType` ↔ `pattern.protocol_types` |
| Detection heuristic match | 25% | `alert.condition` ↔ `pattern.detection_checklist` |
| Severity alignment | 10% | `alert.severity` ↔ historical loss |
| Prerequisite satisfaction | 10% | `context.entryPoints` ↔ `pattern.prerequisites` |
| Storage alignment (v2.0) | +10% bonus | `context.storage` |
| Coupling signal (v2.0) | +10% bonus | `context.coupling` |
| Sync risk (v2.0) | +10% bonus | `context.sync` |
| Pre-classification (v2.0) | adjusts | `context.evidence` |

### Reachability Result (BLOCK GATE #1)

```typescript
interface ReachabilityResult {
    verdict: ReachabilityVerdict;
    reason: string;
    satisfiedPreconditions: string[];
    unsatisfiedPreconditions?: string[];
    unknownPreconditions?: string[];
    saveForPoC: boolean;                 // BLOCK GATE: Save, don't kill!
    confidence?: 'high' | 'medium' | 'low';
}

type ReachabilityVerdict =
    | 'confirmed_pattern'        // All preconditions satisfied
    | 'probable'                 // Most satisfied, some unknown
    | 'lead'                     // Interesting, needs expert review
    | 'dead';                    // Proven unreachable
```

---

## 6. Phase 3 Output: Creative Attack Findings

### Creative Finding (Reverse Engineering)

```typescript
interface CreativeFinding {
    id: string;                          // Format: `CREATIVE_N`
    type: 'reverse_engineering';
    targetAsset: string;
    moneyFlow: string;
    manipulationPoint: string;
    manipulationType: ManipulationType;
    attackIdea: string;
    sourcePhase: number;                 // Always 3
    status: 'HYPOTHESIS';
    createdAt: number;
}

type ManipulationType =
    | 'input'                    // Manipulate function input
    | 'state'                    // Manipulate state variable
    | 'timing';                  // Front-run/sandwich attack
```

### Assumption Break Result

```typescript
interface AssumptionBreak {
    id: string;                          // Format: `AB_{CATEGORY}_N` or `DESYNC_{TYPE}_{FUNC}`
    assumptionId?: string;
    type: AttackType;
    description: string;
    prerequisiteChain: string[];
    trackatorEvidence: TrackatorEvidenceRef;
    estimatedImpact?: string;
    feasibility?: DifficultyLevel;
}

type AttackType =
    // Oracle attacks
    | 'flash_loan_price_manipulation'
    | 'multi_block_manipulation'
    // Desync attacks (v2.0)
    | 'stale_price_exploitation'
    | 'unverified_assumption_exploitation'
    | 'race_condition_exploitation'
    // External contract
    | 'external_contract_manipulation'
    // Price feed
    | 'price_feed_front_running';
```

### Coupling Attack (v2.0+)

```typescript
interface CouplingAttack {
    id: string;                          // Format varies by type
    type: CouplingAttackType;
    description: string;
    attackIdea: string;
    prerequisiteChain: string[];
    trackatorEvidence: CouplingTrackatorEvidence;
    estimatedDifficulty: DifficultyLevel;
    status: 'HYPOTHESIS';
    priorityBoost?: number;              // Additional priority points
}

type CouplingAttackType =
    // v2.0 original
    | 'strong_coupling_exploitation'
    | 'hidden_coupling_exploitation'
    | 'invariant_violation_chain'
    | 'high_value_intersection'
    // v2.1 NEW types
    | 'coupling_cluster_exploitation'
    | 'invariant_violation_path'
    | 'protection_gap_exploitation'
    | 'hidden_assumption_exploitation'
    | 'sensitive_variable_targeting';

interface CouplingTrackatorEvidence {
    // Common fields
    couplingStrength?: number;
    dependencyType?: string;
    sharedVariables?: string[];
    valueBearingInvolved?: boolean;
    riskFactors?: string[];
    isCrossContract?: boolean;
    matrixEntry?: DependencyRelation;
    
    // Cluster-specific
    clusterId?: string;
    functions?: string[];
    cohesionScore?: number;
    riskLevel?: string;
    permissionlessEntries?: string[];
    
    // Hidden coupling-specific
    couplingType?: HiddenCouplingType;
    severity?: string;
    source?: { contract: string; function?: string };
    target?: { contract: string; function?: string };
    mechanism?: string;
    detectionConfidence?: string;
    exploitationScenario?: string;
    
    // Invariant-specific
    invariantId?: string;
    violator?: string;
    dependent?: string;
    pathId?: string;
    entryFunction?: string;
    feasibility?: string;
    impactIfViolated?: string;
    executionSteps?: ExecutionStep[];
    prerequisiteState?: string[];
    
    // Protection gap-specific
    gapId?: string;
    missingProtection?: string;
    affectedFunctions?: string[];
    recommendedFix?: string;
    
    // Intersection-specific
    rank?: number;
    intersectionType?: IntersectionType;
    variables?: string[];
    contracts?: string[];
    riskScore?: number;
    valueAtRisk?: string;
    exploitationComplexity?: DifficultyLevel;
    participants?: IntersectionParticipant[];
    specificFindings?: string[];
    recommendations?: string[];
    
    // Hidden assumption-specific
    assumptionId?: string;
    category?: string;
    detectability?: Detectability;
    exploitability?: ExploitabilityLevel;
    validatedBy?: string[];
    recommendation?: string;
    
    // Variable targeting-specific
    variableName?: string;
    contract?: string;
    primaryCategory?: VariablePrimaryCategory;
    securitySensitivity?: string;
    integrityRequirement?: IntegrityRequirement;
    writerFunctions?: string[];
    readerFunctions?: string[];
    crossContractImpact?: CrossContractImpact[];
    relatedInvariants?: string[];
    
    // Generic
    source?: string;
    originalFinding?: any;
}

interface ExecutionStep {
    action: string;
    variable?: string;
    function?: string;
}
```

### Desync Attack (v2.0+)

```typescript
interface DesyncAttack extends AssumptionBreak {
    // Inherits all AssumptionBreak fields
    // Used specifically for sync analyzer-derived attacks
    trackatorEvidence: {
        syncAnalyzerRiskId: string;
        staleWindowMs?: number;
        raceWindowMs?: number;
        severity?: string;
        missingVerifier?: boolean;
    };
}
```

### Execution Trace

```typescript
interface ExecutionTrace {
    hypothesisId: string;
    steps: TraceStep[];
    finalState: TraceFinalState;
    conclusion: TraceConclusion;
    completed: boolean;
}

interface TraceStep {
    function: string;
    contract?: string;
    modifiers?: string[];
    hasExternalCall?: boolean;
    ceiPattern?: string;
    stateVariablesRead?: string[];
    stateVariablesWritten?: string[];
    calls?: string[];
    note?: string;                       // Annotations like "EXTERNAL CALL HERE"
    type?: TraceStepType;
}

type TraceStepType =
    | 'normal'
    | 'cycle_detected'
    | 'external_or_unknown'
    | 'trace_limit_reached';

interface TraceFinalState {
    // Summary of state after trace completion
    attackerProfit?: number;
    protocolLoss?: number;
    invariantsViolated?: string[];
}

interface TraceConclusion {
    survives: boolean;
    reason: string;
    severity: 'high' | 'medium' | 'mitigated';
}
```

### Plugin Routing Result (v2.1)

```typescript
interface PluginRoutingResult {
    hypothesisId: string;
    primaryPlugin: PluginName;
    secondaryPlugins: PluginName[];
    routingRationale: string;
    priority: number;                     // 0-100
    estimatedValue: EstimateValue;
}

type PluginName =
    | 'fork_tester'
    | 'evidence_validator'
    | 'assumption_breaker'
    | 'reverse_engineering'
    | 'coupling_analyzer'
    | 'pattern_matcher'
    | 'reachability_checker'
    | 'execution_tracer'
    | 'general_analysis';

type EstimateValue = 'critical' | 'high' | 'medium' | 'low';
```

### Evidence Calibration (v2.1)

```typescript
interface EvidenceCalibration {
    // 6-Class Classification
    classification: ClassificationClass;
    classificationConfidence: number;     // 0-100%
    criteriaMet: string[];
    criteriaFailed: string[];
    
    // Reachability Analysis
    reachability: ReachabilityStatus;
    executionPath?: ExecutionPath[];
    crossContractPrereqs?: CrossContractPrereq[];
    blockingRequirement?: BlockingRequirement | null;
    
    // Disproof Analysis
    disproofResult: FinalVerdictType | null;
    disproofConfidence: number;           // 0-100%
    disproofStrategiesAttempted: DisproofStrategy[];
    
    // Multi-Dimensional Confidence
    confidenceBreakdown: {
        overall: number;                  // 0-100 composite
        evidenceStrength: number;         // 0-100
        reachabilityConfidence: number;   // 0-100
        impactConfidence: number;         // 0-100
        falsePositiveRisk: number;        // 0-100 (higher = more likely FP)
    };
    remainingUnknowns: UnknownFactor[];
    
    // Proof Requirements (9-criteria)
    proofRequirements: {
        met: number;
        total: number;                    // 9
        status: ProofStatus;
        requirements: ProofCriterion[];
    };
    
    // Final Verdict
    finalVerdict: FinalVerdictType;
    recommendedAction: RecommendedAction;
}

type ReachabilityStatus = 'reachable' | 'unreachable' | 'unknown';

interface ExecutionPath {
    stepNumber: number;
    contract: string;
    function: string;
    callType: 'internal' | 'external' | 'delegatecall';
    stateReads?: string[];
    stateWrites?: string[];
}
```

---

## 7. Phase 4 Output: Fuzz Results

```typescript
interface FuzzResult {
    campaignRun: boolean;
    violationsFound: number;
    properties: FuzzProperty[];
    realisticFindings: FuzzFinding[];          // Passed realism check
    
    // v2.0: Disproof engine results
    disproofResults: FuzzDisproofResult[];
    
    // v2.0: Classification results
    classifications: FuzzClassification[];
}

interface FuzzProperty {
    propertyId: string;                      // Format: `INV_{id}` or `ADV_{name}`
    violated: boolean;
    reproducible: boolean;
}

interface FuzzFinding {
    id: string;
    propertyViolated: string;
    vulnerableFunctions: string[];
    estimatedCapitalNeeded?: number;          // In millions USD
}

interface FuzzDisproofResult {
    findingId: string;
    disproofResult: 'DISPROVED' | 'NOT_DISPROVED' | 'CANNOT_DETERMINE';
    disproofEvidence: DisproofEvidenceItem[];
    residualRisk: ResidualRisk;
}

type ResidualRisk = 'low' | 'medium' | 'medium-high' | 'high' | 'unknown';

interface FuzzClassification {
    findingId: string;
    class: ClassificationClass;              // Six-class system
    confidence: number;                      // 0-100%
    criteriaMet: string[];
    criteriaFailed: string[];
}
```

### Realism Check Verdict (BLOCK GATE #3)

```typescript
interface RealismCheckResult {
    verdict: RealismVerdict;
    reason: string;
    keepForReview: boolean;                  // BLOCK GATE: Keep for manual review
    proceedToForkTest?: boolean;
}

type RealismVerdict =
    | 'realistic'                // Achievable on mainnet
    | 'unrealistic'              // Requires impossible state
    | 'operational_error'        // Requires trusted role action
    | 'impractical';             // Requires excessive capital
```

---

## 8. Phase 5 Output: Fork Test Results

```typescript
interface ForkTestResult {
    smokeTest: SmokeTestResult;
    deepTest: DeepForkTestResult;
}

interface SmokeTestResult {
    passed: boolean;
    error: string | null;
    contractsDeployed: string[];
    basicOperations: BasicOperation[];
}

interface BasicOperation {
    operation: 'deploy' | 'read_state' | 'call_target_function';
    success: boolean;
}

interface DeepForkTestResult {
    success: boolean;
    totalIterations: number;
    results: IterationResult[];
    bestResult: BestIterationResult | null;
    finalVerdict: ForkFinalVerdict;
}

type ForkFinalVerdict =
    | 'CONFIRMED'                // Exploit works on fork
    | 'PROBABLE'                 // Strong evidence, minor issues
    | 'DEAD'                     // Proven not exploitable
    | 'INCONCLUSIVE';            // Need more investigation

interface IterationResult {
    iteration: number;
    exploitAttempt: string;
    txHash: string;
    success: boolean;
    reverted: boolean;
    revertReason?: string;
    gasUsed: number;
    
    // Trackator visualization analysis
    trackatorAnalysis: TrackatorForkAnalysis;
    
    // Hacker notes
    hackerNotes: string;
    
    // Modifications for next attempt
    modifications: ModificationSuggestion[];
    
    // Iteration verdict
    verdict?: 'CONFIRMED' | 'DEAD_END' | 'CONTINUE';
}

interface TrackatorForkAnalysis {
    stateDiff: StateDiff;
    alertsTriggered: AlertTrigger[];
    oracleImpact: OracleImpact;
    invariantViolations: InvariantViolation[];
}

interface StateDiff {
    before: Record<string, any>;
    after: Record<string, any>;
}

interface AlertTrigger {
    id: string;
    name: string;
    severity: string;
}

interface OracleImpact {
    deviationPercent: number;
    threshold: number;
    status: 'NORMAL' | 'ANOMALY_DETECTED';
}

interface InvariantViolation {
    id: string;
    expression: string;
}

interface BestIterationResult {
    iteration: number;
    txHash: string;
    trackatorAnalysis: TrackatorForkAnalysis;
    verdict: string;
}

interface ModificationSuggestion {
    type: ModificationType;
    description: string;
    suggestion: string;
}

type ModificationType =
    | 'fix_revert'               // Address revert reason
    | 'increase_manipulation'    // Bigger flash loan, etc.
    | 'scale_position'           // Larger attack size
    | 'add_precondition'         // Missing setup transactions
    | 'pivot_attack'             // Try different vector
    | 'adjust_timing'            // Change transaction ordering
    | 'modify_parameters';       // Adjust function inputs
```

---

## 9. Phase 6 Output: Final Report

```typescript
interface FinalReport {
    metadata: ReportMetadata;
    executiveSummary: ExecutiveSummary;
    findings: FindingsBySeverity;
    appendix: ReportAppendix;
}

interface ReportMetadata {
    protocol: string;
    date: string;                         // ISO timestamp
    version: string;                      // e.g., '2.1.0'
}

interface ExecutiveSummary {
    totalHypotheses: number;
    confirmedCount: number;
    probableCount: number;
    leadsCount: number;
    discardedCount: number;
    truePositiveRate: number;              // Estimated percentage
}

interface FindingsBySeverity {
    critical: Finding[];
    high: Finding[];
    medium: Finding[];
    leads: LeadFinding[];
}

interface Finding {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: 'CONFIRMED' | 'PROBABLE';
    category: string;                      // Bug class
    estimatedImpactUsd: number;
    
    // Discovery info
    phaseDetected: number;
    discoverySource: 'pattern-match' | 'creative-attack' | 'fuzz' | 'fork';
    matchedPattern?: string;
    
    // Technical details
    vulnerableFunctions: Array<{ contract: string; function: string; line?: number }>;
    rootCause: string;
    
    // Evidence
    trackatorEvidence: {
        stateDiff?: StateDiff;
        alertsTriggered?: AlertTrigger[];
        invariantViolations?: InvariantViolation[];
    };
    
    // Kill chain
    killChain: string[];
    
    // Execution summary
    executionTraceSummary: string;
    
    // Fork proof
    forkProof?: {
        txHash: string;
        forkBlock: number;
        gasUsed: number;
        attackerProfit: string;
    };
    
    // Economic assessment
    economicAssessment: {
        capitalRequired: string;
        gasCost: string;
        estimatedProfit: string;
        feasibility: 'HIGH' | 'MEDIUM' | 'LOW';
    };
    
    // Recommendation
    recommendation: string;
    
    // Confidence
    confidenceScore: number;               // 0-1
    tier: 'CONFIRMED' | 'PROBABLE' | 'LEAD' | 'DISCARDED';
}

interface LeadFinding {
    id: string;
    title: string;
    briefDescription: string;
    whyInteresting: string;
    suggestedInvestigation: string;
}

interface ReportAppendix {
    discardedSummary: DiscardedSummary[];
    trackatorContext: ProtocolContext;
    methodology: MethodologyNote[];
}

interface DiscardedSummary {
    count: number;
    reason: DiscardReason;
}

type DiscardReason =
    | 'operational-error'          // Trusted role action
    | 'design-choice'              // Intentional behavior
    | 'unreachable'                // Proven by trace
    | 'unrealistic-state'          // Fuzz artifact
    | 'false-positive'             // Disproven
    | 'by-design';                 // Security trade-off

interface MethodologyNote {
    topic: string;
    note: string;
}
```

---

## 10. Classification Classes (6-Class System)

From Evidence Validator (Fix D integration).

| Class | Description | Action | Report Tier |
|-------|-------------|--------|-------------|
| `proven-property` | Code works as designed, intentional behavior | Note in methodology | Appendix |
| `potential-bug` | Likely bug but needs more evidence | Report with caveats | P2/P3 |
| `reachable-bug` | Confirmed reachable vulnerability | Report as P0/P1 | P0/P1 |
| `false-positive` | Matches pattern but not exploitable | Discard with docs | Discarded |
| `by-design` | Looks like bug but intentional trade-off | Note only | Appendix |
| `insufficient-evidence` | Cannot determine with available data | Queue for review | Lead |

### Classification Decision Matrix

| Evidence Strength | Reachable? | Has Guard? | → Class |
|-------------------|------------|------------|---------|
| High | Yes | No | `reachable-bug` |
| High | Unknown | No | `potential-bug` |
| Medium | Yes | Partial | `potential-bug` |
| Low | Any | Yes | `insufficient-evidence` |
| High | No | N/A | `false-positive` |
| Any | N/A | Design doc exists | `by-design` |
| Any | N/A | Working correctly | `proven-property` |

---

## 11. Verdict States & Status Values

### Hypothesis Lifecycle States

```
PENDING → FILTERED → MATCHED → TESTED → CONFIRMED/DEAD
                ↓         ↓
           DISCARDED   LEAD
```

### Verdict Enumerations

#### Intent Verdict (Phase 1)
| Verdict | Meaning |
|---------|---------|
| `keep` | Genuine anomaly |
| `downgrade_to_info` | Known assumption, low severity |
| `discard` | Operational/design |
| `keep_with_note` | Exploitable design choice |

#### Reachability Verdict (Phase 2 - BLOCK GATE)
| Verdict | Meaning |
|---------|---------|
| `confirmed_pattern` | All preconditions met |
| `probable` | Most met, some unknown |
| `lead` | Interesting, needs review |
| `dead` | Proven unreachable |

#### Realism Verdict (Phase 4 - BLOCK GATE)
| Verdict | Meaning |
|---------|---------|
| `realistic` | Achievable on mainnet |
| `unrealistic` | Impossible state required |
| `operational_error` | Needs trusted role |
| `impractical` | Too much capital needed |

#### Fork Verdict (Phase 5)
| Verdict | Meaning |
|---------|---------|
| `CONFIRMED` | Exploit works |
| `PROBABLE` | Strong evidence |
| `DEAD` | Not exploitable |
| `INCONCLUSIVE` | Need more work |

#### Final Verdict (Phase 6 / Evidence Validator)
| Verdict | Action |
|---------|--------|
| `confirmed-vulnerability` | Immediate fix |
| `potential-vulnerability` | Short-term investigation |
| `false-positive` | Dismiss |
| `by-design` | Accept risk |
| `cannot-determine` | Escalate to auditor |
| `deferred` | Defer decision |

### Confidence Score Tiers

| Score Range | Tier | Reporting |
|-------------|------|-----------|
| >= 0.70 (70%) | `CONFIRMED` | P0/P1 findings |
| >= 0.40 (40%) | `PROBABLE` | P2 findings |
| >= 0.20 (20%) | `LEAD` | Manual review queue |
| < 0.20 (20%) | `DISCARDED` | Appendix/discarded |

### Confidence Score Weights

| Factor | Weight | Source |
|--------|--------|--------|
| Pattern match strength | 20% | Phase 2 |
| Trace completeness | 20% | Phase 3 |
| Fuzz validation | 15% | Phase 4 |
| Fork success | **35%** | Phase 5 (most important) |
| Economic feasibility | 10% | Assessment |

---

## Quick Reference: Field Location Index

| Field Name | Location | Type |
|------------|----------|------|
| `id` | Hypothesis | string |
| `priorityScore` | Hypothesis | number |
| `status` | Hypothesis | enum |
| `intentFilterResult.verdict` | Phase 1 output | enum |
| `patternMatches[]` | Phase 2 output | PatternMatch[] |
| `reachabilityResult.verdict` | Phase 2 output | enum |
| `creativeFindings[]` | Phase 3 output | CreativeFinding[] |
| `assumptionBreaks[]` | Phase 3 output | AssumptionBreak[] |
| `couplingAttacks[]` | Phase 3 output (v2.0) | CouplingAttack[] |
| `desyncAttacks[]` | Phase 3 output (v2.0) | DesyncAttack[] |
| `executionTrace` | Phase 3 output | ExecutionTrace |
| `traceConclusion.survives` | Phase 3 output | boolean |
| `pluginRouting` | Phase 3 output (v2.1) | PluginRoutingResult |
| `evidenceCalibration` | Phase 3 output (v2.1) | EvidenceCalibration |
| `fuzzResults` | Phase 4 output | FuzzResult |
| `forkTestResult.deepTest.finalVerdict` | Phase 5 output | enum |

---

*Reference file generated for Redteam-Trackator v2.1*
*Last updated: Based on SKILL.md data structure definitions*
