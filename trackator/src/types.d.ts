export type ProtocolStructure = SolidityContract;
export type ParsedContract = SolidityContract;
export type XRayReport = XRayOutput;
export type BreakdownReport = BreakdownOutput;
export type Parameter = VariableDecl;
export type UsingForDef = UsingForDecl;
export type DecodedEvent = DecodedLogEvent;
export type GasBreakdown = GasBreakdownItem[];
export type AlertResult = Alert;
export interface ExportOptions {
    format: 'json' | 'md' | 'html' | 'all';
    outputDir: string;
    outputPath?: string;
    includeRaw?: boolean;
    includeMermaid?: boolean;
    theme?: 'light' | 'dark' | 'auto';
}
export interface StateInventory {
    contractName: string;
    variables: StorageVariableInfo[];
    totalSlotsUsed: number;
    totalVariables?: number;
    valueBearing?: number;
    byContract?: Map<string, StateInventory>;
    filter?(predicate: (v: StorageVariableInfo) => boolean): StateInventory;
}
export interface StorageVariableInfo {
    variable: StateVariable;
    computedSlot: number;
    computedOffset: number;
    typeSize: number;
    encoding: 'packed' | 'single';
}
export interface MappingSlotInfo {
    mappingVar: string;
    keyType: string;
    valueType: string;
    slot: number;
    hashPath?: string;
}
export interface FunctionRegistry {
    entries: RegisteredFunction[];
    totalFunctions?: number;
    byContract: Map<string, RegisteredFunction[]>;
    byCategory: Map<string, RegisteredFunction[]>;
}
export interface RegisteredFunction {
    id: string;
    contract: string;
    signature: string;
    name: string;
    function?: string;
    category: FunctionCategory;
    accessControl: AccessControlEntry;
    risk: RiskAssessment;
    stateReads: string[];
    stateWrites: string[];
    externalCalls: string[];
    stateImpact?: string;
    lineDeclared: number;
}
export type FunctionCategory = 'core-logic' | 'access-control' | 'admin' | 'oracle' | 'math' | 'token-operation' | 'emergency' | 'utility' | 'constructor' | 'callback';
export interface AccessControlEntry {
    level: AccessControlLevel;
    rolesRequired: string[];
    modifiers: string[];
    ownerOnly: boolean;
    visibility?: string;
    restrictions?: string[];
    length: number;
}
export type AccessControlLevel = 'public' | 'restricted' | 'role-based' | 'admin-only' | 'internal';
export interface RiskAssessment {
    score: number;
    overall: 'critical' | 'high' | 'medium' | 'low' | 'safe';
    factors: RiskFactor[];
}
export interface RiskFactor {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    location?: string;
}
export interface ModifierMap {
    [modifierName: string]: {
        appliedTo: string[];
        parameters: string[];
        conditions: string[];
    };
}
export interface EventCatalog {
    [eventName: string]: EventDef & {
        emittedByFunctions: string[];
    };
}
export interface AccessControlMatrix {
    [functionSignature: string]: {
        roles: string[];
        modifiers: string[];
        visibility: string;
        restrictions: string[];
    };
}
export interface RoleDefinition {
    roleName: string;
    adminRole: string;
    members: string[];
    capabilities: string[];
}
export interface ExternalCallSummary {
    target: string;
    function: string;
    valueSent: boolean;
    trustAssumption: string;
    riskLevel: 'critical' | 'high' | 'medium' | 'low';
    severity?: AlertSeverity;
    line?: number;
    type?: string;
    contract?: string;
    contractName?: string;
    description?: string;
}
export interface DangerousPattern {
    id: string;
    name: string;
    category: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    patternType?: string;
    description: string;
    location: {
        file: string;
        line: number;
    };
    recommendation: string;
}
export interface AnomalyPattern {
    id: string;
    name: string;
    detectionLogic: AlertCondition;
    severity: AlertSeverity;
    category: AlertCategory;
    description: string;
}
export type CallGraph = {
    nodes: Map<string, CallGraphNode>;
    edges: CallEdge[];
    entryPoints: CallGraphNode[];
    cycles: CyclePath[];
};
export interface CyclePath {
    path: string[];
    length: number;
    involvesExternalCall: boolean;
}
export interface VariableChange {
    variable: string;
    contract: string;
    beforeValue: any;
    afterValue: any;
    changeType: 'set' | 'cleared' | 'modified' | 'unchanged';
    slot?: string;
    deltaPercent?: number;
    value?: any;
}
export interface SolidityContract {
    name: string;
    sourcePath: string;
    abstract: boolean;
    inherited: string[];
    inherits?: string[];
    imports: string[];
    stateVariables: StateVariable[];
    functions: FunctionDef[];
    events: EventDef[];
    modifiers: ModifierDef[];
    structs: StructDef[];
    enums: EnumDef[];
    errors: ErrorDef[];
    usingFor: UsingForDecl[];
    lineCount: number;
    kind?: 'contract' | 'interface' | 'library' | 'abstract';
    contracts?: SolidityContract[];
    accessControl?: AccessControlMatrix;
    stateInventory?: StateInventory;
    functionRegistry?: FunctionRegistry;
    externalCallMap?: Record<string, ExternalCallSummary[]>;
}
export interface StateVariable {
    name: string;
    type: string;
    visibility: 'public' | 'private' | 'internal' | 'constant' | 'immutable';
    mutability: string;
    slot?: number;
    offset?: number;
    overridden: boolean;
    initialized: boolean;
    isConstant?: boolean;
    isStateVar?: boolean;
    defaultValue?: string;
    comments?: string;
}
export interface FunctionDef {
    name: string;
    kind: 'function' | 'constructor' | 'fallback' | 'receive' | 'modifier';
    visibility: 'public' | 'external' | 'internal' | 'private';
    stateMutability: 'view' | 'pure' | 'payable' | 'nonpayable';
    virtual: boolean;
    override: boolean;
    parameters: VariableDecl[];
    returnParameters: VariableDecl[];
    modifiers: string[];
    body: FunctionBodyInfo;
    calls: string[];
    externalCalls?: ExternalCallInfo[];
    eventsEmitted: string[];
    stateVariablesRead: string[];
    stateVariablesWritten: string[];
    lineStart: number;
    lineEnd: number;
    complexity: number;
}
export interface ExternalCallInfo {
    target: string;
    function: string;
    functionName?: string;
    valueSent: boolean;
    trustAssumption: string;
    contractName?: string;
}
export interface VariableDecl {
    name: string;
    type: string;
    indexed?: boolean;
}
export interface FunctionBodyInfo {
    statements: number;
    hasRequire: boolean;
    hasRevert: boolean;
    hasExternalCall: boolean;
    hasLoop: boolean;
    hasTransfer: boolean;
    hasDelegateCall: boolean;
    ceiPattern: CEIPattern;
}
export type CEIPattern = 'valid' | 'violated' | 'unknown' | 'not-applicable';
export interface EventDef {
    name: string;
    parameters: VariableDecl[];
    anonymous: boolean;
    emittedBy: string[];
    lineDeclared: number;
}
export interface ModifierDef {
    name: string;
    parameters: VariableDecl[];
    visibility?: string;
    appliedTo: string[];
    lineDeclared: number;
}
export interface StructDef {
    name: string;
    members: VariableDecl[];
    storageLayout?: StorageSlotInfo[];
}
export interface EnumDef {
    name: string;
    members: string[];
}
export interface ErrorDef {
    name: string;
    parameters: VariableDecl[];
}
export interface UsingForDecl {
    type: string;
    library: string[];
}
export interface StorageSlotInfo {
    member: string;
    type: string;
    slot: number;
    offset: number;
    bytes: number;
}
export interface CallGraphNode {
    contract: string;
    function: string;
    from?: {
        contract: string;
        function: string;
    };
    calls: CallEdge[];
    calledBy: CallEdge[];
    visibility: string;
    isExternal: boolean;
    isEntry: boolean;
}
export interface CallEdge {
    from: {
        contract: string;
        function: string;
    };
    to: {
        contract: string;
        function: string;
    };
    type: 'internal' | 'external' | 'delegatecall' | 'staticcall' | 'value-transfer';
    valueFlow?: ValueFlowInfo;
    condition?: string;
}
export interface ValueFlowInfo {
    ethSent: boolean;
    tokenTransfers: TokenTransferInfo[];
    amountSource: string;
}
export interface TokenTransferInfo {
    token: string;
    direction: 'send' | 'receive' | 'mint' | 'burn';
    amountExpr: string;
}
export interface XRayOutput {
    protocolType: ProtocolType;
    protocolClassification?: string;
    threatModel: ThreatModel;
    invariants: Invariant[];
    trustAssumptions: TrustAssumption[];
    adversaryProfiles: AdversaryProfile[];
    attackVectors: AttackVector[];
    attackSurfaces?: AttackSurface[];
    generatedAt: string;
}
export interface AttackSurface {
    id: string;
    name: string;
    type: string;
    description: string;
    vectors: string[];
    severity: 'critical' | 'high' | 'medium' | 'low';
    riskLevel?: AlertSeverity;
}
export type ProtocolType = 'lending' | 'dex' | 'bridge' | 'nft' | 'dao' | 'payment' | 'privacy' | 'cdp' | 'lsd' | 'restaking' | 'perp-dex' | 'yield' | 'vault' | 'unknown' | string;
export interface ThreatModel {
    assetsAtRisk: AssetInfo[];
    entryPoints: EntryPoint[];
    privilegeBoundaries: PrivilegeBoundary[];
    keyActors: ActorRole[];
    primaryAdversaries?: AdversaryProfile[];
    attackSurfaces?: AttackSurface[];
}
export interface AssetInfo {
    type: 'eth' | 'erc20' | 'erc721' | 'erc1155' | 'lp-tokens' | 'unknown';
    name: string;
    location: string;
    estimatedValue?: string;
    liquiditySource?: string;
}
export interface EntryPoint {
    name: string;
    contract: string;
    access: 'anyone' | 'whitelisted' | 'role-based' | 'owner-only' | 'timelock';
    criticality: 'critical' | 'high' | 'medium' | 'low';
    description: string;
}
export interface PrivilegeBoundary {
    from: string;
    to: string;
    mechanism: 'access-control' | 'timelock' | 'multisig' | 'governance' | 'none';
    strength: 'strong' | 'medium' | 'weak' | 'nonexistent';
}
export interface ActorRole {
    role: string;
    capabilities: string[];
    constraints: string[];
}
export interface Invariant {
    id: string;
    category: 'accounting' | 'bounds' | 'ordering' | 'state-machine' | 'oracle' | 'permission';
    protocolType: ProtocolType;
    template: string;
    instance: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    checkable: boolean;
    expression?: string;
    relatedStateVars: string[];
    relatedFunctions: string[];
    relayFunctions?: string[];
    description?: string;
    triggerCondition?: AlertCondition;
}
export interface TrustAssumption {
    id: string;
    category: 'oracle' | 'price-feed' | 'external-contract' | 'governance' | 'admin' | 'math' | 'time';
    assumption: string;
    ifViolated: string;
    mitigation?: string;
    confidence: 'high' | 'medium' | 'low';
    severity?: AlertSeverity;
}
export interface AdversaryProfile {
    id: string;
    type: 'external' | 'insider' | 'governance' | 'oracle-manipulator' | 'liquidator' | 'mev-bot' | 'attacker';
    capabilities: string[];
    goals: string[];
    constraints: string[];
    likelyAttacks: string[];
}
export interface AttackVector {
    id: string;
    name: string;
    category: string;
    prerequisite: string[];
    impact: string;
    likelihood: 'certain' | 'likely' | 'possible' | 'unlikely' | 'rare' | 'depends-on-setup';
    severity: 'critical' | 'high' | 'medium' | 'low';
    relatedInvariants: string[];
    detectionMethod?: string;
}
export interface BreakdownOutput {
    components: ComponentAnalysis[];
    coreComponents?: ComponentAnalysis[];
    moneyFlows: MoneyFlow[];
    numericBehaviors: NumericBehavior[];
    stateAuthority: StateAuthorityMap[];
    expectedBehaviors: ExpectedBehavior[];
    rolePermissions?: RolePermissionMap[];
    generatedAt: string;
}
export interface RolePermissionMap {
    role: string;
    permissions: string[];
    constraints: string[];
    canEscalate: boolean;
    damagePotential?: 'critical' | 'high' | 'medium' | 'low';
}
export interface ComponentAnalysis {
    name: string;
    type: 'core' | 'peripheral' | 'integration' | 'utility';
    responsibility: string;
    dependencies: string[];
    stateOwned: string[];
    interfaces: InterfaceInfo[];
    riskLevel: 'critical' | 'high' | 'medium' | 'low';
}
export interface InterfaceInfo {
    name: string;
    inputs: VariableDecl[];
    outputs: VariableDecl[];
    accessControl: string;
    sideEffects: string[];
}
export interface MoneyFlow {
    id: string;
    name: string;
    trigger: string;
    steps: MoneyFlowStep[];
    conditions: string[];
    valueRange?: {
        min: string;
        max: string;
    };
    edgeCases: string[];
}
export interface MoneyFlowStep {
    order: number;
    action: string;
    from: string;
    to: string;
    asset: string;
    amount: string;
    condition?: string;
}
export interface NumericBehavior {
    variable: string;
    contract: string;
    expectedRange: {
        min: number;
        max: number;
    };
    unit: string;
    normalPattern: string;
    anomalyThreshold: number;
    examples: NumericExample[];
}
export interface NumericExample {
    scenario: string;
    input: string;
    expectedOutput: string;
    explanation: string;
}
export interface StateAuthorityMap {
    variable: string;
    contract: string;
    whoCanWrite: string[];
    howItChanges: string;
    constraints: string[];
    validationPresent: boolean;
}
export interface ExpectedBehavior {
    functionSig: string;
    preConditions: string[];
    postConditions: string[];
    stateChanges: StateChangeExpectation[];
    revertConditions: string[];
    gasEstimate?: string;
    scenario?: string;
    expectedOutcome?: string;
    anomaliesToDetect?: AnomalyPattern[];
    stepByStep?: string[];
}
export interface StateChangeExpectation {
    variable: string;
    direction: 'increase' | 'decrease' | 'set' | 'unchanged';
    bounds?: {
        min: string;
        max: string;
    };
}
export interface AlertRule {
    id: string;
    name: string;
    tier: 'tier1' | 'tier2' | 'tier3';
    category: AlertCategory;
    severity: AlertSeverity;
    condition: AlertCondition;
    description: string;
    mitigation?: string;
    remediation?: string;
    trigger?: string;
    source: 'xray' | 'breakdown' | 'runtime' | 'custom' | string;
    enabled: boolean;
    contract?: string;
}
export type AlertCategory = 'reentrancy' | 'oracle-manipulation' | 'access-control' | 'access-breach' | 'accounting' | 'integer-overflow' | 'logic-error' | 'flash-loan' | 'price-deviation' | 'state-corruption' | 'denial-of-service' | 'front-running' | 'mev' | 'share-inflation' | 'liquidation' | 'slippage' | 'gas-griefing' | 'timestamp-dependency' | 'external-call-failure' | 'unexpected-value' | 'invariant-violation' | 'dangerous-pattern' | 'value-drift' | 'anomaly' | 'custom';
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'informational';
export interface AlertCondition {
    type: 'threshold' | 'pattern' | 'absence' | 'presence' | 'sequence' | 'custom';
    field: string;
    operator: 'gt' | 'lt' | 'eq' | 'neq' | 'gte' | 'lte' | 'contains' | 'not-contains' | 'changed' | 'not-changed' | 'in-sequence' | 'not-in-sequence';
    value?: string | number | boolean;
    secondaryField?: string;
    window?: number;
}
export interface FoundryTrace {
    trace: TraceStep[];
    steps?: TraceStep[];
    transaction: TransactionInfo;
    receipts: Receipt[];
    logs: LogEntry[];
    events?: DecodedLogEvent[];
    gasInfo: GasInfo;
    gasUsage?: GasInfo;
    timestamp: number;
    blockNumber: number;
    stateDiffs?: StateDiff[];
}
export interface TraceStep {
    stepIndex: number;
    depth: number;
    address: string;
    contractName?: string;
    contractCodeHash?: string;
    input: string;
    inputs?: string[];
    output?: string;
    status: 'success' | 'revert' | 'error';
    success?: boolean;
    gasUsed: number;
    gasRemaining: number;
    opcodes: OpcodeExecution[];
    memoryBefore?: MemorySnapshot;
    memoryAfter?: MemorySnapshot;
    storageBefore?: StorageSnapshot;
    storageAfter?: StorageSnapshot;
    stateReads?: StateReadInfo[];
    stateWrites?: StateWriteInfo[];
    subcalls?: TraceStep[];
    error?: string;
    replayData?: ReplayDataPoint[];
    function?: FunctionCallInfo;
}
export interface FunctionCallInfo {
    name: string;
    signature: string;
    contract: string;
    isExternal: boolean;
    valueSent: bigint;
}
export interface StateReadInfo {
    slot: string;
    value: string;
    variable?: string;
}
export interface StateWriteInfo {
    slot: string;
    beforeValue: string;
    afterValue: string;
    variable?: string;
    value?: string;
}
export interface OpcodeExecution {
    pc: number;
    opcode: string;
    pushData?: string;
    stackBefore: string[];
    stackAfter: string[];
    memoryOffset?: number;
    gasCost: number;
    depth: number;
}
export interface MemorySnapshot {
    data: string;
    size: number;
}
export interface StorageSnapshot {
    slots: Record<string, string>;
}
export interface TransactionInfo {
    from: string;
    to: string;
    value: string;
    input: string;
    gas: number;
    gasPrice: string;
    nonce: number;
    chainId: number;
    type: number;
}
export interface Receipt {
    transactionHash: string;
    transactionIndex: number;
    blockHash: string;
    blockNumber: number;
    from: string;
    to: string;
    cumulativeGasUsed: number;
    gasUsed: number;
    contractAddress?: string;
    status: number;
    logs: LogEntry[];
    logsBloom: string;
}
export interface LogEntry {
    address: string;
    topics: string[];
    data: string;
    logIndex: number;
    transactionIndex: number;
    blockNumber: number;
    transactionHash: string;
    decoded?: DecodedLogEvent;
}
export interface DecodedLogEvent {
    name: string;
    signature: string;
    args: {
        [key: string]: any;
    };
    contract: string;
}
export interface GasInfo {
    gasLimit: number;
    gasUsed: number;
    effectiveGasPrice: number;
    refund: number;
    breakdown: GasBreakdownItem[];
}
export interface GasBreakdownItem {
    category: 'calldata' | 'execution' | 'storage' | 'memory' | 'refund' | 'other';
    amount: number;
    percentage: number;
}
export interface StateDiff {
    address: string;
    contract: string;
    contractName: string;
    stepIndex?: number;
    slotChanges: SlotChange[];
    balanceChange: BalanceChange;
    codeChanged: boolean;
    nonceChanged: boolean;
}
export interface SlotChange {
    slot: string;
    slotLabel?: string;
    beforeValue: string;
    afterValue: string;
    decodedBefore?: any;
    decodedAfter?: any;
    changeType: 'set' | 'cleared' | 'modified' | 'unchanged';
    deviation?: number;
    anomaly?: AnomalyInfo;
}
export interface BalanceChange {
    eth: {
        before: string;
        after: string;
        delta: string;
    };
    tokens: TokenBalanceChange[];
}
export interface TokenBalanceChange {
    token: string;
    symbol?: string;
    before: string;
    after: string;
    delta: string;
}
export interface AnomalyInfo {
    detected: boolean;
    ruleId?: string;
    ruleName?: string;
    severity: AlertSeverity;
    message: string;
    context: {
        [key: string]: any;
    };
    suggestion?: string;
}
export interface OracleAnalysis {
    pricesObserved: PriceObservation[];
    deviations: PriceDeviation[];
    twapAnalysis?: TWAPAnalysis;
    manipulationIndicators: ManipulationIndicator[];
}
export interface PriceObservation {
    oracle: string;
    asset: string;
    price: number;
    timestamp: number;
    source: 'spot' | 'twap' | 'chainlink' | 'uniswap' | 'custom';
    confidence: 'high' | 'medium' | 'low';
    slotRead?: string;
    functionCalled?: string;
}
export interface PriceDeviation {
    oracle: string;
    asset: string;
    observedPrice: number;
    expectedPrice: number;
    deviationPercent: number;
    thresholdExceeded: boolean;
    thresholdPercent: number;
    timeWindow: number;
}
export interface TWAPAnalysis {
    period: number;
    avgPrice: number;
    currentPrice: number;
    deviation: number;
    sampleCount: number;
    firstBlock: number;
    lastBlock: number;
}
export interface ManipulationIndicator {
    type: 'flash-loan-price-swing' | 'sandwich-attack' | 'liquidation-cascade' | 'oracle-flip' | 'stale-price';
    confidence: number;
    evidence: string[];
    affectedFunctions: string[];
}
export interface RoleJourney {
    actor: string;
    role: string;
    actions: RoleAction[];
    permissionsChecked: PermissionCheck[];
    privilegesEscalated: PrivilegeEscalation[];
    finalState: string;
}
export interface RoleAction {
    order: number;
    function: string;
    contract: string;
    success: boolean;
    stateImpact: string[];
}
export interface PermissionCheck {
    function: string;
    required: string;
    hadPermission: boolean;
    bypassed: boolean;
    bypassMethod?: string;
}
export interface PrivilegeEscalation {
    from: string;
    to: string;
    method: string;
    contract: string;
    legitimate: boolean;
}
export interface Alert {
    id: string;
    ruleId: string;
    ruleName: string;
    severity: AlertSeverity;
    category: AlertCategory;
    title: string;
    description: string;
    location: {
        file: string;
        line: number;
        contract: string;
        function: string;
    };
    evidence: EvidenceItem[];
    suggestion: string;
    falsePositiveRisk: 'low' | 'medium' | 'high';
    timestamp: number;
    stepIndex: number;
    suppressable: boolean;
}
export interface EvidenceItem {
    type: 'state-diff' | 'log-event' | 'call-stack' | 'price-deviation' | 'gas-anomaly' | 'timing' | 'custom';
    description: string;
    data: any;
    reference?: string;
}
export interface TrackatorOutput {
    runId: string;
    command: 'init' | 'enrich' | 'analyze';
    timestamp: string;
    duration: number;
    contracts?: SolidityContract[];
    callGraph?: CallGraphNode[];
    mermaidDiagrams?: MermaidDiagram[];
    valueFlows?: any[];
    xrayOutput?: XRayOutput;
    breakdownOutput?: BreakdownOutput;
    alertRules?: AlertRule[];
    trace?: FoundryTrace;
    stateDiffs?: StateDiff[];
    oracleAnalysis?: OracleAnalysis;
    roleJourneys?: RoleJourney[];
    roleExtraction?: RoleExtractionResult;
    alerts?: Alert[];
    summary?: AnalysisSummary;
}
export interface MermaidDiagram {
    type: 'sequenceDiagram' | 'flowchart' | 'classDiagram' | 'stateDiagram' | 'erDiagram';
    title: string;
    code: string;
    description: string;
}
export type TrustLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
export interface ProtocolRole {
    id: string;
    name: string;
    category: 'trusted' | 'non-trusted';
    addressSource?: string;
    addressType?: 'state-var' | 'function-return' | 'immutable' | 'msg-sender' | 'unknown';
    roleConstant?: string;
    trustLevel: TrustLevel;
    trustReasoning: string;
    capabilities: RoleCapability[];
    constraints: string[];
    sourceContract: string;
    modifierName?: string;
    relatedFunctions: string[];
    canEscalateTo?: string[];
    assignedBy?: string;
    riskIfCompromised: string;
    isSinglePointOfFailure: boolean;
}
export interface RoleCapability {
    functionSignature: string;
    contractName: string;
    category: 'admin' | 'financial' | 'access-control' | 'operational' | 'emergency' | 'unknown';
    impact: 'critical' | 'high' | 'medium' | 'low';
    description: string;
}
export interface RoleExtractionResult {
    extractedAt: string;
    totalRoles: number;
    trustedRoles: ProtocolRole[];
    nonTrustedRoles: ProtocolRole[];
    roleHierarchy: RoleRelationship[];
    summary: RoleSummary;
}
export interface RoleRelationship {
    fromRole: string;
    toRole: string;
    relationshipType: 'assigns-to' | 'revokes-from' | 'reports-to' | 'can-escalate-to' | 'overrides';
    mechanism: string;
}
export interface RoleSummary {
    trustedCount: number;
    nonTrustedCount: number;
    highTrustCount: number;
    singlePointsOfFailure: string[];
    publicFunctionCount: number;
    hasTimelock: boolean;
    hasMultisig: boolean;
}
export interface AnalysisSummary {
    totalSteps: number;
    totalContractsTouched: number;
    totalStorageSlotsChanged: number;
    totalValueMoved: string;
    alertCounts: {
        [severity: string]: number;
    };
    topAnomalies: AnomalyInfo[];
    gasEfficiency: {
        used: number;
        limit: number;
        percentage: number;
    };
    verdict: 'pass' | 'warning' | 'fail' | 'needs-review';
}
export interface ReplayDataPoint {
    stepIndex: number;
    timestamp: number;
    activeContract: string;
    activeFunction: string;
    stateSnapshot: Record<string, any>;
    callStack: string[];
    emittedEvents: DecodedLogEvent[];
    currentGas: number;
}
