// Trackator Core Types
// ===================

// Tier 1: Static Analysis Types
export interface ParsedContract {
  name: string;
  path: string;
  kind: 'contract' | 'interface' | 'library' | 'abstract';
  inherits: string[];
  imports: string[];
  stateVariables: StateVariable[];
  functions: FunctionDef[];
  modifiers: ModifierDef[];
  events: EventDef[];
  usingFor: UsingForDef[];
  errors: ErrorDef[];
}

export interface StateVariable {
  name: string;
  type: string;
  visibility: 'public' | 'private' | 'internal' | 'constant' | 'immutable';
  isConstant: boolean;
  isImmutable: boolean;
  isStateVar: boolean;
  slot?: number;
  offset?: number;
  defaultValue?: any;
}

export interface FunctionDef {
  name: string;
  kind: 'function' | 'constructor' | 'receive' | 'fallback' | 'modifier';
  visibility: 'public' | 'external' | 'internal' | 'private';
  stateMutability: 'pure' | 'view' | 'nonpayable' | 'payable';
  modifiers: string[];
  parameters: Parameter[];
  returnParameters: Parameter[];
  body: any; // AST node
  externalCalls: ExternalCall[];
  lineStart: number;
  lineEnd: number;
}

export interface ModifierDef {
  name: string;
  parameters: Parameter[];
  visibility: string;
  body: any;
}

export interface EventDef {
  name: string;
  parameters: Parameter[];
  anonymous: boolean;
}

export interface UsingForDef {
  libraryName: string;
  typeName?: string;
}

export interface ErrorDef {
  name: string;
  parameters: Parameter[];
}

export interface Parameter {
  name: string;
  type: string;
  indexed?: boolean;
  storageLocation?: string;
}

export interface ExternalCall {
  functionName: string;
  contractName: string;
  arguments: any[];
  line: number;
  isSendOrTransfer: boolean;
  isDelegateCall: boolean;
  isStaticCall: boolean;
}

// Protocol Structure (Tier 1 Output)
export interface ProtocolStructure {
  name: string;
  rootPath: string;
  contracts: ParsedContract[];
  inheritanceMap: Map<string, string[]>;
  importGraph: Map<string, string[]>;
  callGraph: CallGraphNode[];
  stateInventory: StateInventory;
  functionRegistry: FunctionRegistry;
  modifierMap: ModifierMap;
  eventCatalog: EventCatalog;
  accessControl: AccessControlMatrix;
  externalCallMap: ExternalCallSummary;
}

export interface CallGraphNode {
  from: string;
  to: string;
  function: string;
  type: 'internal' | 'external' | 'delegatecall' | 'send' | 'transfer';
  line: number;
}

export interface StateInventory {
  totalVariables: number;
  totalSlots: number;
  byContract: Map<string, StateVariable[]>;
  bySlot: Map<number, { contract: string; variable: string }[]>;
  valueBearing: StateVariable[]; // Variables that hold user fund/value
}

export interface FunctionRegistry {
  totalFunctions: number;
  byContract: Map<string, FunctionDef[]>;
  byVisibility: Map<string, FunctionDef[]>;
  byMutability: Map<string, FunctionDef[]>;
  externalFunctions: FunctionDef[];
}

export interface ModifierMap {
  totalModifiers: number;
  definitions: Map<string, ModifierDef>;
  applications: Map<string, string[]>; // modifier -> functions using it
}

export interface EventCatalog {
  totalEvents: number;
  byContract: Map<string, EventDef[]>;
}

export interface AccessControlMatrix {
  roles: RoleDefinition[];
  roleToFunctions: Map<string, string[]>;
  functionToRoles: Map<string, string[]>;
  unprotectedFunctions: string[];
}

export interface RoleDefinition {
  name: string;
  source: string; // e.g., "onlyOwner", "msg.sender == admin"
  functions: string[];
  trustLevel: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface ExternalCallSummary {
  totalCalls: number;
  byTarget: Map<string, ExternalCall[]>;
  bySource: Map<string, ExternalCall[]>;
  dangerousPatterns: DangerousPattern[];
}

export interface DangerousPattern {
  type: 'reentrancy' | 'tx-origin' | 'unchecked-call' | 'delegate-call' | 'selfdestruct';
  contract: string;
  function: string;
  line: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

// Tier 2: AI Enrichment Types
export interface XRayReport {
  protocolType: string;
  threatModel: ThreatModel;
  invariants: Invariant[];
  attackSurfaces: AttackSurface[];
  trustAssumptions: TrustAssumption[];
  protocolClassification: ProtocolClassification;
}

export interface ThreatModel {
  primaryAdversaries: Adversary[];
  attackPaths: AttackPath[];
  criticalAssets: CriticalAsset[];
}

export interface Adversary {
  type: string;
  motivation: string;
  capabilities: string[];
  likelihood: 'low' | 'medium' | 'high';
}

export interface AttackPath {
  id: string;
  name: string;
  steps: AttackStep[];
  prerequisites: string[];
  impact: 'low' | 'medium' | 'high' | 'critical';
  detectionDifficulty: 'easy' | 'medium' | 'hard';
}

export interface AttackStep {
  target: string;
  action: string;
  requirement: string;
}

export interface CriticalAsset {
  name: string;
  location: string;
  valueAtRisk: string;
  protectionMechanisms: string[];
}

export interface Invariant {
  id: string;
  category: 'accounting' | 'access-control' | 'ordering' | 'economic' | 'external' | 'protocol-stated';
  description: string;
  expression: string; // Pseudo-code or mathematical expression
  severity: 'critical' | 'high' | 'medium' | 'low';
  location?: string;
  relatedFunctions: string[];
  triggerCondition: string;
}

export interface AttackSurface {
  id: string;
  name: string;
  location: string;
  type: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  mitigations: string[];
  references: string[];
}

export interface TrustAssumption {
  id: string;
  assumption: string;
  category: 'oracle' | 'external-protocol' | 'admin' | 'user-behavior' | 'market' | 'other';
  ifViolated: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  validationStatus: 'validated' | 'assumed' | 'unchecked';
}

export interface ProtocolClassification {
  primaryType: string;
  secondaryTypes: string[];
  detectionSignals: string[];
  complexity: 'low' | 'medium' | 'high' | 'very-high';
}

export interface BreakdownReport {
  coreComponents: ComponentDeepDive[];
  userFlows: UserFlow[];
  moneyFlows: MoneyFlowDescription[];
  expectedBehaviors: ExpectedBehavior[];
  rolePermissions: RolePermission[];
}

export interface ComponentDeepDive {
  contract: string;
  purpose: string;
  keyStateVariables: StateVariable[];
  coreLogicWalkthrough: LogicStep[];
  stateTransitions: StateTransition[];
  externalDependencies: ExternalDependency[];
  trustAssumptions: string[];
}

export interface LogicStep {
  stepNumber: number;
  description: string;
  codeReference?: string;
  numericExample?: NumericExample;
}

export interface NumericExample {
  inputs: Record<string, any>;
  intermediateSteps: Record<string, any>[];
  outputs: Record<string, any>;
}

export interface StateTransition {
  trigger: string;
  preConditions: string[];
  stateChanges: StateChange[];
  postConditions: string[];
}

export interface StateChange {
  variable: string;
  from: string;
  to: string;
  description: string;
}

export interface ExternalDependency {
  target: string;
  purpose: string;
  expectedReturn: string;
  failureMode: string;
}

export interface UserFlow {
  name: string;
  type: 'happy-path' | 'borrow-lifecycle' | 'liquidation' | 'emergency' | 'custom';
  steps: FlowStep[];
  edgeCases: string[];
}

export interface FlowStep {
  actor: string;
  action: string;
  contract: string;
  function: string;
  effects: string[];
}

export interface MoneyFlowDescription {
  type: 'inflow' | 'outflow' | 'internal' | 'fee';
  source: string;
  destination: string;
  asset: string;
  conditions: string[];
  amountDetermination: string;
}

export interface ExpectedBehavior {
  scenario: string;
  preConditions: string[];
  stepByStep: BehaviorStep[];
  expectedOutcome: string;
  invariantChecks: string[];
  anomaliesToDetect: AnomalyPattern[];
}

export interface BehaviorStep {
  step: number;
  action: string;
  stateBefore: Record<string, any>;
  stateAfter: Record<string, any>;
  verification: string;
}

export interface AnomalyPattern {
  id: string;
  name: string;
  description: string;
  detectionLogic: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface RolePermission {
  role: string;
  functions: FunctionPermission[];
  damagePotential: string;
  constraints: string[];
  transferability: string;
}

export interface FunctionPermission {
  name: string;
  purpose: string;
  damageIfCompromised: string;
}

// Alert Rules (Generated from X-Ray + Breakdown)
export interface AlertRule {
  id: string;
  name: string;
  source: string; // e.g., "x-ray.md §Invariants"
  category: 'invariant-violation' | 'access-breach' | 'anomaly' | 'dangerous-pattern' | 'value-drift';
  condition: string; // Expression to evaluate
  severity: 'info' | 'warning' | 'medium' | 'high' | 'critical';
  trigger: 'per-state-change' | 'on-function-call' | 'on-transfer' | 'on-oracle-read' | 'periodic' | 'manual';
  context: string;
  remediation?: string;
  falsePositiveMitigation?: string;
}

// Tier 3: Trace Analysis Types
export interface FoundryTrace {
  transaction: TransactionInfo;
  steps: TraceStep[];
  stateDiffs: StateDiff[];
  events: DecodedEvent[];
  gasUsage: GasBreakdown;
}

export interface TransactionInfo {
  hash: string;
  from: string;
  to: string;
  value: bigint;
  blockNumber: number;
  timestamp: number;
  gasLimit: bigint;
  gasUsed: bigint;
  status: 'success' | 'revert' | 'error';
}

export interface TraceStep {
  stepIndex: number;
  depth: number;
  contractAddress: string;
  contractName: string;
  function: string;
  inputs: Record<string, any>;
  outputs: Record<string, any>;
  gasUsed: bigint;
  gasCost: bigint;
  success: boolean;
  error?: string;
  subcalls: TraceStep[];
  stateReads: StateAccess[];
  stateWrites: StateAccess[];
}

export interface StateAccess {
  slot: number;
  contract: string;
  variable: string;
  value: any;
  accessType: 'read' | 'write';
}

export interface StateDiff {
  stepIndex: number;
  contract: string;
  changes: VariableChange[];
}

export interface VariableChange {
  variable: string;
  slot: number;
  before: any;
  after: any;
  delta: any;
  deltaPercent?: number;
  deviation?: DeviationAnalysis;
}

export interface DeviationAnalysis {
  expectedValue: any;
  actualValue: any;
  deviationPercent: number;
  threshold: number;
  isAnomalous: boolean;
  anomalyType?: string;
}

export interface DecodedEvent {
  name: string;
  contract: string;
  parameters: Record<string, any>;
  logIndex: number;
  stepIndex: number;
}

export interface GasBreakdown {
  totalGas: bigint;
  byFunction: Map<string, bigint>;
  byOperation: Map<string, bigint>;
  byContract: Map<string, bigint>;
  averagePerCall: bigint;
  maxSingleCall: bigint;
}

// Alert/Anomaly Detection Result
export interface AlertResult {
  ruleId: string;
  ruleName: string;
  severity: 'info' | 'warning' | 'medium' | 'high' | 'critical';
  category: string;
  message: string;
  context: AlertContext;
  timestamp: number;
  stepIndex: number;
  confidence: number; // 0-100
  remediation?: string;
  evidence: EvidenceItem[];
}

export interface AlertContext {
  contract: string;
  function: string;
  line?: number;
  variables: Record<string, any>;
  expected: Record<string, any>;
  actual: Record<string, any>;
  relatedAlerts: string[];
}

export interface EvidenceItem {
  type: 'state-diff' | 'event' | 'call-stack' | 'balance-change' | 'gas-anomaly';
  data: any;
  description: string;
}

// Export Formats
export interface ExportOptions {
  format: 'md' | 'html' | 'json' | 'csv' | 'all';
  outputPath: string;
  includeMermaid: boolean;
  includeCharts: boolean;
  includeTimeline: boolean;
  includeAlerts: boolean;
  theme: 'dark' | 'light' | 'vscode-dark';
  interactive: boolean;
}

export interface TerminalOutputConfig {
  showAsciiArt: boolean;
  maxTableWidth: number;
  colorOutput: boolean;
  verbose: boolean;
  showAlertsInline: boolean;
}
