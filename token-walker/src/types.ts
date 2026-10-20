// token-walker :: shared types (the JSON schema of token-state-graph.json is derived from these)

export interface WalkerConfig {
  maxPathsPerEntry: number;     // hard cap on enumerated completing paths per entrypoint
  maxCallDepth: number;         // internal-call inlining depth (cycle guard)
  maxSeqDepth: number;          // cross-entrypoint sequence depth (<=4 recommended)
  maxSequences: number;         // cap on emitted sequences (ranked)
  includePrivileged: boolean;   // also start sequences from owner-gated entrypoints
  rawPaths: boolean;            // emit every enumerated path (not only effect groups)
  maxConstraintSets: number;    // distinct constraint sets kept per effect group
}

export const DEFAULT_CONFIG: WalkerConfig = {
  maxPathsPerEntry: 20000,
  maxCallDepth: 12,
  maxSeqDepth: 4,
  maxSequences: 3000,
  includePrivileged: false,
  rawPaths: false,
  maxConstraintSets: 8,
};

export type KeyClass = 'caller' | 'this' | 'param' | 'state_addr' | 'constant' | 'loop_var' | 'other' | 'none';

export interface Constraint {
  text: string;                 // rendered, args/locals substituted
  arm: 'T' | 'F';
  kind: 'require' | 'if' | 'loop' | 'ternary' | 'modifier';
  line: number;
  fn: string;
}

export interface ReadEv { k: 'R'; var: string; key: string | null; line: number; fn: string }
export interface WriteEv {
  k: 'W'; var: string; key: string | null; keyClass: KeyClass;
  op: string;                   // '=', '+=', '-=', '*=', '/=', '++', '--', 'delete', 'push', 'pop'
  operand: string | null; delta: string; expr: string;
  line: number; fn: string; inLoop: boolean;
}
export interface CallEv {
  k: 'C';
  kind: 'external' | 'native_transfer' | 'native_send' | 'low_level_call' | 'delegatecall' | 'staticcall' | 'selfdestruct' | 'create';
  target: string; targetClass: 'state_var' | 'param' | 'caller' | 'this' | 'constant' | 'derived' | 'unknown';
  targetType: string | null;    // declared contract/interface type when known
  fn: string; args: string[]; value: string | null; likelyView: boolean;
  line: number; callerFn: string;
}
export type Ev = ReadEv | WriteEv | CallEv;

export interface PathRec {
  chain: string[];
  constraints: Constraint[];
  eqFacts: string[];            // 'a == b' facts from TRUE arms
  trace: Ev[];                  // ordered
  flags: string[];              // incomplete / unmodeled markers
  ret: string | null;
}

export interface RevertGuard { cond: string; kind: string; line: number; fn: string; count: number }

export interface Diagnostics {
  warnings: string[];
  unresolved_calls: string[];
  unsupported_nodes: string[];
  truncated_entries: string[];
}
