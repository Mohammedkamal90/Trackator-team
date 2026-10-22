// token-walker :: transaction-scoped symbolic execution primitives
//
// This opt-in runtime is deliberately separate from Walker's legacy, single-entry
// analysis. An AST adapter may supply resolved function bodies as FrameExecutor
// callbacks. This module models call frames, transaction-local storage, rollback,
// branch uncertainty, and the narrow return-data cases needed by future V2 work;
// it is not an EVM and never treats symbolic completion as concrete execution.

export type ReachabilityClass = 'conditional' | 'established_under_assumptions' | 'unresolved';
export type ModeledOutcome = 'normal_return_candidate' | 'revert_candidate' | 'unresolved';
export type ExecutionEvidence = { kind: 'none' } | { kind: 'concrete'; source: string; reference?: string };

export interface PathClassification {
  path_source: 'static_interpretation';
  reachability: ReachabilityClass;
  modeled_outcome: ModeledOutcome;
  execution_evidence: ExecutionEvidence;
}

export interface SymbolicValue<T = unknown> {
  expression: string;
  known: boolean;
  value?: T;
  provenance: 'source_constant' | 'prior_modeled_write' | 'user_assumption' | 'unknown_initial_state' | 'call_result' | 'derived';
}
export const knownValue = <T>(value: T, expression = String(value), provenance: SymbolicValue<T>['provenance'] = 'source_constant'): SymbolicValue<T> =>
  ({ expression, known: true, value, provenance });
export const symbolicValue = <T = unknown>(expression: string, provenance: SymbolicValue<T>['provenance'] = 'derived'): SymbolicValue<T> =>
  ({ expression, known: false, provenance });

export interface ContractInstance {
  id: string;
  contract: string;
  source: string;
  binding?: { kind: 'user_supplied_source_analysis'; detail: string };
}
export interface CallFrame {
  contractInstance: string;
  contract: string;
  function: string;
  callerInstance: string | null;
  msgSender: SymbolicValue<string>;
  args: SymbolicValue[];
  callSite: { source: string; line: number; expression?: string } | null;
  callKind: 'root' | 'high_level' | 'low_level' | 'static_call';
  returnTarget: string | null;
}
export interface StorageCell {
  contractInstance: string;
  variable: string;
  keys: string[];
}
export interface StorageWrite {
  cell: StorageCell;
  before: SymbolicValue;
  after: SymbolicValue;
  callDepth: number;
  disposition: 'transaction_local' | 'rolled_back' | 'unresolved' | 'committed_with_concrete_evidence';
}
export interface RuntimeTraceEvent {
  step: number;
  kind: 'call_enter' | 'call_return' | 'call_revert' | 'call_unresolved' | 'read' | 'write' | 'branch' | 'rollback' | 'return_data' | 'modifier_enter' | 'modifier_exit' | 'event';
  contractInstance: string;
  function: string;
  detail: Record<string, unknown>;
}
export interface ReturnData {
  status: 'known' | 'unknown' | 'revert_data';
  bytesHex?: string;
  reason?: string;
}
export interface RuntimeCallResult {
  status: 'returned' | 'reverted' | 'unresolved';
  success: SymbolicValue<boolean>;
  value?: SymbolicValue;
  returnData: ReturnData;
  path: TransactionPath;
}
export type FrameCompletion =
  | { status: 'returned'; value?: SymbolicValue; returnData?: ReturnData }
  | { status: 'reverted'; reason: string; returnData?: ReturnData }
  | { status: 'unresolved'; reason: string };
export type FrameExecutor = (path: TransactionPath, args: SymbolicValue[]) => FrameCompletion;
export interface BoolEvaluation { path: TransactionPath; value: SymbolicValue<boolean>; status?: 'reverted' | 'unresolved' }
export type BoolEvaluator = (path: TransactionPath) => BoolEvaluation[];

const storageKey = (c: StorageCell) => JSON.stringify([c.contractInstance, c.variable, c.keys]);
const cloneValue = <T>(v: SymbolicValue<T>): SymbolicValue<T> => ({ ...v });
const cloneCell = (c: StorageCell): StorageCell => ({ ...c, keys: [...c.keys] });

export class TransactionPath {
  readonly instances = new Map<string, ContractInstance>();
  frames: CallFrame[] = [];
  storage = new Map<string, SymbolicValue>();
  initialStorage = new Map<string, SymbolicValue>();
  writes: StorageWrite[] = [];
  trace: RuntimeTraceEvent[] = [];
  constraints: string[] = [];
  flags: string[] = [];
  transactionStatus: 'active' | 'reverted' | 'unresolved' = 'active';
  classification: PathClassification = {
    path_source: 'static_interpretation',
    reachability: 'conditional',
    modeled_outcome: 'unresolved',
    execution_evidence: { kind: 'none' },
  };

  constructor(instances: ContractInstance[], root: { instanceId: string; fn: string; caller: SymbolicValue<string>; args?: SymbolicValue[]; source?: string; line?: number }) {
    for (const i of instances) this.instances.set(i.id, { ...i, binding: i.binding ? { ...i.binding } : undefined });
    const instance = this.instances.get(root.instanceId);
    if (!instance) throw new Error(`unknown root contract instance '${root.instanceId}'`);
    this.frames.push({
      contractInstance: instance.id, contract: instance.contract, function: root.fn,
      callerInstance: null, msgSender: cloneValue(root.caller), args: (root.args ?? []).map(cloneValue),
      callSite: root.source ? { source: root.source, line: root.line ?? 0 } : null,
      callKind: 'root', returnTarget: null,
    });
  }

  get frame(): CallFrame {
    const f = this.frames[this.frames.length - 1];
    if (!f) throw new Error('no active call frame');
    return f;
  }

  clone(): TransactionPath {
    const c = Object.create(TransactionPath.prototype) as TransactionPath;
    (c as any).instances = new Map([...this.instances].map(([k, v]) => [k, { ...v, binding: v.binding ? { ...v.binding } : undefined }]));
    c.frames = this.frames.map(f => ({ ...f, msgSender: cloneValue(f.msgSender), args: f.args.map(cloneValue), callSite: f.callSite ? { ...f.callSite } : null }));
    c.storage = new Map([...this.storage].map(([k, v]) => [k, cloneValue(v)]));
    c.initialStorage = new Map([...this.initialStorage].map(([k, v]) => [k, cloneValue(v)]));
    c.writes = this.writes.map(w => ({ ...w, cell: cloneCell(w.cell), before: cloneValue(w.before), after: cloneValue(w.after) }));
    c.trace = this.trace.map(e => ({ ...e, detail: { ...e.detail } }));
    c.constraints = [...this.constraints]; c.flags = [...this.flags];
    c.transactionStatus = this.transactionStatus;
    c.classification = { ...this.classification, execution_evidence: { ...this.classification.execution_evidence } as ExecutionEvidence };
    return c;
  }

  private event(kind: RuntimeTraceEvent['kind'], detail: Record<string, unknown>, frame = this.frame) {
    this.trace.push({ step: this.trace.length + 1, kind, contractInstance: frame.contractInstance, function: frame.function, detail });
  }

  /** Trace a source modifier while retaining the executing function's contract frame. */
  record(kind: RuntimeTraceEvent['kind'], detail: Record<string, unknown>): void { this.event(kind, detail); }

  /** Same-instance Solidity internal call: msg.sender and storage namespace are preserved. */
  enterInternalFrame(fn: string, args: SymbolicValue[], callSite: { source: string; line: number; expression?: string }, implementation?: { contract: string; source: string; line: number }): void {
    const caller = this.frame;
    const frame: CallFrame = {
      contractInstance: caller.contractInstance, contract: caller.contract, function: fn,
      callerInstance: caller.contractInstance, msgSender: cloneValue(caller.msgSender),
      args: args.map(cloneValue), callSite: { ...callSite }, callKind: 'high_level', returnTarget: null,
    };
    this.frames.push(frame);
    this.event('call_enter', { callerInstance: caller.contractInstance, calleeInstance: caller.contractInstance, fn, args, callSite, callKind: 'internal', implementation: implementation ?? null }, frame);
  }

  leaveInternalFrame(value?: SymbolicValue): void {
    if (this.frames.length < 2) throw new Error('no internal frame to return from');
    const callee = this.frame;
    const site = callee.callSite;
    this.frames.pop();
    this.event('call_return', { calleeInstance: callee.contractInstance, resumedAt: site, value: value ?? null, callKind: 'internal' });
  }

  /** Enter a separately bound contract instance using CALL or STATICCALL semantics. */
  enterExternalFrame(instanceId: string, fn: string, args: SymbolicValue[], callSite: { source: string; line: number; expression?: string }, callKind: 'high_level' | 'low_level' | 'static_call'): void {
    const target = this.instances.get(instanceId);
    if (!target) throw new Error(`unknown external contract instance '${instanceId}'`);
    const caller = this.frame;
    const frame: CallFrame = {
      contractInstance: target.id, contract: target.contract, function: fn,
      callerInstance: caller.contractInstance, msgSender: knownValue(caller.contractInstance, caller.contractInstance, 'derived'),
      args: args.map(cloneValue), callSite: { ...callSite }, callKind, returnTarget: null,
    };
    this.frames.push(frame);
    this.event('call_enter', { callerInstance: caller.contractInstance, calleeInstance: target.id, fn, args, msgSender: frame.msgSender, callSite, callKind }, frame);
  }

  leaveExternalFrame(value: SymbolicValue | undefined, returnData: ReturnData, callKind: 'high_level' | 'low_level' | 'static_call'): void {
    if (this.frames.length < 2) throw new Error('no external frame to return from');
    const callee = this.frame;
    const caller = this.frames[this.frames.length - 2];
    const site = callee.callSite;
    this.frames.pop();
    this.event('call_return', { calleeInstance: callee.contractInstance, resumedAt: site, value: value ?? null, returnData, callKind }, caller);
    this.event('return_data', { status: returnData.status, bytesHex: returnData.bytesHex ?? null, reason: returnData.reason ?? null }, caller);
  }

  /** Revert a low-level callee locally, or propagate a high-level revert to the root. */
  failExternalFrame(reason: string, callSite: { source: string; line: number; expression?: string }, callKind: 'high_level' | 'low_level' | 'static_call', checkpoint: Map<string, SymbolicValue>, writeStart: number, externalFrameIndex = this.frames.length - 1): ReturnData {
    if (externalFrameIndex < 1 || externalFrameIndex >= this.frames.length) throw new Error('no external frame to fail');
    const callee = this.frames[externalFrameIndex];
    this.event('call_revert', { calleeInstance: callee.contractInstance, callSite, reason, callKind }, callee);
    const data: ReturnData = { status: 'revert_data', reason: 'revert payload is not modeled' };
    if (callKind === 'low_level') {
      this.storage = new Map([...checkpoint].map(([k, v]) => [k, cloneValue(v)]));
      for (let i = writeStart; i < this.writes.length; i++) this.writes[i].disposition = 'rolled_back';
      const caller = this.frames[externalFrameIndex - 1];
      // Revert unwinds the whole callee subtree, including internal frames, but
      // keeps the attempted trace and resumes the low-level caller.
      this.frames = this.frames.slice(0, externalFrameIndex);
      this.event('rollback', { scope: 'callee_frame', writesRolledBack: this.writes.slice(writeStart).length }, caller);
    }
    return data;
  }

  read(variable: string, keys: string[] = []): SymbolicValue {
    const cell = { contractInstance: this.frame.contractInstance, variable, keys: [...keys] };
    const existing = this.storage.get(storageKey(cell)) ?? this.initialStorage.get(storageKey(cell));
    const value = existing ? cloneValue(existing) : symbolicValue(`storage[${cell.contractInstance}].${variable}${keys.length ? '[' + keys.join('][') + ']' : ''}`, 'unknown_initial_state');
    this.event('read', { cell, value });
    return value;
  }

  write(variable: string, value: SymbolicValue, keys: string[] = []): void {
    const cell = { contractInstance: this.frame.contractInstance, variable, keys: [...keys] };
    const k = storageKey(cell);
    const before = this.storage.has(k) ? cloneValue(this.storage.get(k)!) : this.initialStorage.has(k) ? cloneValue(this.initialStorage.get(k)!) : symbolicValue(`storage[${cell.contractInstance}].${variable}`, 'unknown_initial_state');
    const after = { ...value, provenance: 'prior_modeled_write' as const };
    this.storage.set(k, after);
    this.writes.push({ cell, before, after: cloneValue(after), callDepth: this.frames.length, disposition: 'transaction_local' });
    this.event('write', { cell, before, after });
  }

  assumeStorage(variable: string, value: SymbolicValue, keys: string[] = []): void {
    const cell = { contractInstance: this.frame.contractInstance, variable, keys: [...keys] };
    this.initialStorage.set(storageKey(cell), { ...value, provenance: 'user_assumption' });
  }

  assume(condition: string, value: boolean): void {
    this.constraints.push(value ? condition : `!(${condition})`);
    this.classification.reachability = 'established_under_assumptions';
    this.event('branch', { condition, arm: value ? 'true' : 'false', establishedBy: 'explicit_assumption' });
  }

  /** Fork both arms for an unknown condition. Neither arm is asserted reachable. */
  branch(condition: string, known?: boolean): { path: TransactionPath; value: boolean }[] {
    if (known !== undefined) {
      const p = this.clone(); p.constraints.push(known ? condition : `!(${condition})`);
      p.classification.reachability = 'established_under_assumptions';
      p.event('branch', { condition, arm: known ? 'true' : 'false', establishedBy: 'known_symbolic_value' });
      return [{ path: p, value: known }];
    }
    const yes = this.clone(); const no = this.clone();
    yes.constraints.push(condition); no.constraints.push(`!(${condition})`);
    yes.classification.reachability = no.classification.reachability = 'conditional';
    yes.event('branch', { condition, arm: 'true', establishedBy: 'symbolic_fork' });
    no.event('branch', { condition, arm: 'false', establishedBy: 'symbolic_fork' });
    return [{ path: yes, value: true }, { path: no, value: false }];
  }

  /** Solidity-style lazy &&. Right hand side is evaluated only on the true arm. */
  and(left: SymbolicValue<boolean>, right: BoolEvaluator): BoolEvaluation[] {
    const out: BoolEvaluation[] = [];
    for (const arm of this.branch(left.expression, left.known ? Boolean(left.value) : undefined)) {
      if (!arm.value) { out.push({ path: arm.path, value: knownValue(false, `(${left.expression} && <skipped>)`, 'derived') }); continue; }
      out.push(...right(arm.path));
    }
    return out;
  }

  /** Solidity-style lazy ||. Right hand side is evaluated only on the false arm. */
  or(left: SymbolicValue<boolean>, right: BoolEvaluator): BoolEvaluation[] {
    const out: BoolEvaluation[] = [];
    for (const arm of this.branch(left.expression, left.known ? Boolean(left.value) : undefined)) {
      if (arm.value) { out.push({ path: arm.path, value: knownValue(true, `(${left.expression} || <skipped>)`, 'derived') }); continue; }
      out.push(...right(arm.path));
    }
    return out;
  }

  /** Execute a resolved source body as a nested call, preserving the caller frame. */
  invoke(instanceId: string, fn: string, args: SymbolicValue[], callSite: { source: string; line: number; expression?: string }, callKind: 'high_level' | 'low_level' | 'static_call', executor: FrameExecutor, returnTarget: string | null = null): RuntimeCallResult[] {
    const target = this.instances.get(instanceId);
    if (!target) return [this.unresolvedCall(`unresolved target instance '${instanceId}'`, callSite)];
    const caller = this.frame;
    const child = this.clone();
    const checkpoint = new Map(child.storage);
    const parentDepth = child.frames.length;
    const frame: CallFrame = {
      contractInstance: target.id, contract: target.contract, function: fn,
      callerInstance: caller.contractInstance,
      msgSender: knownValue(caller.contractInstance, caller.contractInstance, 'derived'),
      args: args.map(cloneValue), callSite: { ...callSite },
      callKind, returnTarget,
    };
    child.frames.push(frame);
    child.event('call_enter', { callerInstance: caller.contractInstance, calleeInstance: target.id, fn, args, callSite, callKind }, frame);
    const writesAtEntry = child.writes.length;
    let completion = executor(child, args.map(cloneValue));
    const staticContext = child.frames.some(f => f.callKind === 'static_call');
    if (staticContext && child.writes.length > writesAtEntry && completion.status === 'returned') {
      completion = { status: 'reverted', reason: 'state modification attempted during static call' };
    }
    if (completion.status === 'returned') {
      child.frames.pop();
      child.event('call_return', { calleeInstance: target.id, resumedAt: callSite, returnTarget, value: completion.value ?? null, returnData: completion.returnData ?? { status: 'unknown', reason: 'return data not supplied' } }, caller);
      return [{ status: 'returned', success: knownValue(true, 'call.success', 'call_result'), value: completion.value, returnData: completion.returnData ?? { status: 'unknown', reason: 'return data not supplied' }, path: child }];
    }
    if (completion.status === 'reverted') {
      child.storage = checkpoint;
      for (const w of child.writes) if (w.callDepth > parentDepth) w.disposition = 'rolled_back';
    } else {
      child.storage = checkpoint;
      for (const w of child.writes) if (w.callDepth > parentDepth && w.disposition === 'transaction_local') w.disposition = 'unresolved';
    }
    child.event(completion.status === 'reverted' ? 'call_revert' : 'call_unresolved', { calleeInstance: target.id, callSite, detail: completion.status === 'reverted' ? completion.reason : completion.reason, returnData: completion.status === 'reverted' ? completion.returnData ?? { status: 'revert_data', reason: completion.reason } : null }, frame);
    if (completion.status === 'unresolved') {
      child.transactionStatus = 'unresolved'; child.classification.modeled_outcome = 'unresolved';
      child.flags.push(`unresolved_call:${target.contract}.${fn}`);
      return [{ status: 'unresolved', success: symbolicValue<boolean>('call.success', 'call_result'), returnData: { status: 'unknown', reason: completion.reason }, path: child }];
    }
    if (callKind === 'low_level' || callKind === 'static_call') {
      child.frames.pop();
      child.transactionStatus = 'active';
      child.storage = checkpoint;
      child.event('rollback', { scope: 'callee_frame', writesRolledBack: child.writes.filter(w => w.disposition === 'rolled_back').length }, caller);
      return [{ status: 'reverted', success: knownValue(false, 'call.success', 'call_result'), returnData: completion.returnData ?? { status: 'revert_data', reason: completion.reason }, path: child }];
    }
    child.frames = child.frames.slice(0, -1);
    child.transactionStatus = 'reverted';
    child.classification.modeled_outcome = 'revert_candidate';
    child.storage.clear();
    for (const w of child.writes) w.disposition = 'rolled_back';
    child.event('rollback', { scope: 'transaction', writesRolledBack: child.writes.length }, caller);
    return [{ status: 'reverted', success: knownValue(false, 'call.success', 'call_result'), returnData: completion.returnData ?? { status: 'revert_data', reason: completion.reason }, path: child }];
  }

  unresolvedCall(reason: string, callSite: { source: string; line: number; expression?: string }): RuntimeCallResult {
    const p = this.clone(); p.flags.push(`unresolved_call:${reason}`);
    p.classification.modeled_outcome = 'unresolved'; p.transactionStatus = 'unresolved';
    p.event('call_unresolved', { reason, callSite });
    return { status: 'unresolved', success: symbolicValue<boolean>('call.success', 'call_result'), returnData: { status: 'unknown', reason }, path: p };
  }

  /** Mark only a modeled normal root return; this is never concrete-success evidence. */
  finishRoot(): void {
    if (this.frames.length !== 1) throw new Error('cannot finish root while nested call frames remain');
    if (this.transactionStatus === 'active') this.classification.modeled_outcome = 'normal_return_candidate';
    this.classification.execution_evidence = { kind: 'none' };
  }

  /** A source-level root revert rolls back this transaction overlay, not its trace. */
  revertRoot(reason: string): void {
    if (this.frames.length !== 1) throw new Error('root revert cannot be raised while nested call frames remain');
    this.transactionStatus = 'reverted';
    this.classification.modeled_outcome = 'revert_candidate';
    this.classification.execution_evidence = { kind: 'none' };
    for (const w of this.writes) w.disposition = 'rolled_back';
    this.storage.clear();
    this.event('call_revert', { scope: 'root', reason });
    this.event('rollback', { scope: 'transaction', writesRolledBack: this.writes.length });
  }

  /** Stop continuation when AST behavior cannot be modeled; do not imply rollback. */
  markUnresolved(reason: string): void {
    this.transactionStatus = 'unresolved';
    this.classification.modeled_outcome = 'unresolved';
    this.classification.execution_evidence = { kind: 'none' };
    for (const w of this.writes) if (w.disposition === 'transaction_local') w.disposition = 'unresolved';
    this.flags.push(`unresolved:${reason}`);
    this.event('call_unresolved', { scope: 'current', reason });
  }

  /** Return whether known call data is empty; opaque return bytes remain unresolved. */
  static isEmptyReturnData(data: ReturnData): SymbolicValue<boolean> {
    if (data.status !== 'known' || data.bytesHex === undefined) return symbolicValue<boolean>('returnData.length == 0', 'call_result');
    const hex = data.bytesHex.toLowerCase().replace(/^0x/, '');
    if (!/^(?:[0-9a-f]{2})*$/.test(hex)) return symbolicValue<boolean>('returnData.length == 0:invalid_bytes', 'call_result');
    return knownValue(hex.length === 0, 'returnData.length == 0', 'call_result');
  }

  /** Narrow bool ABI support (return-data word only); unsupported shapes stay unknown. */
  static encodeBoolReturn(value: boolean): ReturnData {
    return { status: 'known', bytesHex: value ? `0x${'0'.repeat(63)}1` : `0x${'0'.repeat(64)}` };
  }
  static decodeBoolReturnResult(data: ReturnData): { status: 'decoded'; value: SymbolicValue<boolean> } | { status: 'revert_candidate'; reason: string } | { status: 'unresolved'; value: SymbolicValue<boolean> } {
    if (data.status !== 'known' || !data.bytesHex) return { status: 'unresolved', value: symbolicValue<boolean>('abi.decode(returnData,bool)', 'call_result') };
    const hex = data.bytesHex.toLowerCase().replace(/^0x/, '');
    if (!/^(?:[0-9a-f]{2})*$/.test(hex)) return { status: 'revert_candidate', reason: 'return data is not even-length hex bytes' };
    if (hex.length < 64) return { status: 'revert_candidate', reason: 'abi.decode(bool) requires at least one 32-byte word' };
    const word = hex.slice(0, 64);
    if (!/^0{63}[01]$/.test(word)) return { status: 'revert_candidate', reason: 'ABI bool word is not canonical 0 or 1' };
    return { status: 'decoded', value: knownValue(word.endsWith('1'), 'abi.decode(returnData,bool)', 'call_result') };
  }
  static decodeBoolReturn(data: ReturnData): SymbolicValue<boolean> {
    const result = TransactionPath.decodeBoolReturnResult(data);
    return result.status === 'decoded' ? result.value : result.status === 'unresolved' ? result.value : symbolicValue<boolean>(`abi.decode(returnData,bool):revert(${result.reason})`, 'call_result');
  }
}
