// Opt-in, deliberately narrow AST adapter over the transaction-scoped runtime.
// It executes only the Solidity AST constructs implemented below. Unsupported
// syntax terminates as unresolved; this is static interpretation, never EVM evidence.
import { Index, FnInfo } from './parse';
import {
  ContractInstance, FrameCompletion, ReturnData, SymbolicValue, TransactionPath,
  knownValue, symbolicValue,
} from './transaction';
import { selectorForSignature } from './keccak';

export interface AstBinding {
  /** Explicit source-analysis mapping: `callerInstance.stateVariable` -> target instance id. */
  receivers?: Record<string, string>;
}
export interface AstRun {
  path: TransactionPath;
  status: 'returned' | 'reverted' | 'unresolved';
  returnValue?: SymbolicValue;
}
interface State { path: TransactionPath; status: 'active' | 'returned' | 'reverted' | 'unresolved'; value?: SymbolicValue; locals?: Map<string, SymbolicValue>; }
interface Eval { path: TransactionPath; value: SymbolicValue; status?: 'reverted' | 'unresolved'; locals?: Map<string, SymbolicValue>; }
interface Lvalue { name: string; keys?: string[]; local?: boolean; integerType?: { bits: number; signed: boolean }; }
interface LvalueEval { path: TransactionPath; target?: Lvalue; status?: 'reverted' | 'unresolved'; }
type Loc = { source: string; line: number; expression?: string };

export class AstTransactionAdapter {
  private uncheckedDepth = 0;
  constructor(private readonly index: Index, private readonly instances: ContractInstance[], private readonly bindings: AstBinding = {}) {}

  runRoot(instanceId: string, functionName: string, args: SymbolicValue[], caller: SymbolicValue<string>): AstRun[] {
    const instance = this.instances.find(i => i.id === instanceId);
    if (!instance) throw new Error(`unknown instance '${instanceId}'`);
    const fn = this.resolve(instance.contract, functionName, args.length);
    if (!fn) {
      const p = new TransactionPath(this.instances, { instanceId, fn: functionName, caller, args, source: instance.source });
      p.markUnresolved(`function body not uniquely resolved: ${instance.contract}.${functionName}/${args.length}`);
      return [{ path: p, status: 'unresolved' }];
    }
    const path = new TransactionPath(this.instances, { instanceId, fn: fn.name, caller, args, source: fn.file, line: fn.line });
    const states = this.executeFunction(path, fn, args);
    return states.map(s => {
      if (s.status === 'active' || s.status === 'returned') {
        if (s.path.transactionStatus === 'active') s.path.finishRoot();
        return { path: s.path, status: 'returned' as const, returnValue: s.value };
      }
      if (s.status === 'reverted') {
        if (s.path.transactionStatus === 'active') {
          // High-level internal reverts unwind every source frame before transaction rollback.
          s.path.frames = s.path.frames.slice(0, 1);
          s.path.revertRoot('source-level revert');
        }
        return { path: s.path, status: 'reverted' as const };
      }
      if (s.path.transactionStatus !== 'unresolved') s.path.markUnresolved('AST execution unresolved');
      return { path: s.path, status: 'unresolved' as const };
    });
  }

  private resolve(contract: string, name: string, argc: number): FnInfo | null {
    const candidates = this.index.findFns(contract, name, argc);
    return candidates.length === 1 ? candidates[0] : null;
  }

  private loc(fn: FnInfo, n: any): Loc {
    const src = this.index.fileSrc.get(fn.file) ?? fn.file;
    const text = n?.range ? src.slice(n.range[0], n.range[1] + 1) : n?.type ?? 'AST node';
    return { source: fn.file, line: n?.loc?.start?.line ?? fn.line, expression: text };
  }

  private executeFunction(path: TransactionPath, fn: FnInfo, args: SymbolicValue[]): State[] {
    if (!fn.node.body || !Array.isArray(fn.node.body.statements)) {
      path.markUnresolved(`no executable function body for ${fn.contract}.${fn.name}`);
      return [{ path, status: 'unresolved' }];
    }
    const locals = new Map<string, SymbolicValue>();
    fn.params.forEach((p, i) => { if (p.name) locals.set(p.name, args[i] ?? symbolicValue(`arg${i}`)); });
    // Solidity return parameters are named local variables and are returned implicitly.
    fn.returns.forEach((p, i) => { if (p.name) locals.set(p.name, symbolicValue(`return.${p.name}`, 'unknown_initial_state')); });
    const states = this.executeModifierChain(path, fn, locals, 0);
    return states.map(s => {
      if (s.status !== 'active') return s;
      const finalLocals = s.locals ?? locals;
      if (fn.returns.length) {
        const values = fn.returns.map((r, i) => r.name ? finalLocals.get(r.name) ?? symbolicValue(`return.${r.name}`, 'unknown_initial_state') : symbolicValue(`return[${i}]`, 'unknown_initial_state'));
        const value = values.length === 1 ? values[0] : knownValue(values, `(${values.map(v => v.expression).join(', ')})`, 'derived');
        return { ...s, status: 'returned' as const, value };
      }
      return { ...s, status: 'returned' as const, value: knownValue(undefined, 'return', 'derived') };
    });
  }

  /** Execute modifiers in declaration order, wrapping the body at each placeholder. */
  private executeModifierChain(path: TransactionPath, fn: FnInfo, locals: Map<string, SymbolicValue>, index: number): State[] {
    if (index >= fn.modifiers.length) return this.execStatements(path, fn, fn.node.body.statements, locals);
    const invocation = fn.modifiers[index];
    const modifier = this.index.findModifier(path.frame.contract, invocation.name);
    if (!modifier) {
      path.markUnresolved(`modifier body not uniquely resolved: ${fn.contract}.${invocation.name}`);
      return [{ path, status: 'unresolved' }];
    }
    const statements = modifier.node.body?.statements ?? [];
    const placeholders = statements.map((s: any, i: number) => s.type === 'ExpressionStatement' && s.expression?.type === 'Identifier' && s.expression.name === '_' ? i : -1).filter((i: number) => i >= 0);
    if (placeholders.length !== 1) {
      path.markUnresolved(`modifier ${modifier.contract}.${modifier.name} requires exactly one top-level placeholder`);
      return [{ path, status: 'unresolved' }];
    }
    const placeholder = placeholders[0];
    let variants: { path: TransactionPath; args: SymbolicValue[] }[] = [{ path, args: [] }];
    for (const arg of invocation.args) {
      const next: typeof variants = [];
      for (const variant of variants) for (const value of this.evalExpr(variant.path, fn, arg, locals)) {
        if (value.status) return [{ path: value.path, status: value.status }];
        next.push({ path: value.path, args: [...variant.args, value.value] });
      }
      variants = next;
    }
    const out: State[] = [];
    for (const variant of variants) {
      const modifierLocals = new Map(locals);
      modifier.params.forEach((p, i) => { if (p.name) modifierLocals.set(p.name, variant.args[i] ?? symbolicValue(`modifier.arg${i}`)); });
      variant.path.record('modifier_enter', { modifier: `${modifier.contract}.${modifier.name}`, source: modifier.file, line: modifier.line });
      const before = this.execStatements(variant.path, modifier, statements.slice(0, placeholder), modifierLocals);
      for (const b of before) {
        if (b.status !== 'active') { out.push(b); continue; }
        const bodyStates = this.executeModifierChain(b.path, fn, locals, index + 1);
        for (const body of bodyStates) {
          // A Solidity return from the wrapped function still executes modifier suffix code.
          const priorStatus = body.status;
          if (priorStatus === 'reverted' || priorStatus === 'unresolved') { out.push(body); continue; }
          const suffixStart = body.path.trace.length;
          const suffixStates = this.execStatements(body.path, modifier, statements.slice(placeholder + 1), modifierLocals);
          for (const suffix of suffixStates) {
            if (suffix.status === 'active') {
              suffix.path.record('modifier_exit', { modifier: `${modifier.contract}.${modifier.name}`, source: modifier.file, line: modifier.line });
              out.push(priorStatus === 'returned' ? { ...suffix, status: 'returned', value: body.value } : suffix);
            } else out.push(suffix);
          }
        }
      }
    }
    return out;
  }

  private execStatements(path: TransactionPath, fn: FnInfo, nodes: any[], locals: Map<string, SymbolicValue>): State[] {
    let states: State[] = [{ path, status: 'active', locals: new Map(locals) }];
    for (const node of nodes) {
      const next: State[] = [];
      for (const state of states) {
        if (state.status !== 'active') { next.push(state); continue; }
        const stateLocals = state.locals ?? new Map(locals);
        const results = this.execStatement(state.path, fn, node, stateLocals);
        next.push(...results.map(result => ({ ...result, locals: result.locals ?? new Map(stateLocals) })));
      }
      states = next;
    }
    return states;
  }

  private execStatement(path: TransactionPath, fn: FnInfo, n: any, locals: Map<string, SymbolicValue>): State[] {
    if (!n) return [{ path, status: 'unresolved' }];
    if (n.type === 'Block') return this.execStatements(path, fn, n.statements ?? [], new Map(locals));
    if (n.type === 'PlaceholderStatement') {
      path.markUnresolved('modifier placeholder outside supported modifier execution');
      return [{ path, status: 'unresolved' }];
    }
    if (n.type === 'ExpressionStatement') {
      const evals = this.evalExpr(path, fn, n.expression, locals);
      return evals.map(e => ({ path: e.path, status: e.status ?? 'active', locals: e.locals ?? new Map(locals) }));
    }
    if (n.type === 'EmitStatement') {
      const eventName = n.eventCall?.expression?.name ?? this.sourceText(fn, n.eventCall?.expression);
      const args = n.eventCall?.arguments ?? [];
      let variants: { path: TransactionPath; args: SymbolicValue[] }[] = [{ path, args: [] }];
      for (const arg of args) {
        const next: typeof variants = [];
        for (const v of variants) for (const e of this.evalExpr(v.path, fn, arg, locals)) {
          if (e.status) return [{ path: e.path, status: e.status }];
          next.push({ path: e.path, args: [...v.args, e.value] });
        }
        variants = next;
      }
      return variants.map(v => {
        v.path.record('event', { name: eventName, args: v.args, source: fn.file, line: n.loc?.start?.line ?? fn.line });
        return { path: v.path, status: 'active' as const };
      });
    }
    if (n.type === 'UncheckedStatement') {
      // solidity-parser stores the block under `block` (not `body`). Scope the
      // arithmetic mode around the actual parsed block and restore it reliably.
      this.uncheckedDepth++;
      try { return this.execStatement(path, fn, n.block ?? n.body, locals); }
      finally { this.uncheckedDepth--; }
    }
    if (n.type === 'IfStatement') {
      const conds = this.evalExpr(path, fn, n.condition, locals);
      const out: State[] = [];
      for (const c of conds) {
        if (c.status) { out.push({ path: c.path, status: c.status }); continue; }
        const arms = c.path.branch(c.value.expression, c.value.known ? Boolean(c.value.value) : undefined);
        for (const arm of arms) {
          const body = arm.value ? n.trueBody : n.falseBody;
          if (!body) { out.push({ path: arm.path, status: 'active', locals: new Map(c.locals ?? locals) }); continue; }
          const armLocals = new Map(c.locals ?? locals);
          out.push(...this.execStatement(arm.path, fn, body, armLocals).map(s => ({ ...s, locals: s.locals ?? armLocals })));
        }
      }
      return out;
    }
    if (n.type === 'ReturnStatement') {
      if (!n.expression) return [{ path, status: 'returned' }];
      return this.evalExpr(path, fn, n.expression, locals).map(e => ({ path: e.path, status: e.status ?? 'returned', value: e.value, locals: e.locals ?? new Map(locals) }));
    }
    if (n.type === 'RevertStatement') {
      const reason = n.arguments?.length ? this.sourceText(fn, n.arguments[0]) : 'revert()';
      return [{ path, status: 'reverted', value: symbolicValue(reason) }];
    }
    if (n.type === 'VariableDeclarationStatement') {
      const slots = n.variables ?? [];
      const declarations = slots.filter((v: any) => v);
      if (!n.initialValue) {
        for (const decl of declarations) if (decl.name) locals.set(decl.name, symbolicValue(`local.${decl.name}`, 'unknown_initial_state'));
        return [{ path, status: 'active', locals }];
      }
      const values = this.evalExpr(path, fn, n.initialValue, locals);
      return values.map(e => {
        if (e.status) return { path: e.path, status: e.status };
        // Each evaluated branch needs its own lexical environment. Mutating the
        // shared map here lets the last ternary arm overwrite earlier paths.
        const branchLocals = new Map(e.locals ?? locals);
        if (slots.length <= 1) {
          const decl = slots[0];
          const tuple = e.value.known && Array.isArray(e.value.value) ? e.value.value as SymbolicValue[] : null;
          if (tuple && tuple.length === 1 && decl?.name) branchLocals.set(decl.name, tuple[0]);
          else if (tuple) { e.path.markUnresolved('single declaration received an incompatible tuple return'); return { path: e.path, status: 'unresolved' as const }; }
          else if (decl?.name) branchLocals.set(decl.name, e.value);
          return { path: e.path, status: 'active' as const, locals: branchLocals };
        }
        const tuple = e.value.known && Array.isArray(e.value.value) ? e.value.value as (SymbolicValue | null)[] : null;
        if (!tuple || tuple.length !== slots.length) {
          e.path.markUnresolved('tuple declaration return shape is unresolved');
          return { path: e.path, status: 'unresolved' as const };
        }
        for (let i = 0; i < slots.length; i++) {
          const decl = slots[i];
          if (decl?.name) {
            const component = tuple[i];
            if (!component) { e.path.markUnresolved(`tuple component ${i} is omitted but destination is named`); return { path: e.path, status: 'unresolved' as const }; }
            branchLocals.set(decl.name, component);
          }
        }
        return { path: e.path, status: 'active' as const, locals: branchLocals };
      });
    }
    path.markUnresolved(`unsupported statement ${n.type} at ${this.loc(fn, n).source}:${this.loc(fn, n).line}`);
    return [{ path, status: 'unresolved' }];
  }

  private sourceText(fn: FnInfo, n: any): string {
    const src = this.index.fileSrc.get(fn.file) ?? '';
    return n?.range ? src.slice(n.range[0], n.range[1] + 1) : n?.type ?? 'unknown';
  }

  private evalExpr(path: TransactionPath, fn: FnInfo, n: any, locals: Map<string, SymbolicValue>): Eval[] {
    if (!n) return [{ path, value: symbolicValue('missing expression') }];
    if (n.type === 'BooleanLiteral') return [{ path, value: knownValue(!!n.value, String(!!n.value)) }];
    if (n.type === 'NumberLiteral' || n.type === 'DecimalNumber') {
      const raw = String(n.number ?? n.value);
      const units: Record<string, bigint> = { wei: 1n, gwei: 1_000_000_000n, ether: 1_000_000_000_000_000_000n };
      if (n.subdenomination) {
        const multiplier = units[String(n.subdenomination).toLowerCase()];
        if (!multiplier || !/^\d+$/.test(raw)) {
          path.markUnresolved(`unsupported Solidity denomination '${n.subdenomination}' at ${this.loc(fn, n).line}`);
          return [{ path, value: symbolicValue(this.sourceText(fn, n)), status: 'unresolved' }];
        }
        return [{ path, value: knownValue(BigInt(raw) * multiplier, `${raw} ${n.subdenomination}`, 'derived') }];
      }
      const v = Number(raw);
      return [{ path, value: Number.isFinite(v) ? knownValue(v, String(v)) : symbolicValue(this.sourceText(fn, n)) }];
    }
    if (n.type === 'StringLiteral') return [{ path, value: knownValue(n.value, JSON.stringify(n.value)) }];
    if (n.type === 'Identifier') {
      const local = locals.get(n.name);
      if (local) return [{ path, value: local }];
      const stateVar = this.index.allVars(path.frame.contract).get(n.name);
      if (stateVar) return [{ path, value: path.read(n.name) }];
      const declared = this.index.allVars(fn.contract).get(n.name);
      if (declared?.constant) return [{ path, value: symbolicValue(`constant.${fn.contract}.${n.name}`, 'derived') }];
      return [{ path, value: symbolicValue(n.name) }];
    }
    if (n.type === 'MemberAccess' && n.expression?.type === 'Identifier' && n.expression.name === 'msg' && n.memberName === 'sender') {
      return [{ path, value: path.frame.msgSender }];
    }
    if (n.type === 'MemberAccess' && n.expression?.type === 'Identifier' && n.expression.name === 'block') {
      return [{ path, value: symbolicValue(`ENV:block.${n.memberName}`, 'unknown_initial_state') }];
    }
    if (n.type === 'MemberAccess' && n.memberName === 'length' && n.expression?.type === 'Identifier') {
      const local = locals.get(n.expression.name);
      if (local?.known && typeof local.value === 'string' && /^(?:0x)?(?:[0-9a-fA-F]{2})*$/.test(local.value)) {
        const hex = local.value.replace(/^0x/i, '');
        return [{ path, value: knownValue(hex.length / 2, `${n.expression.name}.length`, 'call_result') }];
      }
      const data = local?.known ? local.value as ReturnData : undefined;
      if (data?.status === 'known' && data.bytesHex !== undefined && /^(?:0x)?(?:[0-9a-fA-F]{2})*$/.test(data.bytesHex)) {
        const hex = data.bytesHex.replace(/^0x/i, '');
        return [{ path, value: knownValue(hex.length / 2, `${n.expression.name}.length`, 'call_result') }];
      }
      if (data?.status === 'revert_data') return [{ path, value: symbolicValue(`${n.expression.name}.length`, 'call_result') }];
    }
    if (n.type === 'IndexAccess' && n.base?.type === 'Identifier') {
      const keys = n.index ? this.evalExpr(path, fn, n.index, locals) : [{ path, value: symbolicValue('index') }];
      return keys.map(k => k.status ? k : ({ path: k.path, value: k.path.read(n.base.name, [this.storageKeyExpression(k.value)]), locals: new Map(k.locals ?? locals) }));
    }
    if (n.type === 'UnaryOperation' && n.operator === '!') {
      return this.evalExpr(path, fn, n.subExpression, locals).map(e => ({
        path: e.path, value: e.value.known ? knownValue(!Boolean(e.value.value), `!(${e.value.expression})`, 'derived') : symbolicValue(`!(${e.value.expression})`),
        status: e.status, locals: e.locals,
      }));
    }
    if (n.type === 'BinaryOperation') return this.evalBinary(path, fn, n, locals);
    if (n.type === 'Conditional') {
      const conditions = this.evalExpr(path, fn, n.condition, locals);
      const out: Eval[] = [];
      for (const condition of conditions) {
        if (condition.status) { out.push(condition); continue; }
        for (const arm of condition.path.branch(condition.value.expression, condition.value.known ? Boolean(condition.value.value) : undefined)) {
          const selected = arm.value ? n.trueExpression : n.falseExpression;
          out.push(...this.evalExpr(arm.path, fn, selected, new Map(condition.locals ?? locals)).map(v => ({ ...v, locals: v.locals ?? new Map(condition.locals ?? locals) })));
        }
      }
      return out;
    }
    if (n.type === 'TupleExpression' && !n.isArray) {
      // Parenthesized scalar expressions are represented by a one-component
      // TupleExpression by solidity-parser; they are not ABI tuple values.
      if ((n.components ?? []).length === 1 && n.components[0]) return this.evalExpr(path, fn, n.components[0], locals);
      let variants: { path: TransactionPath; values: (SymbolicValue | null)[] }[] = [{ path, values: [] }];
      for (const component of n.components ?? []) {
        if (!component) { variants = variants.map(v => ({ ...v, values: [...v.values, null] })); continue; }
        const next: typeof variants = [];
        for (const variant of variants) for (const value of this.evalExpr(variant.path, fn, component, locals)) {
          if (value.status) return [{ path: value.path, value: value.value, status: value.status }];
          next.push({ path: value.path, values: [...variant.values, value.value] });
        }
        variants = next;
      }
      return variants.map(v => ({ path: v.path, value: knownValue(v.values, `(${v.values.map(x => x?.expression ?? '').join(', ')})`, 'derived') }));
    }
    if (n.type === 'FunctionCall') return this.evalCall(path, fn, n, locals);
    path.markUnresolved(`unsupported expression ${n.type} at ${this.loc(fn, n).line}`);
    return [{ path, value: symbolicValue(this.sourceText(fn, n)), status: 'unresolved' }];
  }

  private evalBinary(path: TransactionPath, fn: FnInfo, n: any, locals: Map<string, SymbolicValue>): Eval[] {
    const op = n.operator;
    const lhs = this.evalExpr(path, fn, n.left, locals);
    const out: Eval[] = [];
    for (const l of lhs) {
      if (l.status) { out.push(l); continue; }
      if (op === '&&' || op === '||') {
        const known = l.value.known ? Boolean(l.value.value) : undefined;
        const shouldEvalRight = known === undefined || (op === '&&' ? known : !known);
        const shortValue = op === '&&' ? false : true;
        for (const arm of l.path.branch(l.value.expression, known)) {
          if (arm.value !== (op === '&&')) {
            out.push({ path: arm.path, value: knownValue(shortValue, String(shortValue), 'derived'), locals: new Map(l.locals ?? locals) });
            continue;
          }
          if (!shouldEvalRight) continue;
          out.push(...this.evalExpr(arm.path, fn, n.right, new Map(l.locals ?? locals)).map(r => ({
            ...r, value: r.value.known ? knownValue(Boolean(r.value.value), r.value.expression, 'derived') : symbolicValue<boolean>(r.value.expression, 'derived'),
          })));
        }
        continue;
      }
      const branchLocals = new Map(l.locals ?? locals);
      const rhs = this.evalExpr(l.path, fn, n.right, branchLocals);
      for (const r of rhs) {
        if (r.status) { out.push(r); continue; }
        if (['=', '+=', '-=', '*=', '/=', '%=', '|=', '&=', '^=', '<<=', '>>='].includes(op)) {
          const target = this.lvalue(r.path, n.left, fn, r.locals ?? branchLocals);
          if (!target) { r.path.markUnresolved(`unsupported assignment target ${this.sourceText(fn, n.left)}`); out.push({ path: r.path, value: symbolicValue('assignment'), status: 'unresolved' }); continue; }
          const before = target.local
            ? (r.locals ?? branchLocals).get(target.name) ?? symbolicValue(`local.${target.name}`, 'unknown_initial_state')
            : target.keys ? r.path.read(target.name, target.keys) : r.path.read(target.name);
          const val = op === '=' ? { value: r.value } : this.compoundAssignment(r.path, fn, op.slice(0, -1), before, r.value, target.integerType);
          if (val.status) { out.push({ ...r, value: val.value, status: val.status }); continue; }
          const resultLocals = new Map(r.locals ?? branchLocals);
          if (target.local) resultLocals.set(target.name, val.value);
          else r.path.write(target.name, val.value, target.keys ?? []);
          out.push({ path: r.path, value: val.value, locals: resultLocals });
        } else out.push({ path: r.path, value: this.compareOrArithmetic(op, l.value, r.value), locals: r.locals ?? branchLocals });
      }
    }
    return out;
  }

  private lvalue(path: TransactionPath, n: any, fn: FnInfo, locals: Map<string, SymbolicValue>): { name: string; keys?: string[]; local?: boolean; integerType?: { bits: number; signed: boolean } } | null {
    if (n?.type === 'Identifier') {
      if (locals.has(n.name)) return { name: n.name, local: true };
      const v = this.index.allVars(path.frame.contract).get(n.name);
      if (v) return { name: n.name, integerType: this.integerType(v.type) };
      return null;
    }
    if (n?.type === 'IndexAccess' && n.base?.type === 'Identifier' && n.index) {
      const variable = this.index.allVars(path.frame.contract).get(n.base.name);
      if (!variable || !['mapping', 'array'].includes(variable.kind)) return null;
      const evaluated = this.evalExpr(path, fn, n.index, locals);
      if (evaluated.length !== 1 || evaluated[0].status) return null;
      const keyValue = evaluated[0].value;
      // Only stable scalar symbolic keys are accepted. Do not alias distinct
      // symbolic expressions or turn an unknown key into source-text identity.
      if (!keyValue.expression || keyValue.expression === this.sourceText(fn, n.index)) return null;
      return { name: n.base.name, keys: [this.storageKeyExpression(keyValue)], integerType: this.integerType(variable.valueType) };
    }
    return null;
  }

  private integerType(type: string): { bits: number; signed: boolean } | undefined {
    const m = type.trim().match(/^(u?int)(\d*)$/);
    if (!m) return undefined;
    const bits = Number(m[2] || 256);
    return bits >= 8 && bits <= 256 && bits % 8 === 0 ? { bits, signed: m[1] === 'int' } : undefined;
  }

  private compilerAtLeast(file: string, major: number, minor: number): boolean {
    const src = this.index.fileSrc.get(file) ?? '';
    const pragma = src.match(/pragma\s+solidity\s+([^;]+);/);
    const version = pragma?.[1].match(/(?:^|[^\d])([0-9]+)\.([0-9]+)(?:\.[0-9]+)?/);
    if (!version) return false;
    const foundMajor = Number(version[1]), foundMinor = Number(version[2]);
    return foundMajor > major || (foundMajor === major && foundMinor >= minor);
  }

  private storageKeyExpression(value: SymbolicValue): string {
    return value.expression;
  }

  private compoundAssignment(path: TransactionPath, fn: FnInfo, op: string, a: SymbolicValue, b: SymbolicValue,
    type?: { bits: number; signed: boolean }): { value: SymbolicValue; status?: 'unresolved' | 'reverted' } {
    const supported = ['%', '|', '&', '^', '<<', '>>'];
    if (!supported.includes(op)) return { value: this.arithmetic(op, a, b) };
    if (!type || type.signed || !b.known || !['number', 'bigint'].includes(typeof b.value) ||
      (a.known && !['number', 'bigint'].includes(typeof a.value))) {
      path.markUnresolved(`unsupported or untyped compound assignment ${op}=`);
      return { value: symbolicValue(`(${a.expression} ${op} ${b.expression})`), status: 'unresolved' };
    }
    if ((op === '<<' || op === '>>') && !this.compilerAtLeast(fn.file, 0, 5)) {
      path.markUnresolved('shift assignment requires a known Solidity compiler version >= 0.5.0');
      return { value: symbolicValue(`(${a.expression} ${op} ${b.expression})`), status: 'unresolved' };
    }
    const y = BigInt(b.value as any), width = BigInt(type.bits), limit = 1n << width;
    if (op === '%' && y === 0n) {
      path.record('call_revert', { reason: 'modulo by zero', operator: '%=' });
      return { value: symbolicValue('modulo by zero'), status: 'reverted' };
    }
    if ((op === '<<' || op === '>>') && y < 0n) {
      path.markUnresolved(`shift amount outside supported uint${type.bits} range`);
      return { value: symbolicValue(`(${a.expression} ${op} ${b.expression})`), status: 'unresolved' };
    }
    if (!a.known) return { value: symbolicValue(`uint${type.bits}(${a.expression} ${op} ${b.expression})`, 'derived') };
    const x = BigInt(a.value as any);
    let value: bigint;
    if (op === '%') value = x % y;
    else if (op === '|') value = x | y;
    else if (op === '&') value = x & y;
    else if (op === '^') value = x ^ y;
    else if (op === '<<') value = y >= width ? 0n : (x << y) % limit;
    else value = y >= width ? 0n : x >> y;
    return { value: knownValue(value, `uint${type.bits}(${a.expression} ${op} ${b.expression})`, 'derived') };
  }

  private arithmetic(op: string, a: SymbolicValue, b: SymbolicValue): SymbolicValue {
    if (this.uncheckedDepth > 0) {
      if (a.known && b.known && Number.isSafeInteger(Number(a.value)) && Number.isSafeInteger(Number(b.value))) {
        const x = BigInt(Number(a.value)), y = BigInt(Number(b.value));
        let value: bigint | undefined;
        if (op === '+') value = x + y;
        if (op === '-') value = x - y;
        if (op === '*') value = x * y;
        if (value !== undefined) {
          const mod = 1n << 256n;
          value = ((value % mod) + mod) % mod;
          return knownValue(value, `unchecked(${a.expression} ${op} ${b.expression})`, 'derived');
        }
      }
      return symbolicValue(`unchecked(${a.expression} ${op} ${b.expression}) mod 2^256`, 'derived');
    }
    if (a.known && b.known) {
      const x = Number(a.value), y = Number(b.value);
      if (op === '+' && Number.isFinite(x + y)) return knownValue(x + y, `(${a.expression} + ${b.expression})`, 'derived');
      if (op === '-' && Number.isFinite(x - y)) return knownValue(x - y, `(${a.expression} - ${b.expression})`, 'derived');
    }
    return symbolicValue(`(${a.expression} ${op} ${b.expression})`);
  }
  private compareOrArithmetic(op: string, a: SymbolicValue, b: SymbolicValue): SymbolicValue {
    if (a.known && b.known) {
      if ((typeof a.value === 'bigint' || typeof a.value === 'number') && (typeof b.value === 'bigint' || typeof b.value === 'number')) {
        const x = BigInt(a.value as any), y = BigInt(b.value as any);
        if (op === '==') return knownValue(x === y, `(${a.expression} == ${b.expression})`, 'derived');
        if (op === '!=') return knownValue(x !== y, `(${a.expression} != ${b.expression})`, 'derived');
        if (op === '<') return knownValue(x < y, `(${a.expression} < ${b.expression})`, 'derived');
        if (op === '>') return knownValue(x > y, `(${a.expression} > ${b.expression})`, 'derived');
        if (op === '<=') return knownValue(x <= y, `(${a.expression} <= ${b.expression})`, 'derived');
        if (op === '>=') return knownValue(x >= y, `(${a.expression} >= ${b.expression})`, 'derived');
        // The V2 sources use the bounded literal expression 10000 ** 2 in the
        // invariant. Evaluate only nonnegative exponents within this narrow,
        // exact integer domain; other arithmetic remains symbolic.
        if (op === '**' && y >= 0n && y <= 256n) {
          const value = x ** y;
          if (value <= (1n << 256n) - 1n) return knownValue(value, `(${a.expression} ** ${b.expression})`, 'derived');
        }
      }
      if (op === '==') return knownValue(a.value === b.value, `(${a.expression} == ${b.expression})`, 'derived');
      if (op === '!=') return knownValue(a.value !== b.value, `(${a.expression} != ${b.expression})`, 'derived');
      if (op === '<') return knownValue(Number(a.value) < Number(b.value), `(${a.expression} < ${b.expression})`, 'derived');
    }
    if (['+', '-', '*', '/', '%', '**', '&', '|', '^', '<<', '>>'].includes(op)) return symbolicValue(`(${a.expression} ${op} ${b.expression})`, 'derived');
    if (['<=', '>='].includes(op)) return symbolicValue(`(${a.expression} ${op} ${b.expression})`, 'derived');
    return symbolicValue(`(${a.expression} ${op} ${b.expression})`);
  }

  private evalCall(path: TransactionPath, fn: FnInfo, n: any, locals: Map<string, SymbolicValue>): Eval[] {
    const name = n.expression?.type === 'Identifier' || n.expression?.type === 'ElementaryTypeName'
      ? n.expression.name : n.expression?.memberName;
    if (name === 'require') {
      const condNode = n.arguments?.[0];
      if (!condNode) { path.markUnresolved('require without supported condition'); return [{ path, value: symbolicValue('require'), status: 'unresolved' }]; }
      return this.evalExpr(path, fn, condNode, locals).flatMap(e => {
        if (e.status) return [e];
        const arms = e.path.branch(e.value.expression, e.value.known ? Boolean(e.value.value) : undefined);
        return arms.map(a => a.value
          ? { path: a.path, value: knownValue(undefined, 'require passed', 'derived'), locals: new Map(e.locals ?? locals) }
          : { path: a.path, value: symbolicValue('require reverted'), status: 'reverted' as const, locals: new Map(e.locals ?? locals) });
      });
    }
    if (name === 'revert') return [{ path, value: symbolicValue(this.sourceText(fn, n)), status: 'reverted' }];
    if (name === 'decode' && n.expression?.type === 'MemberAccess' && n.expression.expression?.type === 'Identifier' && n.expression.expression.name === 'abi') {
      const dataNode = n.arguments?.[0];
      const dataValue = dataNode?.type === 'Identifier' ? locals.get(dataNode.name) : undefined;
      const typeText = n.arguments?.[1] ? this.sourceText(fn, n.arguments[1]) : '';
      if (!dataValue || !/\bbool\b/.test(typeText)) {
        path.markUnresolved(`unsupported ABI decode ${this.sourceText(fn, n)}`);
        return [{ path, value: symbolicValue('abi.decode'), status: 'unresolved' }];
      }
      const decoded = TransactionPath.decodeBoolReturnResult(dataValue.value as ReturnData);
      if (decoded.status === 'decoded') return [{ path, value: decoded.value }];
      if (decoded.status === 'revert_candidate') return [{ path, value: symbolicValue(`abi.decode(bool): ${decoded.reason}`), status: 'reverted' }];
      path.markUnresolved('ABI bool return data is unknown or unsupported');
      return [{ path, value: decoded.value, status: 'unresolved' }];
    }
    // Narrow identity forms needed by inherited ERC20 transfer guards. Other
    // conversions (especially narrowing numeric casts) remain unresolved.
    if (name === 'address') {
      const arg = n.arguments?.[0];
      if (n.arguments?.length === 1 && arg?.type === 'NumberLiteral' && String(arg.number) === '0') {
        return [{ path, value: knownValue('address(0)', 'address(0)') }];
      }
      if (n.arguments?.length === 1 && arg?.type === 'Identifier' && arg.name === 'this') {
        return [{ path, value: symbolicValue(`address(this@${path.frame.contractInstance})`) }];
      }
      path.markUnresolved(`unsupported address conversion ${this.sourceText(fn, n)}`);
      return [{ path, value: symbolicValue(this.sourceText(fn, n)), status: 'unresolved' }];
    }
    const member = n.expression?.type === 'MemberAccess' ? n.expression : null;
    if (member && this.isLibraryCall(fn, member, n.arguments?.length ?? 0)) return this.libraryCall(path, fn, n, member, locals);
    if (member && ['add', 'sub', 'mul', 'div'].includes(name)) return this.safeMathCall(path, fn, n, member, locals, name);
    if ((n.expression?.type === 'Identifier' || n.expression?.type === 'ElementaryTypeName') && /^(u?int)([0-9]*)$/.test(name) && n.arguments?.length === 1) {
      const type = name.match(/^(u?int)([0-9]*)$/)!;
      const bits = Number(type[2] || 256);
      if (type[1] === 'uint' && bits >= 8 && bits <= 256 && bits % 8 === 0) {
        const arg = n.arguments[0];
        if (arg?.type === 'UnaryOperation' && arg.operator === '-' && arg.subExpression?.type === 'NumberLiteral' && String(arg.subExpression.number) === '1') {
          return [{ path, value: knownValue((1n << BigInt(bits)) - 1n, `${name}(-1)`, 'derived') }];
        }
        const values = this.evalExpr(path, fn, arg, locals);
        return values.map(v => ({ ...v, value: v.status ? v.value : symbolicValue(`${name}(${v.value.expression})`, 'derived') }));
      }
    }
    if (member?.memberName === 'call') return this.lowLevelExternalCall(path, fn, n, member, locals);
    if (member) return this.externalCall(path, fn, n, member, locals);
    if (n.expression?.type === 'Identifier') return this.internalCall(path, fn, n, locals, name);
    path.markUnresolved(`unsupported function call ${this.sourceText(fn, n)}`);
    return [{ path, value: symbolicValue(this.sourceText(fn, n)), status: 'unresolved' }];
  }

  /** SafeMath is an internal library-style call in the V2 sources. Model only
   * its arithmetic and the explicit underflow/overflow failure boundary. */
  private safeMathCall(path: TransactionPath, fn: FnInfo, call: any, member: any, locals: Map<string, SymbolicValue>, op: string): Eval[] {
    const left = this.evalExpr(path, fn, member.expression, locals);
    const out: Eval[] = [];
    for (const l of left) {
      if (l.status) { out.push(l); continue; }
      const args = call.arguments ?? [];
      if (args.length !== 1) { l.path.markUnresolved(`unsupported SafeMath.${op} arity`); out.push({ path: l.path, value: symbolicValue(`SafeMath.${op}`), status: 'unresolved' }); continue; }
      for (const r of this.evalExpr(l.path, fn, args[0], locals)) {
        if (r.status) { out.push(r); continue; }
        if (op === 'sub') {
          if (l.value.known && r.value.known) {
            const value = Number(l.value.value) - Number(r.value.value);
            if (value < 0) { r.path.record('call_revert', { callee: 'SafeMath.sub', reason: 'underflow' }); out.push({ path: r.path, value: symbolicValue('SafeMath: subtraction overflow'), status: 'reverted' }); }
            else out.push({ path: r.path, value: knownValue(value, `(${l.value.expression} - ${r.value.expression})`, 'derived') });
          } else {
            const arms = r.path.branch(`${l.value.expression} >= ${r.value.expression}`);
            for (const arm of arms) out.push(arm.value
              ? { path: arm.path, value: symbolicValue(`(${l.value.expression} - ${r.value.expression})`, 'derived') }
              : { path: arm.path, value: symbolicValue('SafeMath: subtraction overflow'), status: 'reverted' });
          }
          continue;
        }
        out.push({ path: r.path, value: this.arithmetic(op === 'div' ? '/' : op, l.value, r.value) });
      }
    }
    return out;
  }

  private internalCall(path: TransactionPath, fn: FnInfo, call: any, locals: Map<string, SymbolicValue>, name: string): Eval[] {
    const argsNodes = call.arguments ?? [];
    let variants: { path: TransactionPath; args: SymbolicValue[] }[] = [{ path, args: [] }];
    const terminal: Eval[] = [];
    for (const arg of argsNodes) {
      const next: typeof variants = [];
      for (const variant of variants) for (const value of this.evalExpr(variant.path, fn, arg, locals)) {
        if (value.status) { terminal.push(value); continue; }
        next.push({ path: value.path, args: [...variant.args, value.value] });
      }
      variants = next;
    }
    if (!variants.length) return terminal;
    const candidates = this.index.findFns(path.frame.contract, name, argsNodes.length);
    if (candidates.length !== 1) {
      for (const variant of variants) variant.path.markUnresolved(`internal function body unresolved or ambiguous: ${path.frame.contract}.${name}/${argsNodes.length}`);
      return variants.map(v => ({ path: v.path, value: symbolicValue(`return.${name}`), status: 'unresolved' }));
    }
    return [...terminal, ...this.invokeInternalCallee(variants, candidates[0], name, this.loc(fn, call))];
  }

  private invokeInternalCallee(variants: { path: TransactionPath; args: SymbolicValue[] }[], callee: FnInfo, name: string, site: Loc): Eval[] {
    const out: Eval[] = [];
    for (const variant of variants) {
      const child = variant.path.clone();
      child.enterInternalFrame(callee.name, variant.args, site, { contract: callee.contract, source: callee.file, line: callee.line });
      const outcomes = this.executeFunction(child, callee, variant.args);
      for (const outcome of outcomes) {
        if (outcome.status === 'returned') {
          outcome.path.leaveInternalFrame(outcome.value);
          out.push({ path: outcome.path, value: outcome.value ?? knownValue(undefined, `return.${name}`, 'derived') });
        } else if (outcome.status === 'reverted') {
          outcome.path.record('call_revert', { callee: `${callee.contract}.${callee.name}`, callSite: site, reason: 'source-level internal revert' });
          out.push({ path: outcome.path, value: outcome.value ?? symbolicValue(`revert.${name}`), status: 'reverted' });
        } else {
          if (outcome.path.transactionStatus !== 'unresolved') outcome.path.markUnresolved(`internal call unresolved: ${callee.contract}.${callee.name}`);
          out.push({ path: outcome.path, value: symbolicValue(`return.${name}`), status: 'unresolved' });
        }
      }
    }
    return out;
  }

  private isLibraryCall(fn: FnInfo, member: any, argc: number): boolean {
    if (member.expression?.type === 'Identifier') {
      return this.index.findFns(member.expression.name, member.memberName, argc).some(candidate => candidate.isLibrary);
    }
    return this.index.usingLibs(fn.contract).some(lib =>
      this.index.findFns(lib, member.memberName, argc + 1).some(candidate => candidate.isLibrary));
  }

  /** Execute a library function's parsed body in the current contract instance. */
  private libraryCall(path: TransactionPath, fn: FnInfo, call: any, member: any, locals: Map<string, SymbolicValue>): Eval[] {
    const direct = member.expression?.type === 'Identifier' && this.index.findFns(member.expression.name, member.memberName, (call.arguments ?? []).length)
      .some(candidate => candidate.isLibrary);
    const arity = (call.arguments ?? []).length + (direct ? 0 : 1);
    const libraries = direct ? [member.expression.name] : this.index.usingLibs(fn.contract);
    const candidates = libraries.flatMap(lib => this.index.findFns(lib, member.memberName, arity).filter(candidate => candidate.isLibrary));
    if (candidates.length !== 1) {
      path.markUnresolved(`library function body unresolved or ambiguous: ${member.memberName}/${arity}`);
      return [{ path, value: symbolicValue(`library.${member.memberName}`), status: 'unresolved' }];
    }
    const callee = candidates[0];
    const nodes = direct ? (call.arguments ?? []) : [member.expression, ...(call.arguments ?? [])];
    let variants: { path: TransactionPath; args: SymbolicValue[] }[] = [{ path, args: [] }];
    const terminal: Eval[] = [];
    for (const node of nodes) {
      const next: typeof variants = [];
      for (const variant of variants) for (const value of this.evalExpr(variant.path, fn, node, locals)) {
        if (value.status) { terminal.push(value); continue; }
        next.push({ path: value.path, args: [...variant.args, value.value] });
      }
      variants = next;
    }
    if (!variants.length) return terminal;
    return [...terminal, ...this.invokeInternalCallee(variants, callee, member.memberName, this.loc(fn, call))];
  }

  private externalCall(path: TransactionPath, fn: FnInfo, call: any, member: any, locals: Map<string, SymbolicValue>): Eval[] {
    const site = this.loc(fn, call);
    const target = this.resolveBoundTarget(path, member.expression, locals);
    if (!target) {
      const result = path.unresolvedCall(`unresolved external receiver ${this.sourceText(fn, member.expression)}`, site);
      return [{ path: result.path, value: symbolicValue('external return'), status: 'unresolved' }];
    }
    const argNodes = call.arguments ?? [];
    // Arguments are evaluated in source order. This bounded adapter accepts a single
    // deterministic value per argument; ambiguous argument behavior stays unresolved.
    let variants: { path: TransactionPath; args: SymbolicValue[] }[] = [{ path, args: [] }];
    const terminal: Eval[] = [];
    for (const arg of argNodes) {
      const next: typeof variants = [];
      for (const v of variants) for (const e of this.evalExpr(v.path, fn, arg, locals)) {
        if (e.status) { terminal.push(e); continue; }
        next.push({ path: e.path, args: [...v.args, e.value] });
      }
      variants = next;
    }
    if (!variants.length) return terminal;
    const candidates = this.index.findFns(target.contract, member.memberName, variants[0]?.args.length ?? 0);
    if (candidates.length !== 1) {
      return variants.map(v => {
        v.path.markUnresolved(`external target body unresolved or ambiguous: ${target.contract}.${member.memberName}`);
        return { path: v.path, value: symbolicValue('external return'), status: 'unresolved' as const };
      });
    }
    const callee = candidates[0];
    const callKind = callee.mutability === 'view' || callee.mutability === 'pure' ? 'static_call' : 'high_level';
    return [...terminal, ...this.executeExternalCall(variants, target.id, callee, site, callKind, false)];
  }

  private resolveBoundTarget(path: TransactionPath, receiverNode: any, locals: Map<string, SymbolicValue>) {
    const current = path.frame.contractInstance;
    const receiver = receiverNode?.type === 'FunctionCall' && receiverNode.expression?.type === 'Identifier'
      ? receiverNode.arguments?.[0]
      : receiverNode;
    const variables: string[] = [];
    if (receiver?.type === 'Identifier') {
      const local = locals.get(receiver.name);
      const origin = local?.expression.match(/^storage\[([^\]]+)\]\.([A-Za-z_$][\w$]*)$/);
      if (origin) variables.push(`${origin[1]}.${origin[2]}`, origin[2]);
      variables.push(receiver.name);
      // The real V2 sources commonly copy token0/token1 into `_token0`/`_token1`
      // locals before making interface calls. Keep this alias narrow and require
      // the caller's explicit source-analysis binding to resolve it.
      if (/^_+token[01]$/.test(receiver.name)) variables.push(receiver.name.replace(/^_+/, ''));
    } else if (receiver?.type === 'MemberAccess') {
      variables.push(this.sourceText({ file: path.frame.callSite?.source ?? '' } as FnInfo, receiver));
    }
    for (const variable of variables) {
      const id = this.bindings.receivers?.[`${current}.${variable}`] ?? this.bindings.receivers?.[variable];
      if (!id) continue;
      const target = this.instances.find(i => i.id === id);
      if (target) return target;
    }
    return undefined;
  }

  private executeExternalCall(variants: { path: TransactionPath; args: SymbolicValue[] }[], targetId: string, callee: FnInfo, site: Loc,
    callKind: 'high_level' | 'low_level' | 'static_call', lowLevel: boolean): Eval[] {
    const out: Eval[] = [];
    for (const variant of variants) {
      const start = variant.path.clone();
      const checkpoint = new Map(start.storage);
      const writeStart = start.writes.length;
      start.enterExternalFrame(targetId, callee.name, variant.args, site, callKind);
      const externalFrameIndex = start.frames.length - 1;
      const outcomes = this.executeFunction(start, callee, variant.args);
      for (const outcome of outcomes) {
        const newlyWrote = outcome.path.writes.length > writeStart;
        if (outcome.status === 'returned' && callKind === 'static_call' && newlyWrote) {
          const data = outcome.path.failExternalFrame('state modification attempted during STATICCALL', site, callKind, checkpoint, writeStart, externalFrameIndex);
          out.push({ path: outcome.path, value: symbolicValue(`revert(${data.reason})`), status: 'reverted' });
          continue;
        }
        if (outcome.status === 'returned') {
          const returnData = this.returnDataFor(callee, outcome.value);
          outcome.path.leaveExternalFrame(outcome.value, returnData, callKind);
          if (lowLevel) {
            const success = knownValue(true, 'lowLevelCall.success', 'call_result');
            out.push({ path: outcome.path, value: knownValue([success, knownValue(returnData, 'lowLevelCall.data', 'call_result')], 'lowLevelCall result', 'call_result') });
          } else out.push({ path: outcome.path, value: outcome.value ?? symbolicValue(`return.${callee.name}`, 'call_result') });
          continue;
        }
        if (outcome.status === 'reverted') {
          const data = outcome.path.failExternalFrame('source-level revert in resolved callee', site, callKind, checkpoint, writeStart, externalFrameIndex);
          if (lowLevel) {
            const success = knownValue(false, 'lowLevelCall.success', 'call_result');
            out.push({ path: outcome.path, value: knownValue([success, knownValue(data, 'lowLevelCall.data', 'call_result')], 'lowLevelCall result', 'call_result') });
          } else out.push({ path: outcome.path, value: symbolicValue('external revert'), status: 'reverted' });
          continue;
        }
        if (outcome.path.transactionStatus !== 'unresolved') outcome.path.markUnresolved(`external call unresolved: ${callee.contract}.${callee.name}`);
        out.push({ path: outcome.path, value: symbolicValue(`return.${callee.name}`, 'call_result'), status: 'unresolved' });
      }
    }
    return out;
  }

  private returnDataFor(callee: FnInfo, value?: SymbolicValue): ReturnData {
    if (!callee.returns.length) return { status: 'known', bytesHex: '0x' };
    if (value?.known && typeof value.value === 'boolean') return TransactionPath.encodeBoolReturn(Boolean(value.value));
    return { status: 'unknown', reason: `return data for ${callee.contract}.${callee.name} is not modeled` };
  }

  private lowLevelExternalCall(path: TransactionPath, fn: FnInfo, call: any, member: any, locals: Map<string, SymbolicValue>): Eval[] {
    const site = this.loc(fn, call);
    const target = this.resolveBoundTarget(path, member.expression, locals);
    if (!target) {
      const unresolved = path.unresolvedCall(`unresolved low-level call target ${this.sourceText(fn, member.expression)}`, site);
      return [{ path: unresolved.path, value: symbolicValue('lowLevelCall result'), status: 'unresolved' }];
    }
    const payload = call.arguments?.[0];
    const encode = payload?.type === 'FunctionCall' && payload.expression?.type === 'MemberAccess' && payload.expression.expression?.type === 'Identifier' && payload.expression.expression.name === 'abi' && payload.expression.memberName === 'encodeWithSelector'
      ? payload : null;
    const selectorNode = encode?.arguments?.[0];
    if (!encode || selectorNode?.type !== 'Identifier') {
      path.markUnresolved(`unsupported low-level calldata encoding ${this.sourceText(fn, payload)}`);
      return [{ path, value: symbolicValue('lowLevelCall result'), status: 'unresolved' }];
    }
    const vars = this.index.allVars(fn.contract);
    const selectorDecl = vars.get(selectorNode.name);
    const signatureMatch = selectorDecl?.initial?.match(/bytes\s*\(\s*(['"])(.*?)\1\s*\)/);
    if (!signatureMatch) {
      path.markUnresolved(`cannot derive selector ${selectorNode.name} from source constant`);
      return [{ path, value: symbolicValue('lowLevelCall result'), status: 'unresolved' }];
    }
    const selector = selectorForSignature(signatureMatch[2]);
    const argsNodes = encode.arguments.slice(1);
    let variants: { path: TransactionPath; args: SymbolicValue[] }[] = [{ path, args: [] }];
    const terminal: Eval[] = [];
    for (const arg of argsNodes) {
      const next: typeof variants = [];
      for (const variant of variants) for (const value of this.evalExpr(variant.path, fn, arg, locals)) {
        if (value.status) { terminal.push(value); continue; }
        next.push({ path: value.path, args: [...variant.args, value.value] });
      }
      variants = next;
    }
    if (!variants.length) return terminal;
    const candidateName = signatureMatch[2].slice(0, signatureMatch[2].indexOf('('));
    const candidates = this.index.findFns(target.contract, candidateName, argsNodes.length)
      .filter(candidate => selectorForSignature(`${candidateName}(${candidate.params.map(p => this.canonicalAbiType(p.type)).join(',')})`) === selector);
    if (candidates.length !== 1) {
      for (const variant of variants) variant.path.markUnresolved(`selector ${selector} does not resolve uniquely in ${target.contract}`);
      return variants.map(v => ({ path: v.path, value: symbolicValue('lowLevelCall result'), status: 'unresolved' }));
    }
    return [...terminal, ...this.executeExternalCall(variants, target.id, candidates[0], site, 'low_level', true)];
  }

  private canonicalAbiType(type: string): string {
    if (type === 'uint') return 'uint256';
    if (type === 'int') return 'int256';
    return type.replace(/\s+memory|\s+calldata|\s+storage/g, '').trim();
  }
}
