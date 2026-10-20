// token-walker :: engine.ts — un-pruned symbolic path walker (statements, expressions, calls)
import { Index, FnInfo, VarInfo } from './parse';
import { WalkerConfig, Diagnostics, PathRec, RevertGuard, KeyClass, CallEv, WriteEv, Ev } from './types';
import { State, Lv, adopt, canon, stripParens, splitTop, splitCommaTop, wrapsWhole } from './state';

interface Res { st: State; v: string; parts?: string[] | null }
export interface EntryResult { paths: PathRec[]; reverts: RevertGuard[]; truncated: boolean; enumerated: number }

const ELEM = /^(u?int\d*|bytes\d*|bool|string|address|byte)$/;
const ARITH: Record<string, string> = { add: '+', sub: '-', mul: '*', div: '/', mod: '%' };
const VIEW_EXT = new Set(['WETH', 'factory', 'getPair', 'getReserves', 'balanceOf', 'totalSupply', 'allowance', 'getAmountsOut',
  'getAmountsIn', 'getAmountOut', 'getAmountIn', 'quote', 'decimals', 'name', 'symbol', 'token0', 'token1', 'kLast',
  'latestRoundData', 'latestAnswer', 'slot0', 'liquidity', 'owner', 'supportsInterface', 'price0CumulativeLast', 'price1CumulativeLast']);
const BUILTIN_FN = new Set(['keccak256', 'sha256', 'ripemd160', 'ecrecover', 'addmod', 'mulmod', 'blockhash', 'gasleft', 'type', 'abi']);

export class Walker {
  vars: Map<string, VarInfo>;
  reverts = new Map<string, RevertGuard>();
  truncated = false;
  entryParams = new Set<string>();
  private warned = new Set<string>();

  constructor(private ix: Index, private target: string, private cfg: WalkerConfig, private diag: Diagnostics) {
    this.vars = ix.allVars(target);
  }

  private warn(list: string[], msg: string) { const k = list === this.diag.warnings ? 'w:' + msg : 'u:' + msg; if (!this.warned.has(k)) { this.warned.add(k); list.push(msg); } }

  // ───────────────────────── entry runners ─────────────────────────
  runEntry(fn: FnInfo): EntryResult {
    this.reverts = new Map(); this.truncated = false;
    this.entryParams = new Set(fn.params.map((p, i) => p.name || `_p${i}`));
    const st = new State();
    const key = `${fn.contract}.${fn.name}`;
    const frame = st.top;
    fn.params.forEach((p, i) => frame.set(p.name || `_p${i}`, p.name || `_p${i}`));
    fn.returns.forEach(r => { if (r.name) frame.set(r.name, '0'); });
    st.fnStack.push(key); st.chain.push(key);
    if (fn.mutability === 'payable' || fn.kind === 'receive') {
      st.trace.push({ k: 'W', var: '$native_balance', key: 'this', keyClass: 'this', op: '+=', operand: 'msg.value', delta: '$native_balance[this] += msg.value', expr: 'msg.value', line: fn.line, fn: key, inLoop: false });
    }
    const res = this.runWithModifiers(fn, 0, st, 0);
    return this.finish(res);
  }

  runConstructor(): EntryResult {
    this.reverts = new Map(); this.truncated = false; this.entryParams = new Set();
    const st = new State(); st.fnStack.push(`${this.target}.constructor`); st.chain.push(`${this.target}.constructor`);
    for (const cn of [...this.ix.lin(this.target)].reverse()) {
      for (const v of this.ix.contracts.get(cn)!.vars.values()) {
        if (v.constant || v.initial === null) continue;
        st.trace.push({ k: 'W', var: v.name, key: null, keyClass: 'none', op: '=', operand: v.initial, delta: `${v.name} = ${v.initial}`, expr: v.initial, line: v.line, fn: `${cn}.<initializer>`, inLoop: false });
      }
    }
    let states: State[] = [st];
    for (const cn of [...this.ix.lin(this.target)].reverse()) {
      const ctor = this.ix.contracts.get(cn)!.fns.find(f => f.kind === 'constructor');
      if (!ctor) continue;
      const next: State[] = [];
      for (const s of states) {
        const args = ctor.params.map((p, i) => p.name || `_p${i}`);
        for (const r of this.callInline(ctor, args, s, `${cn}.constructor`)) next.push(r.st);
      }
      states = next;
    }
    return this.finish(states);
  }

  private finish(states: State[]): EntryResult {
    const done = states.filter(s => s.halt !== 'revert');
    const paths: PathRec[] = done.map(s => ({ chain: s.chain, constraints: s.conds, eqFacts: s.eq, trace: s.trace, flags: s.flags, ret: s.ret }));
    return { paths, reverts: [...this.reverts.values()], truncated: this.truncated, enumerated: states.length };
  }

  // ───────────────────────── statements ─────────────────────────
  private execStmts(stmts: any[], states: State[]): State[] {
    let cur = states;
    for (const s of stmts) {
      const next: State[] = [];
      for (const st of cur) {
        if (st.halt !== 'none') { next.push(st); continue; }
        for (const r of this.execStmt(s, st)) next.push(r);
      }
      cur = next;
      if (cur.length > this.cfg.maxPathsPerEntry) { cur.length = this.cfg.maxPathsPerEntry; this.truncated = true; }
    }
    return cur;
  }

  private execStmt(n: any, st: State): State[] {
    if (!n) return [st];
    const line = n.loc?.start.line ?? 0;
    switch (n.type) {
      case 'Block': case 'UncheckedStatement': return this.execStmts(n.statements, [st]);
      case 'ExpressionStatement': {
        const e = n.expression;
        if (e.type === 'Identifier' && e.name === '_' && st.modStack.length) return this.placeholder(st);
        return this.evalExpr(e, st).map(r => r.st);
      }
      case 'VariableDeclarationStatement': return this.execVarDecl(n, st);
      case 'IfStatement': return this.execIf(n, st, line);
      case 'ForStatement': case 'WhileStatement': case 'DoWhileStatement': return this.execLoop(n, st, line);
      case 'ReturnStatement': {
        if (!n.expression) { st.halt = 'return'; return [st]; }
        return this.evalExpr(n.expression, st).map(r => { r.st.ret = r.v; r.st.retParts = r.parts ?? null; r.st.halt = 'return'; return r.st; });
      }
      case 'EmitStatement': {
        let cur: State[] = [st];
        for (const a of n.eventCall.arguments) { const nx: State[] = []; for (const s of cur) for (const r of this.evalExpr(a, s)) nx.push(r.st); cur = nx; }
        return cur;
      }
      case 'RevertStatement': st.halt = 'revert'; this.recordRevert('(unconditional)', 'revert', line, st.curFn); return [st];
      case 'BreakStatement': case 'ContinueStatement': st.halt = 'break'; return [st];
      case 'TryStatement': return this.execTry(n, st);
      case 'InlineAssemblyStatement': st.addFlag('unmodeled_assembly'); this.warn(this.diag.warnings, `inline assembly in ${st.curFn} (line ${line}) is NOT modeled — sstore/call effects missing`); return [st];
      default: this.warn(this.diag.unsupported_nodes, `${n.type} (line ${line})`); return [st];
    }
  }

  private execVarDecl(n: any, st: State): State[] {
    const out: State[] = [];
    const vars: any[] = n.variables;
    if (!n.initialValue) { for (const v of vars) if (v) st.top.set(v.name, '0'); return [st]; }
    for (const r of this.evalExpr(n.initialValue, st)) {
      const s = r.st;
      if (vars.length === 1 && vars[0]) {
        const v = vars[0];
        s.top.set(v.name, r.v);
        if (v.storageLocation === 'storage') { const lv = this.lvFromNode(n.initialValue, s, true); if (lv) s.refs.set(v.name, lv); }
      } else {
        vars.forEach((v, i) => { if (v) s.top.set(v.name, r.parts?.[i] ?? `${r.v}#${i}`); });
      }
      out.push(s);
    }
    return out;
  }

  private execIf(n: any, st: State, line: number): State[] {
    const out: State[] = [];
    for (const r of this.evalExpr(n.condition, st)) {
      const s = r.st; const known = this.decide(s, r.v);
      const doT = known !== false; const doF = known !== true;
      if (doT) {
        const t = doF ? s.clone() : s; if (known === null) this.assume(t, r.v, 'T', 'if', line);
        for (const x of this.execStmt(n.trueBody, t)) { if (x.halt === 'revert') this.recordRevert(stripParens(r.v), 'if-revert', line, x.curFn); out.push(x); }
      }
      if (doF) {
        if (known === null) this.assume(s, r.v, 'F', 'if', line);
        if (n.falseBody) { for (const x of this.execStmt(n.falseBody, s)) out.push(x); } else out.push(s);
      }
    }
    return out;
  }

  private execLoop(n: any, st: State, line: number): State[] {
    let starts: State[] = [st];
    if (n.type === 'ForStatement' && n.initExpression) {
      starts = this.execStmt(n.initExpression, st);
      for (const s of starts) if (n.initExpression.type === 'VariableDeclarationStatement')
        for (const v of n.initExpression.variables) if (v) { s.top.set(v.name, v.name); s.loopVars.add(v.name); }
    }
    const out: State[] = [];
    for (const s0 of starts) {
      const condNode = n.type === 'ForStatement' ? n.conditionExpression : n.condition;
      const conds: Res[] = condNode ? this.evalExpr(condNode, s0) : [{ st: s0, v: 'true' }];
      for (const r of conds) {
        const s = r.st;
        const skip = s.clone(); this.assume(skip, r.v, 'F', 'loop', line); out.push(skip);          // 0 iterations
        this.assume(s, r.v, 'T', 'loop', line); s.loopDepth++;                                        // 1 iteration
        s.addFlag('loop_unrolled_once');
        for (const b of this.execStmt(n.body, s)) {
          if (b.halt === 'break') b.halt = 'none';
          if (b.halt === 'none' && n.type === 'ForStatement' && n.loopExpression) {
            for (const x of this.execStmt(n.loopExpression, b)) { x.loopDepth--; out.push(x); }
          } else { b.loopDepth--; out.push(b); }
        }
      }
    }
    return out;
  }

  private execTry(n: any, st: State): State[] {
    const out: State[] = [];
    for (const r of this.evalExpr(n.expression, st)) {
      const ok = r.st.clone();
      (n.returnParameters || []).forEach((p: any, i: number) => { if (p?.name) ok.top.set(p.name, `${r.v}#${i}`); });
      for (const x of this.execStmt(n.body, ok)) out.push(x);
      for (const c of n.catchClauses || []) { const cs = r.st.clone(); for (const x of this.execStmt(c.body, cs)) out.push(x); }
    }
    return out;
  }

  // ───────────────────────── constraints ─────────────────────────
  private decide(st: State, cond: string): boolean | null {
    const { t, neg } = canon(cond);
    if (t === 'true') return !neg; if (t === 'false') return neg;
    const d = st.decided.get(t);
    return d === undefined ? null : (neg ? !d : d);
  }
  private assume(st: State, cond: string, arm: 'T' | 'F', kind: any, line: number) {
    const text = stripParens(cond);
    st.conds.push({ text: arm === 'T' ? text : `!(${text})`, arm, kind, line, fn: st.curFn });
    const { t, neg } = canon(cond);
    const truth = arm === 'T' ? !neg : neg;
    st.decided.set(t, truth);
    const parts = truth ? splitTop(t, '&&') : splitTop(t, '||');
    if (parts.length > 1 && !(truth ? t.includes('||') : t.includes('&&')))
      for (const p of parts) { const c = canon(p); st.decided.set(c.t, truth ? !c.neg : c.neg); }
    const facts = (truth ? splitTop(t, '&&') : []).concat(truth ? [] : splitTop(t, '||'));
    for (const f of (parts.length > 1 && !(truth ? t.includes('||') : t.includes('&&')) ? parts : [t])) {
      const c = canon(f); const tr = truth ? !c.neg : c.neg;
      const m = /^(.+?) (==|!=) (.+)$/.exec(c.t);
      if (m && ((m[2] === '==') === tr)) st.eq.push(`${m[1]} == ${m[3]}`);
    }
    void facts;
  }
  private requireLike(st: State, cond: string, kind: string, line: number) {
    const known = this.decide(st, cond);
    if (known === true) return;
    this.recordRevert(stripParens(cond), kind, line, st.curFn);
    if (known === false) { st.halt = 'revert'; return; }
    this.assume(st, cond, 'T', 'require', line);
  }
  private recordRevert(cond: string, kind: string, line: number, fn: string) {
    const k = `${fn}|${line}|${cond}`; const g = this.reverts.get(k);
    if (g) g.count++; else this.reverts.set(k, { cond, kind, line, fn, count: 1 });
  }

  // ───────────────────────── modifiers / calls ─────────────────────────
  private runWithModifiers(fn: FnInfo, idx: number, st: State, fnFrameIdx: number): State[] {
    const mods = fn.modifiers.filter(m => this.ix.findModifier(this.target, m.name));
    if (idx >= mods.length) return this.execStmts(fn.node.body.statements, [st]);
    const m = mods[idx]; const md = this.ix.findModifier(this.target, m.name)!;
    const args: string[] = [];
    for (const a of m.args) args.push(this.evalPure(a, st));
    const frame = new Map<string, string>(); md.params.forEach((p, i) => frame.set(p.name, args[i] ?? p.name));
    st.frames.push(frame); st.modStack.push({ fn, mods, idx, frameIdx: fnFrameIdx });
    st.chain.push(`modifier:${md.contract}.${md.name}`);
    const res = this.execStmts(md.node.body.statements, [st]);
    for (const r of res) { r.modStack.pop(); r.frames.length = fnFrameIdx + 1; if (r.halt === 'return') r.halt = 'none'; }
    return res;
  }

  private placeholder(st: State): State[] {
    const top = st.modStack[st.modStack.length - 1];
    const stash = st.frames.splice(top.frameIdx + 1);          // hide modifier frames while body runs
    const res = this.runWithModifiers(top.fn, top.idx + 1, st, top.frameIdx);
    for (const r of res) {
      r.frames.length = top.frameIdx + 1;
      for (const f of stash) r.frames.push(new Map(f));
      if (r.halt === 'return') r.halt = 'none';               // modifier epilogue still runs after body `return`
    }
    return res;
  }

  private callFn(fn: FnInfo, args: string[], st: State): Res[] {
    const key = `${fn.contract}.${fn.name}`;
    if (st.fnStack.length >= this.cfg.maxCallDepth || st.fnStack.filter(x => x === key).length >= 2) {
      st.addFlag(`depth_limit:${key}`); this.warn(this.diag.warnings, `call depth/recursion limit hit at ${key} — callee effects missing on some paths`);
      return [{ st, v: `${fn.name}(${args.join(', ')})` }];
    }
    if (fn.mutability === 'view' || fn.mutability === 'pure') return this.callView(fn, args, st, key);
    return this.callInline(fn, args, st, key);
  }

  private callInline(fn: FnInfo, args: string[], st: State, key: string): Res[] {
    const frame = new Map<string, string>();
    fn.params.forEach((p, i) => frame.set(p.name || `_p${i}`, args[i] ?? p.name));
    fn.returns.forEach(r => { if (r.name) frame.set(r.name, '0'); });
    st.frames.push(frame); const idx = st.frames.length - 1;
    st.fnStack.push(key); st.chain.push(key);
    const res = this.runWithModifiers(fn, 0, st, idx);
    const out: Res[] = [];
    for (const r of res) {
      let v = r.ret ?? ''; let parts = r.retParts;
      if (r.ret === null && fn.returns.length) {
        const fr = r.frames[idx];
        const vals = fn.returns.map(x => (x.name && fr?.get(x.name)) || '0');
        if (vals.length === 1) v = vals[0]; else { parts = vals; v = `(${vals.join(', ')})`; }
      }
      r.frames.length = idx; r.fnStack.pop(); if (r.halt === 'return') r.halt = 'none';
      r.ret = null; r.retParts = null;
      out.push({ st: r, v, parts });
    }
    return out;
  }

  /** view/pure callee: explore on a clone, keep union of READ/CALL events, return value if single-path */
  private callView(fn: FnInfo, args: string[], st: State, key: string): Res[] {
    const base = st.trace.length;
    const sub = st.clone();
    const res = this.callInline(fn, args, sub, key);
    const seen = new Set<string>(); const evs: Ev[] = [];
    for (const r of res) for (const e of r.st.trace.slice(base)) { const j = JSON.stringify(e); if (!seen.has(j)) { seen.add(j); evs.push(e); } }
    st.trace.push(...evs); st.chain.push(key);
    for (const r of res) for (const f of r.st.flags) st.addFlag(f);
    if (res.some(r => r.st.halt === 'revert')) { /* reverts in views are recorded globally */ }
    const live = res.filter(r => r.st.halt !== 'revert');
    if (live.length === 1) return [{ st, v: live[0].v, parts: live[0].parts }];
    return [{ st, v: `${fn.name}(${args.join(', ')})` }];
  }

  // ───────────────────────── expressions ─────────────────────────
  evalPure(n: any, st: State): string {
    const rs = this.evalExpr(n, st);
    if (rs.length > 1) this.warn(this.diag.warnings, `forking call inside key/arg expression ignored (${st.curFn} line ${n.loc?.start.line})`);
    adopt(st, rs[0].st); return rs[0].v;
  }

  private isLocal(name: string, st: State): boolean { return st.top.has(name); }
  private isStateVar(name: string, st: State): boolean { return !this.isLocal(name, st) && this.vars.has(name); }

  /** resolve an lvalue/rvalue access path rooted at a state variable (or a storage-pointer local) */
  private lvFromNode(n: any, st: State, quiet = false): Lv | null {
    const keyNodes: any[] = []; const fields: string[] = []; let cur = n;
    for (;;) {
      if (cur.type === 'IndexAccess') { keyNodes.unshift(cur.index); cur = cur.base; }
      else if (cur.type === 'MemberAccess') { fields.unshift(cur.memberName); cur = cur.expression; }
      else break;
    }
    if (cur.type !== 'Identifier') return null;
    let base: Lv | null = null;
    if (this.isLocal(cur.name, st)) { const ref = st.refs.get(cur.name); if (!ref) return null; base = { name: ref.name, keys: [...ref.keys], fields: [...ref.fields] }; }
    else if (this.vars.has(cur.name)) base = { name: cur.name, keys: [], fields: [] };
    if (!base) return null;
    for (const k of keyNodes) base.keys.push(k ? this.evalPure(k, st) : '?');
    base.fields.push(...fields);
    void quiet; return base;
  }
  private lvText(lv: Lv): string { return lv.name + lv.keys.map(k => `[${k}]`).join('') + (lv.fields.length ? '.' + lv.fields.join('.') : ''); }
  private lvVar(lv: Lv): string { const f = lv.fields.filter(x => x !== 'length'); return lv.name + (f.length ? '.' + f.join('.') : ''); }

  private keyClassOf(k: string | null): KeyClass {
    if (k === null || k === '') return 'none';
    const first = splitCommaTop(k)[0];
    if (first === 'msg.sender' || first === 'tx.origin') return 'caller';
    if (first === 'this') return 'this';
    if (/^(0x[0-9a-fA-F]+|address\(\d+\)|\d+)$/.test(first)) return 'constant';
    if (this.vars.has(first)) return 'state_addr';
    if (this.entryParams.has(first)) return 'param';
    if (/^[A-Za-z_]\w*$/.test(first)) return 'loop_var';
    return 'other';
  }

  private recordRead(lv: Lv, st: State, line: number) {
    const vi = this.vars.get(lv.name);
    if (vi && (vi.constant || vi.immutable)) return;
    st.trace.push({ k: 'R', var: this.lvVar(lv), key: lv.keys.length ? lv.keys.join(', ') : null, line, fn: st.curFn });
  }
  private recordWrite(lv: Lv, op: string, val: string | null, st: State, line: number) {
    const L = this.lvText(lv); let o = op; let operand = val;
    if (op === '=' && val !== null) {
      const pre = `(${L} `;
      if (val.startsWith(pre) && wrapsWhole(val)) {
        const after = val.slice(pre.length, -1); const m = /^([+\-*/%]) ([\s\S]*)$/.exec(after);
        if (m && !after.startsWith('** ')) { o = m[1] + '='; operand = m[2]; }
      }
    }
    const delta = ['++', '--', 'delete', 'pop'].includes(o) ? (o === 'delete' ? `delete ${L}` : o === 'pop' ? `${L}.pop()` : `${L}${o}`)
      : o === '=' ? `${L} = ${val}` : o === 'push' ? `${L}.push(${val})` : `${L} ${o} ${operand}`;
    const key = lv.keys.length ? lv.keys.join(', ') : null;
    st.trace.push({ k: 'W', var: this.lvVar(lv), key, keyClass: this.keyClassOf(key), op: o, operand, delta, expr: val ?? '', line, fn: st.curFn, inLoop: st.loopDepth > 0 });
  }

  private assignTo(lhs: any, val: string, op: string, st: State, line: number, parts?: string[] | null) {
    if (lhs.type === 'TupleExpression') {
      lhs.components.forEach((c: any, i: number) => { if (c) this.assignTo(c, parts?.[i] ?? `${val}#${i}`, '=', st, line); });
      return;
    }
    if (lhs.type === 'Identifier' && this.isLocal(lhs.name, st)) {
      const cur = st.top.get(lhs.name)!;
      st.top.set(lhs.name, op === '=' ? val : `(${cur} ${op.slice(0, -1)} ${val})`); return;
    }
    const lv = this.lvFromNode(lhs, st);
    if (!lv) return;                                           // memory/local aggregate: not state
    if (op !== '=') this.recordRead(lv, st, line);
    this.recordWrite(lv, op, val, st, line);
  }

  private evalExpr(n: any, st: State): Res[] {
    if (!n) return [{ st, v: '' }];
    const line = n.loc?.start.line ?? 0;
    switch (n.type) {
      case 'NumberLiteral': return [{ st, v: n.number + (n.subdenomination ? ' ' + n.subdenomination : '') }];
      case 'BooleanLiteral': return [{ st, v: String(n.value) }];
      case 'StringLiteral': return [{ st, v: JSON.stringify(String(n.value).slice(0, 40)) }];
      case 'HexLiteral': return [{ st, v: '0x' + n.value }];
      case 'Identifier': {
        const nm = n.name;
        if (this.isLocal(nm, st)) { const ref = st.refs.get(nm); return [{ st, v: ref ? this.lvText(ref) : st.top.get(nm)! }]; }
        if (this.vars.has(nm)) { this.recordRead({ name: nm, keys: [], fields: [] }, st, line); return [{ st, v: nm }]; }
        return [{ st, v: nm }];
      }
      case 'MemberAccess': case 'IndexAccess': {
        if (n.type === 'MemberAccess' && n.memberName === 'balance') {
          const b = this.evalPure(n.expression, st); st.trace.push({ k: 'R', var: '$native_balance', key: b, line, fn: st.curFn });
          return [{ st, v: `${b}.balance` }];
        }
        const lv = this.lvFromNode(n, st);
        if (lv) { this.recordRead(lv, st, line); return [{ st, v: this.lvText(lv) }]; }
        if (n.type === 'IndexAccess') { const b = this.evalPure(n.base, st); const i = n.index ? this.evalPure(n.index, st) : ''; return [{ st, v: `${b}[${i}]` }]; }
        const b = this.evalPure(n.expression, st); return [{ st, v: `${b}.${n.memberName}` }];
      }
      case 'BinaryOperation': return this.evalBinary(n, st, line);
      case 'UnaryOperation': {
        const op = n.operator;
        if (op === '++' || op === '--' || op === 'delete') {
          if (n.subExpression.type === 'Identifier' && this.isLocal(n.subExpression.name, st)) {
            if (op !== 'delete') { const c = st.top.get(n.subExpression.name)!; st.top.set(n.subExpression.name, `(${c} ${op[0]} 1)`); } else st.top.set(n.subExpression.name, '0');
            return [{ st, v: st.top.get(n.subExpression.name)! }];
          }
          const lv = this.lvFromNode(n.subExpression, st);
          if (lv) { if (op !== 'delete') this.recordRead(lv, st, line); this.recordWrite(lv, op, null, st, line); return [{ st, v: this.lvText(lv) }]; }
          return [{ st, v: '' }];
        }
        const s = this.evalPure(n.subExpression, st); return [{ st, v: `${op}${s}` }];
      }
      case 'Conditional': {
        const c = this.evalPure(n.condition, st); const a = this.evalPure(n.trueExpression, st); const b = this.evalPure(n.falseExpression, st);
        st.addFlag('ternary_effects_merged'); return [{ st, v: `(${c} ? ${a} : ${b})` }];
      }
      case 'TupleExpression': {
        const parts = n.components.map((c: any) => (c ? this.evalPure(c, st) : ''));
        if (parts.length === 1 && !n.isArray) return [{ st, v: parts[0].startsWith('(') ? parts[0] : `(${parts[0]})`, parts: null }];
        return [{ st, v: `(${parts.join(', ')})`, parts }];
      }
      case 'FunctionCall': return this.evalCall(n, st, line);
      case 'NewExpression': return [{ st, v: `new ${n.typeName?.namePath ?? '?'}` }];
      case 'ElementaryTypeName': return [{ st, v: n.name }];
      case 'TypeNameExpression': return [{ st, v: n.typeName?.name ?? n.typeName?.namePath ?? '?' }];
      default: this.warn(this.diag.unsupported_nodes, `expr ${n.type} (line ${line})`); return [{ st, v: `<${n.type}>` }];
    }
  }

  private evalBinary(n: any, st: State, line: number): Res[] {
    const op = n.operator;
    if (['=', '+=', '-=', '*=', '/=', '%=', '|=', '&=', '^=', '<<=', '>>='].includes(op)) {
      const out: Res[] = [];
      for (const r of this.evalExpr(n.right, st)) {
        // evaluate keys of the lvalue AFTER the rhs (rhs side effects first) — good enough for token code
        this.assignTo(n.left, r.v, op, r.st, line, r.parts);
        out.push({ st: r.st, v: r.v });
      }
      return out;
    }
    const out: Res[] = [];
    for (const l of this.evalExpr(n.left, st)) for (const r of this.evalExpr(n.right, l.st)) out.push({ st: r.st, v: `(${l.v} ${op} ${r.v})` });
    return out;
  }

  private withArgs(argNodes: any[], st: State): { st: State; args: string[]; parts: (string[] | null | undefined)[] }[] {
    let cur = [{ st, args: [] as string[], parts: [] as (string[] | null | undefined)[] }];
    for (const a of argNodes) {
      const nx: typeof cur = [];
      for (const c of cur) for (const r of this.evalExpr(a, c.st)) nx.push({ st: r.st, args: [...c.args, r.v], parts: [...c.parts, r.parts] });
      cur = nx;
    }
    return cur;
  }

  private isContractTypedBase(text: string): string | null {
    const vi = this.vars.get(text); if (vi && this.ix.isContractName(vi.type)) return vi.type;
    const m = /^(\w+)\(/.exec(text); if (m && this.ix.isContractName(m[1])) return m[1];
    if (vi && /^I[A-Z]\w*$/.test(vi.type)) return vi.type;
    if (m && /^I[A-Z]\w*$/.test(m[1])) return m[1];
    return null;
  }

  private classifyTarget(text: string): CallEv['targetClass'] {
    const m = /^(\w+)\((.*)\)$/.exec(text);
    if (m && (this.ix.isContractName(m[1]) || /^I[A-Z]/.test(m[1]) || m[1] === 'address' || m[1] === 'payable')) return this.classifyTarget(m[2]);
    if (text === 'msg.sender' || text === 'tx.origin') return 'caller';
    if (text === 'this') return 'this';
    if (this.vars.has(text)) return 'state_var';
    if (this.entryParams.has(text)) return 'param';
    if (/^(0x[0-9a-fA-F]{6,}|address\(\d+\))$/.test(text)) return 'constant';
    if (/^[A-Za-z_]\w*$/.test(text)) return 'derived';
    return 'unknown';
  }

  private pushCall(st: State, c: Omit<CallEv, 'k' | 'callerFn'>) { st.trace.push({ k: 'C', callerFn: st.curFn, ...c }); }

  private evalCall(n: any, st: State, line: number): Res[] {
    let callee = n.expression; let valueNode: any = null;
    if (callee.type === 'NameValueExpression') {
      const nv = callee.arguments; const vi = nv.names.indexOf('value'); if (vi >= 0) valueNode = nv.arguments[vi];
      callee = callee.expression;
    }
    // special forms that must not pre-evaluate message args
    if (callee.type === 'Identifier' && (callee.name === 'require' || callee.name === 'assert')) {
      const out: Res[] = [];
      for (const r of this.evalExpr(n.arguments[0], st)) { this.requireLike(r.st, r.v, callee.name, line); out.push({ st: r.st, v: '' }); }
      return out;
    }
    const out: Res[] = [];
    for (const a of this.withArgs(n.arguments, st)) {
      const s = a.st; const args = a.args;
      const value = valueNode ? this.evalPure(valueNode, s) : null;
      for (const r of this.callCore(callee, n, args, a.parts, value, s, line)) out.push(r);
    }
    return out;
  }

  private callCore(callee: any, call: any, args: string[], parts: any[], value: string | null, st: State, line: number): Res[] {
    const plain = (v: string): Res[] => [{ st, v }];
    if (callee.type === 'Identifier') {
      const name = callee.name;
      if (name === 'revert') { st.halt = 'revert'; this.recordRevert('(unconditional)', 'revert', line, st.curFn); return plain(''); }
      if (name === 'address' || name === 'payable') return plain(args[0] === 'this' ? 'this' : /^\d+$/.test(args[0] ?? '') ? `address(${args[0]})` : (args[0] ?? ''));
      if (ELEM.test(name)) return plain(`${name}(${args.join(', ')})`);
      if (name === 'selfdestruct' || name === 'suicide') { this.pushCall(st, { kind: 'selfdestruct', target: args[0] ?? '', targetClass: this.classifyTarget(args[0] ?? ''), targetType: null, fn: 'selfdestruct', args, value: null, likelyView: false, line }); return plain(''); }
      if (this.ix.isContractName(name)) return plain(`${name}(${args.join(', ')})`);       // interface/contract conversion
      if (BUILTIN_FN.has(name)) return plain(`${name}(${args.join(', ')})`);
      const fn = this.ix.findFn(this.target, name, args.length);
      if (fn) return this.callFn(fn, args, st);
      this.warn(this.diag.unresolved_calls, `${name}/${args.length} (line ${line}) — treated as opaque`);
      return plain(`${name}(${args.join(', ')})`);
    }
    if (callee.type === 'ElementaryTypeName') {
      const nm = callee.name as string;
      if (nm === 'address' || nm === 'payable' || nm === 'address payable') return plain(args[0] === 'this' ? 'this' : /^\d+$/.test(args[0] ?? '') ? `address(${args[0]})` : (args[0] ?? ''));
      return plain(`${nm}(${args.join(', ')})`);
    }
    if (callee.type === 'NewExpression') {
      const tn = callee.typeName;
      if (tn?.type === 'UserDefinedTypeName' && this.ix.isContractName(tn.namePath)) {
        this.pushCall(st, { kind: 'create', target: tn.namePath, targetClass: 'unknown', targetType: tn.namePath, fn: 'new', args, value, likelyView: false, line }); return plain('new()');
      }
      return plain('new[]');                                   // new address[](n), new bytes(n): memory allocation only
    }
    if (callee.type !== 'MemberAccess') return plain(`<call ${callee.type}>(${args.join(', ')})`);

    const member = callee.memberName; const baseNode = callee.expression;
    if (baseNode.type === 'Identifier') {
      const bn = baseNode.name;
      if (bn === 'abi') return plain(`abi.${member}(${args.join(', ')})`);
      if (bn === 'super') {
        const cur = st.curFn.split('.')[0]; const lin = this.ix.lin(this.target); const i = lin.indexOf(cur);
        for (const cn of lin.slice(i + 1)) { const f = this.ix.contracts.get(cn)!.fns.find(x => x.name === member && x.params.length === args.length && x.node.body); if (f) return this.callFn(f, args, st); }
        return plain(`super.${member}(${args.join(', ')})`);
      }
      if (bn === 'this') { const f = this.ix.findFn(this.target, member, args.length); st.addFlag('self_external_call'); if (f) return this.callFn(f, args, st); }
      if (!this.isLocal(bn, st) && !this.vars.has(bn) && this.ix.isContractName(bn)) {
        if (/safemath/i.test(bn) && ARITH[member] && args.length >= 2) return plain(`(${args[0]} ${ARITH[member]} ${args[1]})`);
        const f = this.ix.findFn(bn, member, args.length);
        if (f) return this.callFn(f, args, st);
        return plain(`${bn}.${member}(${args.join(', ')})`);
      }
    }
    const baseText = this.evalPure(baseNode, st);
    const ctype = this.isContractTypedBase(baseText);
    if (!ctype) {
      // using-for library binding (SafeMath, Address, ...)
      for (const lib of this.ix.usingLibs(this.target)) {
        if (/safemath/i.test(lib) && ARITH[member] && args.length >= 1) return plain(`(${baseText} ${ARITH[member]} ${args[0]})`);
        const f = this.ix.findFn(lib, member, args.length + 1);
        if (f) return this.callFn(f, [baseText, ...args], st);
      }
      // state array mutation
      if ((member === 'push' || member === 'pop') && baseNode.type !== 'CallExpression') {
        const lv = this.lvFromNode(baseNode, st);
        if (lv) { this.recordWrite(lv, member, member === 'push' ? (args[0] ?? '') : null, st, line); return plain(''); }
      }
      // native-currency primitives
      if (member === 'transfer' && args.length === 1) { this.pushCall(st, { kind: 'native_transfer', target: baseText, targetClass: this.classifyTarget(baseText), targetType: null, fn: 'transfer', args, value: args[0], likelyView: false, line }); return plain(''); }
      if (member === 'send' && args.length === 1) { this.pushCall(st, { kind: 'native_send', target: baseText, targetClass: this.classifyTarget(baseText), targetType: null, fn: 'send', args, value: args[0], likelyView: false, line }); return plain('true'); }
      if (member === 'call' || member === 'delegatecall' || member === 'staticcall') {
        const kind = member === 'call' ? 'low_level_call' : member;
        this.pushCall(st, { kind: kind as any, target: baseText, targetClass: this.classifyTarget(baseText), targetType: null, fn: member, args, value, likelyView: member === 'staticcall', line });
        return [{ st, v: `(ext<${baseText}.${member}>.ok, ext<${baseText}.${member}>.data)`, parts: [`ext<${baseText}.${member}>.ok`, `ext<${baseText}.${member}>.data`] }];
      }
    }
    // ordinary external call
    const type = ctype ?? (this.vars.get(baseText)?.type ?? null);
    this.pushCall(st, { kind: 'external', target: baseText, targetClass: this.classifyTarget(baseText), targetType: type, fn: member, args, value, likelyView: VIEW_EXT.has(member), line });
    return plain(`ext<${baseText}.${member}>(${args.join(', ')})`);
  }
}
