// token-walker :: engine.ts — un-pruned symbolic path walker (statements, expressions, calls)
import { Index, FnInfo, VarInfo } from './parse';
import { WalkerConfig, Diagnostics, PathRec, RevertGuard, KeyClass, CallEv, WriteEv, Ev } from './types';
import { State, Lv, adopt, canon, stripParens, splitTop, splitCommaTop, wrapsWhole } from './state';

interface Res { st: State; v: string; parts?: string[] | null }
export interface EntryResult { paths: PathRec[]; revertedPaths: PathRec[]; reverts: RevertGuard[]; truncated: boolean; enumerated: number; statesGenerated: number; discarded: number; peakFrontier: number; error?: string }

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
  discarded = 0; peak = 0; generated = 0;
  entryParams = new Set<string>();
  private warned = new Set<string>();

  constructor(private ix: Index, private target: string, private cfg: WalkerConfig, private diag: Diagnostics) {
    this.vars = ix.allVars(target);
  }

  private warn(list: string[], msg: string) { const k = list === this.diag.warnings ? 'w:' + msg : 'u:' + msg; if (!this.warned.has(k)) { this.warned.add(k); list.push(msg); } }

  // ───────────────────────── entry runners ─────────────────────────
  runEntry(fn: FnInfo): EntryResult {
    this.reverts = new Map(); this.truncated = false; this.discarded = 0; this.peak = 0; this.generated = 0;
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
    this.reverts = new Map(); this.truncated = false; this.discarded = 0; this.peak = 0; this.generated = 0; this.entryParams = new Set();
    const st = new State(); st.fnStack.push(`${this.target}.constructor`); st.chain.push(`${this.target}.constructor`);
    for (const cn of [...this.ix.lin(this.target)].reverse()) {
      for (const v of this.ix.contracts.get(cn)!.vars.values()) {
        if (v.constant || v.initial === null) continue;
        st.trace.push({ k: 'W', var: v.name, key: null, keyClass: 'none', op: '=', operand: v.initial, delta: `${v.name} = ${v.initial}`, expr: v.initial, line: v.line, fn: `${cn}.<initializer>`, inLoop: false });
      }
    }
    let states: State[] = [st];
    const baseArgs = this.ix.baseCtorArgs(this.target);
    for (const cn of [...this.ix.lin(this.target)].reverse()) {
      const ctor = this.ix.contracts.get(cn)!.fns.find(f => f.kind === 'constructor');
      if (!ctor) continue;
      const next: State[] = [];
      for (const s of states) {
        let args = ctor.params.map((p, i) => p.name || `_p${i}`);
        const spec = baseArgs.get(cn);
        if (spec && spec.length === ctor.params.length) {
          const tmp = new State(); tmp.fnStack.push(`${this.target}.constructor`);
          for (const c2 of this.ix.lin(this.target)) for (const f of this.ix.contracts.get(c2)!.fns) if (f.kind === 'constructor') f.params.forEach((p, i) => tmp.top.set(p.name || `_p${i}`, p.name || `_p${i}`));
          args = spec.map(a => this.evalPure(a, tmp));
          if (tmp.trace.some(e => e.k === 'R')) this.warn(this.diag.warnings, `base-constructor argument for ${cn} reads state; evaluated against symbolic constructor parameters only`);
        }
        for (const r of this.callInline(ctor, args, s, `${cn}.constructor`)) next.push(r.st);
      }
      states = next;
    }
    return this.finish(states);
  }

  private finish(states: State[]): EntryResult {
    const make = (s: State): PathRec => {
      const outcome = s.halt === 'revert' ? 'reverts' : 'completes';
      if (s.trace[s.trace.length - 1]?.k !== 'X') s.trace.push({ k: 'X', outcome, reason: s.failure?.reason ?? null, line: s.failure?.line ?? 0, fn: s.failure?.fn ?? s.curFn });
      return { outcome, chain: s.chain, constraints: s.conds, eqFacts: s.eq, trace: s.trace, flags: s.flags, ret: s.ret, failure: s.failure };
    };
    const paths = states.filter(s => s.halt !== 'revert').map(make);
    const revertedPaths = states.filter(s => s.halt === 'revert').map(make);
    return { paths, revertedPaths, reverts: [...this.reverts.values()], truncated: this.truncated, enumerated: states.length, statesGenerated: this.generated, discarded: this.discarded, peakFrontier: this.peak };
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
      this.generated += cur.length; if (cur.length > this.peak) this.peak = cur.length;
      if (cur.length > this.cfg.maxPathsPerEntry) {            // deterministic, evenly-strided sample (not a tail cut)
        const cap = this.cfg.maxPathsPerEntry; const step = cur.length / cap; const keep: State[] = [];
        for (let i = 0; i < cap; i++) keep.push(cur[Math.floor(i * step)]);
        this.discarded += cur.length - cap; cur = keep; this.truncated = true;
      }
    }
    return cur;
  }

  private execStmt(n: any, st: State): State[] {
    if (!n) return [st];
    const line = n.loc?.start.line ?? 0;
    switch (n.type) {
      case 'Block': return this.execStmts(n.statements ?? [], [st]);
      case 'UncheckedStatement': return this.execStmt(n.block, st);      // parser ≥0.17: { block: Block }
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
      case 'RevertStatement': st.halt = 'revert'; st.failure = { kind: 'revert', reason: '(unconditional)', line, fn: st.curFn }; st.trace.push({ k: 'X', outcome: 'reverts', reason: '(unconditional)', line, fn: st.curFn }); this.recordRevert('(unconditional)', 'revert', line, st.curFn); return [st];
      case 'BreakStatement': st.halt = 'break'; return [st];
      case 'ContinueStatement': st.halt = 'continue'; return [st];
      case 'TryStatement': return this.execTry(n, st);
      case 'InlineAssemblyStatement': st.addFlag('unmodeled_assembly'); this.warn(this.diag.warnings, `inline assembly in ${st.curFn} (line ${line}) is NOT modeled — sstore/call effects missing`); return [st];
      default: {
        this.warn(this.diag.unsupported_nodes, `${n.type} (line ${line})`); st.addFlag(`unsupported_stmt:${n.type}`);
        let cur: State[] = [st];                                  // conservative: still execute/visit children so nested effects reach the trace
        for (const k of Object.keys(n)) {
          if (k === 'loc' || k === 'range') continue; const c = (n as any)[k];
          for (const ch of Array.isArray(c) ? c : [c]) {
            if (!ch || typeof ch !== 'object' || typeof ch.type !== 'string') continue;
            const nx: State[] = [];
            for (const s2 of cur) {
              if (s2.halt !== 'none') { nx.push(s2); continue; }
              if (/Statement$|^Block$/.test(ch.type)) for (const r of this.execStmt(ch, s2)) nx.push(r);
              else for (const r of this.evalExpr(ch, s2)) nx.push(r.st);
            }
            cur = nx;
          }
        }
        return cur;
      }
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
      let allRevert = false;
      if (doT) {
        const t = doF ? s.clone() : s; this.assume(t, r.v, 'T', 'if', line);
        const tres = this.execStmt(n.trueBody, t);
        allRevert = tres.length > 0 && tres.every(x => x.halt === 'revert');
        for (const x of tres) { if (x.halt === 'revert') { const reason = stripParens(r.v); this.recordRevert(reason, 'if-revert', line, x.curFn); x.failure = { kind: 'if-revert', reason, condition: reason, line, fn: x.curFn }; for (let i = x.trace.length - 1; i >= 0; i--) if (x.trace[i].k === 'X') { (x.trace[i] as any).reason = reason; break; } } out.push(x); }
      }
      if (doF) {
        // `if (bad) revert();` ⇒ the surviving arm is a REQUIRE-style guard (needed for access-class evidence)
        this.assume(s, r.v, 'F', allRevert ? 'require' : 'if', line);
        if (n.falseBody) { for (const x of this.execStmt(n.falseBody, s)) out.push(x); } else out.push(s);
      }
    }
    return out;
  }

  private markLoopEffects(st: State, base: number) {
    if (st.trace.slice(base).some(e => e.k === 'W' || e.k === 'C')) st.addFlag('loop_effects_bounded');   // only 1 iteration modeled
  }

  private execLoop(n: any, st: State, line: number): State[] {
    const isFor = n.type === 'ForStatement', isDo = n.type === 'DoWhileStatement';
    let starts: State[] = [st];
    if (isFor && n.initExpression) {
      starts = this.execStmt(n.initExpression, st);                 // initializer values are KEPT (first iteration sees them)
      for (const s of starts) if (n.initExpression.type === 'VariableDeclarationStatement')
        for (const v of n.initExpression.variables) if (v) s.loopVars.add(v.name);
    }
    const condNode = isFor ? n.conditionExpression : n.condition;
    // one iteration: body → (continue clears) → increment → exit-condition check. `break`/`return` leave immediately.
    const iterate = (s: State): State[] => {
      s.loopDepth++; s.addFlag('loop_unrolled_once');
      const base = s.trace.length; const res: State[] = [];
      for (const b of this.execStmt(n.body, s)) {
        if (b.halt === 'break') { b.halt = 'none'; b.loopDepth--; this.markLoopEffects(b, base); res.push(b); continue; }
        if (b.halt === 'continue') b.halt = 'none';
        if (b.halt !== 'none') { b.loopDepth--; this.markLoopEffects(b, base); res.push(b); continue; }
        const nx = isFor && n.loopExpression ? this.execStmt(n.loopExpression, b) : [b];
        for (const x of nx) {
          if (x.halt !== 'none' || !condNode) { x.loopDepth--; this.markLoopEffects(x, base); res.push(x); continue; }
          for (const r of this.evalExpr(condNode, x)) {
            const known = this.decide(r.st, r.v);
            if (known === true) continue;                           // cond still true ⇒ would iterate again; no 1-iteration exit exists
            this.assume(r.st, r.v, 'F', 'loop', line);   // exit requires the condition to be false now
            r.st.loopDepth--; this.markLoopEffects(r.st, base); res.push(r.st);
          }
        }
      }
      return res;
    };
    const out: State[] = [];
    for (const s0 of starts) {
      if (isDo) { for (const x of iterate(s0)) out.push(x); continue; }          // do-while: mandatory first iteration
      const conds: Res[] = condNode ? this.evalExpr(condNode, s0) : [{ st: s0, v: 'true' }];
      for (const r of conds) {
        const s = r.st; const known = this.decide(s, r.v);
        const doIter = known !== false, doSkip = known !== true;
        if (doSkip) { const skip = doIter ? s.clone() : s; this.assume(skip, r.v, 'F', 'loop', line); out.push(skip); }   // 0 iterations
        if (doIter) { this.assume(s, r.v, 'T', 'loop', line); for (const x of iterate(s)) out.push(x); }                    // 1 iteration
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
    st.conds.push({ text: arm === 'T' ? text : this.negate(text), arm, kind, line, fn: st.curFn });
    st.trace.push({ k: 'B', condition: text, arm, kind, line, fn: st.curFn });
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
  private negate(text: string): string {
    if (!text.includes('&&') && !text.includes('||')) {
      const m = /^(.+?) (==|!=) (.+)$/.exec(text);
      if (m) return `${m[1]} ${m[2] === '==' ? '!=' : '=='} ${m[3]}`;
    }
    return text.startsWith('!') && wrapsWhole(text.slice(1)) ? stripParens(text.slice(1)) : `!(${text})`;
  }
  private requireLike(st: State, cond: string, kind: string, line: number): State[] {
    const known = this.decide(st, cond);
    this.recordRevert(stripParens(cond), kind, line, st.curFn);
    if (known === true) { this.assume(st, cond, 'T', 'require', line); return [st]; }
    if (known === false) { st.halt = 'revert'; st.failure = { kind, reason: stripParens(cond), condition: stripParens(cond), line, fn: st.curFn }; st.trace.push({ k: 'B', condition: stripParens(cond), arm: 'F', kind: 'require', line, fn: st.curFn }); st.trace.push({ k: 'X', outcome: 'reverts', reason: stripParens(cond), line, fn: st.curFn }); return [st]; }
    const failed = st.clone();
    this.assume(failed, cond, 'F', 'require', line); failed.halt = 'revert';
    failed.failure = { kind, reason: stripParens(cond), condition: stripParens(cond), line, fn: failed.curFn };
    failed.trace.push({ k: 'X', outcome: 'reverts', reason: stripParens(cond), line, fn: failed.curFn });
    this.assume(st, cond, 'T', 'require', line);
    return [st, failed];
  }
  private recordRevert(cond: string, kind: string, line: number, fn: string) {
    const k = `${fn}|${line}|${cond}`; const g = this.reverts.get(k);
    if (g) g.count++; else this.reverts.set(k, { cond, kind, line, fn, count: 1 });
  }

  // ───────────────────────── modifiers / calls ─────────────────────────
  private runWithModifiers(fn: FnInfo, idx: number, st: State, fnFrameIdx: number): State[] {
    const mods = fn.modifiers.filter(m => this.ix.findModifier(this.target, m.name));
    if (idx === 0) for (const m of fn.modifiers) if (!this.ix.findModifier(this.target, m.name) && !this.ix.isContractName(m.name)) {
      st.addFlag(`unresolved_modifier:${m.name}`); this.warn(this.diag.warnings, `modifier '${m.name}' on ${fn.contract}.${fn.name} not found — its guard/effects are MISSING`);
    }
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

  /** same-name/same-arity overloads cannot be told apart without types ⇒ explore all, flag ambiguity */
  private callCandidates(fns: FnInfo[], args: string[], st: State): Res[] {
    if (fns.length === 1) return this.callFn(fns[0], args, st);
    this.warn(this.diag.warnings, `overload ambiguity: ${fns[0].name}/${args.length} has ${fns.length} candidates — all explored (flag overload_ambiguous)`);
    const out: Res[] = [];
    fns.forEach((f, i) => { const s = i === fns.length - 1 ? st : st.clone(); s.addFlag(`overload_ambiguous:${f.name}`); for (const r of this.callFn(f, args, s)) out.push(r); });
    return out;
  }

  private opaqueCall(st: State, fnName: string, args: string[], line: number, why: string): void {
    st.addFlag(why);
    this.pushCall(st, { kind: 'external', target: '<opaque>', targetClass: 'unknown', targetType: null, fn: fnName, args, value: null, likelyView: false, viewBasis: 'unknown', line });
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
  /** a write to V makes every remembered decision about a condition mentioning V stale */
  private invalidate(st: State, name: string) {
    const re = new RegExp(`\\b${name.replace(/[$]/g, '\\$')}\\b`);
    for (const k of [...st.decided.keys()]) if (re.test(k)) st.decided.delete(k);
  }
  /** an external call may re-enter and change any state: forget decisions that depend on state */
  private invalidateStateConds(st: State) {
    for (const k of [...st.decided.keys()]) if ((k.match(/[A-Za-z_]\w*/g) ?? []).some(i => this.vars.has(i))) st.decided.delete(k);
  }
  private recordWrite(lv: Lv, op: string, val: string | null, st: State, line: number) {
    this.invalidate(st, lv.name);
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
    let kc = this.keyClassOf(key); if (st.loopDepth > 0 && kc === 'constant' && /^\d+$/.test(splitCommaTop(key!)[0])) kc = 'loop_var';
    st.trace.push({ k: 'W', var: this.lvVar(lv), key, keyClass: kc, op: o, operand, delta, expr: val ?? '', line, fn: st.curFn, inLoop: st.loopDepth > 0 });
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
      default: {
        this.warn(this.diag.unsupported_nodes, `expr ${n.type} (line ${line})`); st.addFlag(`unmodeled_expr:${n.type}`);
        for (const k of Object.keys(n)) {                      // conservative: still visit children for reads/writes/calls
          if (k === 'loc' || k === 'range') continue; const c = (n as any)[k];
          for (const ch of Array.isArray(c) ? c : [c]) if (ch && typeof ch === 'object' && typeof ch.type === 'string') this.evalPure(ch, st);
        }
        return [{ st, v: `<${n.type}>` }];
      }
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

  private pushCall(st: State, c: Omit<CallEv, 'k' | 'callerFn'>) { st.trace.push({ k: 'C', callerFn: st.curFn, ...c }); if (!c.likelyView) this.invalidateStateConds(st); }

  private evalCall(n: any, st: State, line: number): Res[] {
    let callee = n.expression; let valueNode: any = null;
    if (callee.type === 'NameValueExpression') {
      const nv = callee.arguments; const vi = nv.names.indexOf('value'); if (vi >= 0) valueNode = nv.arguments[vi];
      callee = callee.expression;
    }
    // special forms that must not pre-evaluate message args
    if (callee.type === 'Identifier' && (callee.name === 'require' || callee.name === 'assert')) {
      const out: Res[] = [];
      for (const r of this.evalExpr(n.arguments[0], st)) for (const next of this.requireLike(r.st, r.v, callee.name, line)) out.push({ st: next, v: '' });
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
      if (name === 'revert') { st.halt = 'revert'; st.failure = { kind: 'revert', reason: '(unconditional)', line, fn: st.curFn }; st.trace.push({ k: 'X', outcome: 'reverts', reason: '(unconditional)', line, fn: st.curFn }); this.recordRevert('(unconditional)', 'revert', line, st.curFn); return plain(''); }
      if (name === 'address' || name === 'payable') return plain(args[0] === 'this' ? 'this' : /^\d+$/.test(args[0] ?? '') ? `address(${args[0]})` : (args[0] ?? ''));
      if (ELEM.test(name)) return plain(`${name}(${args.join(', ')})`);
      if (name === 'selfdestruct' || name === 'suicide') { this.pushCall(st, { kind: 'selfdestruct', target: args[0] ?? '', targetClass: this.classifyTarget(args[0] ?? ''), targetType: null, fn: 'selfdestruct', args, value: null, likelyView: false, line }); return plain(''); }
      if (this.ix.isContractName(name)) return plain(`${name}(${args.join(', ')})`);       // interface/contract conversion
      if (BUILTIN_FN.has(name)) return plain(`${name}(${args.join(', ')})`);
      const fns = this.ix.findFns(this.target, name, args.length);
      if (fns.length) return this.callCandidates(fns, args, st);
      if (/^[A-Z]/.test(name)) return plain(`${name}(${args.join(', ')})`);               // struct / enum / error / event constructor
      this.warn(this.diag.unresolved_calls, `${name}/${args.length} (line ${line}) — emitted as opaque call event`);
      this.opaqueCall(st, name, args, line, `unresolved_call:${name}`);
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
    if (callee.type !== 'MemberAccess') {
      this.warn(this.diag.unsupported_nodes, `call through ${callee.type} (line ${line})`);
      try { this.evalPure(callee, st); } catch { /* receiver reads only */ }
      this.opaqueCall(st, `<${callee.type}>`, args, line, `unmodeled_call:${callee.type}`);
      return plain(`<call ${callee.type}>(${args.join(', ')})`);
    }

    const member = callee.memberName; const baseNode = callee.expression;
    if (baseNode.type === 'Identifier') {
      const bn = baseNode.name;
      if (bn === 'abi') return plain(`abi.${member}(${args.join(', ')})`);
      if (bn === 'super') {
        const cur = st.curFn.split('.')[0];
        const fs = this.ix.findFns(this.target, member, args.length, cur);
        if (fs.length) return this.callCandidates(fs, args, st);
        this.opaqueCall(st, `super.${member}`, args, line, `unresolved_call:super.${member}`);
        return plain(`super.${member}(${args.join(', ')})`);
      }
      if (bn === 'this') { const fs = this.ix.findFns(this.target, member, args.length); st.addFlag('self_external_call'); if (fs.length) return this.callCandidates(fs, args, st); }
      if (!this.isLocal(bn, st) && !this.vars.has(bn) && this.ix.isContractName(bn)) {
        if (/safemath/i.test(bn) && ARITH[member] && args.length >= 2) return plain(`(${args[0]} ${ARITH[member]} ${args[1]})`);
        const fs = this.ix.findFns(bn, member, args.length);
        if (fs.length) return this.callCandidates(fs, args, st);
        this.opaqueCall(st, `${bn}.${member}`, args, line, `unresolved_call:${bn}.${member}`);
        return plain(`${bn}.${member}(${args.join(', ')})`);
      }
    }
    const baseText = this.evalPure(baseNode, st);
    const ctype = this.isContractTypedBase(baseText);
    if (!ctype) {
      // using-for library binding (SafeMath, Address, ...)
      for (const lib of this.ix.usingLibs(this.target)) {
        if (/safemath/i.test(lib) && ARITH[member] && args.length >= 1) return plain(`(${baseText} ${ARITH[member]} ${args[0]})`);
        const fs = this.ix.findFns(lib, member, args.length + 1);
        if (fs.length) return this.callCandidates(fs, [baseText, ...args], st);
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
    const tclass = this.classifyTarget(baseText);
    let likelyView = false; let viewBasis: 'declared' | 'name_heuristic' | 'unknown' = 'unknown';
    const known = type && this.ix.contracts.has(type) ? this.ix.lin(type).flatMap(cn => this.ix.contracts.get(cn)!.fns).filter(f => f.name === member && f.params.length === args.length) : [];
    if (known.length) { likelyView = known.every(f => f.mutability === 'view' || f.mutability === 'pure'); viewBasis = 'declared'; }   // declared mutability wins
    else if (VIEW_EXT.has(member) && (tclass === 'state_var' || tclass === 'constant') && type) { likelyView = true; viewBasis = 'name_heuristic'; }
    // attacker-controlled / unknown targets are NEVER assumed view: a "balanceOf" on a param-supplied contract can run arbitrary code
    this.pushCall(st, { kind: 'external', target: baseText, targetClass: tclass, targetType: type, fn: member, args, value, likelyView, viewBasis, line });
    return plain(`ext<${baseText}.${member}>(${args.join(', ')})`);
  }
}
