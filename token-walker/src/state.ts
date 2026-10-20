// token-walker :: state.ts — symbolic execution state + small text helpers
import { Ev, Constraint } from './types';
import { FnInfo } from './parse';

export interface Lv { name: string; keys: string[]; fields: string[] }
export interface ModFrame { fn: FnInfo; mods: { name: string; args: any[] }[]; idx: number; frameIdx: number }

export class State {
  frames: Map<string, string>[] = [new Map()];
  fnStack: string[] = [];
  modStack: ModFrame[] = [];
  conds: Constraint[] = [];
  decided = new Map<string, boolean>();
  eq: string[] = [];
  trace: Ev[] = [];
  chain: string[] = [];
  flags: string[] = [];
  refs = new Map<string, Lv>();        // local storage-pointer aliases
  loopVars = new Set<string>();
  halt: 'none' | 'return' | 'revert' | 'break' = 'none';
  ret: string | null = null;
  retParts: string[] | null = null;
  loopDepth = 0;

  clone(): State {
    const c = new State();
    c.frames = this.frames.map(f => new Map(f));
    c.fnStack = [...this.fnStack];
    c.modStack = this.modStack.map(m => ({ ...m }));
    c.conds = [...this.conds];
    c.decided = new Map(this.decided);
    c.eq = [...this.eq];
    c.trace = [...this.trace];
    c.chain = [...this.chain];
    c.flags = [...this.flags];
    c.refs = new Map(this.refs);
    c.loopVars = new Set(this.loopVars);
    c.halt = this.halt; c.ret = this.ret; c.retParts = this.retParts ? [...this.retParts] : null;
    c.loopDepth = this.loopDepth;
    return c;
  }
  get top(): Map<string, string> { return this.frames[this.frames.length - 1]; }
  get curFn(): string { return this.fnStack.length ? this.fnStack[this.fnStack.length - 1] : '?'; }
  addFlag(f: string) { if (!this.flags.includes(f)) this.flags.push(f); }
}

export function adopt(dst: State, src: State) { if (dst !== src) Object.assign(dst, src); }

/** true if the whole string is wrapped by one matching outer paren pair */
export function wrapsWhole(t: string): boolean {
  if (t.length < 2 || t[0] !== '(' || t[t.length - 1] !== ')') return false;
  let d = 0;
  for (let i = 0; i < t.length; i++) {
    if (t[i] === '(') d++; else if (t[i] === ')') { d--; if (d === 0 && i < t.length - 1) return false; }
  }
  return d === 0;
}
export function stripParens(t: string): string { t = t.trim(); while (wrapsWhole(t)) t = t.slice(1, -1).trim(); return t; }

/** canonical form of a condition: {text, neg} so `!x` and `x` correlate */
export function canon(t: string): { t: string; neg: boolean } {
  let neg = false; t = stripParens(t);
  for (;;) {
    if (t[0] === '!' && t[1] !== '=') { neg = !neg; t = stripParens(t.slice(1)); continue; }
    break;
  }
  return { t, neg };
}

/** split at top-level operator (paren/bracket depth 0) */
export function splitTop(t: string, op: string): string[] {
  const out: string[] = []; let d = 0; let last = 0;
  for (let i = 0; i < t.length; i++) {
    const ch = t[i];
    if (ch === '(' || ch === '[') d++; else if (ch === ')' || ch === ']') d--;
    else if (d === 0 && t.startsWith(op, i)) { out.push(t.slice(last, i)); i += op.length - 1; last = i + 1; }
  }
  out.push(t.slice(last));
  return out.map(s => s.trim());
}

export function splitCommaTop(t: string): string[] { return splitTop(t, ','); }
