// token-walker :: parse.ts — source index (contracts, inheritance, state vars, functions, modifiers, using-for)
import * as fs from 'fs';
import * as path from 'path';
import * as parser from '@solidity-parser/parser';

export interface VarInfo {
  name: string; contract: string; type: string;
  kind: 'scalar' | 'mapping' | 'array' | 'struct';
  keyTypes: string[]; valueType: string; visibility: string;
  constant: boolean; immutable: boolean; initial: string | null;
  line: number; file: string;
}
export interface FnInfo {
  contract: string; name: string; kind: 'function' | 'constructor' | 'receive' | 'fallback' | 'modifier';
  node: any; params: { name: string; type: string }[]; returns: { name: string; type: string }[];
  visibility: string; mutability: string; modifiers: { name: string; args: any[] }[];
  file: string; line: number; isLibrary: boolean; virtual: boolean;
}
export interface ContractInfo {
  name: string; kind: string; bases: string[]; file: string; line: number;
  vars: Map<string, VarInfo>; fns: FnInfo[]; modifiers: Map<string, FnInfo>;
  usings: { lib: string; type: string | null }[]; node: any;
}

export function typeStr(t: any): string {
  if (!t) return '';
  switch (t.type) {
    case 'ElementaryTypeName': return t.name + (t.stateMutability ? ' ' + t.stateMutability : '');
    case 'UserDefinedTypeName': return t.namePath;
    case 'Mapping': return `mapping(${typeStr(t.keyType)} => ${typeStr(t.valueType)})`;
    case 'ArrayTypeName': return `${typeStr(t.baseTypeName)}[]`;
    case 'FunctionTypeName': return 'function';
    default: return t.type || '';
  }
}

export class Index {
  contracts = new Map<string, ContractInfo>();
  fileSrc = new Map<string, string>();
  files: string[] = [];
  warnings: string[] = [];
  parseErrors: string[] = [];
  failedFiles: string[] = [];
  duplicates: string[] = [];
  private linCache = new Map<string, string[]>();

  static collectSol(root: string, errors: string[] = []): string[] {
    const out: string[] = [];
    const skip = new Set(['node_modules', 'artifacts', 'cache', 'out', '.git', 'broadcast', 'typechain', 'typechain-types']);
    const seen = new Set<string>();
    const walk = (p: string) => {
      try {
        const real = fs.realpathSync(p);
        if (seen.has(real)) return; seen.add(real);                 // symlink-cycle / duplicate guard
        const st = fs.statSync(p);
        if (st.isFile()) { if (p.endsWith('.sol')) out.push(p); return; }
        for (const e of fs.readdirSync(p)) { if (!skip.has(e)) walk(path.join(p, e)); }
      } catch (e: any) { errors.push(`${p}: ${e.code ?? ''} ${e.message}`); }   // broken symlink / EACCES etc: reported, not fatal
    };
    walk(root);
    return out.sort();
  }

  addFile(file: string) {
    const src = fs.readFileSync(file, 'utf8');
    this.fileSrc.set(file, src);
    let ast: any;
    try { ast = parser.parse(src, { loc: true, range: true, tolerant: true }); }
    catch (e: any) { this.warnings.push(`parse failed: ${file}: ${e.message}`); this.failedFiles.push(file); return; }
    for (const er of ast.errors ?? []) this.parseErrors.push(`${file}:${er.line}:${er.column} ${er.message}`);
    this.files.push(file);
    for (const n of ast.children) if (n.type === 'ContractDefinition') this.addContract(n, file, src);
  }

  private addContract(n: any, file: string, src: string) {
    const c: ContractInfo = {
      name: n.name, kind: n.kind, bases: (n.baseContracts || []).map((b: any) => b.baseName.namePath),
      file, line: n.loc?.start.line ?? 0, vars: new Map(), fns: [], modifiers: new Map(), usings: [], node: n,
    };
    for (const s of n.subNodes) {
      if (s.type === 'StateVariableDeclaration') {
        for (const v of s.variables) {
          const t = v.typeName; const ts = typeStr(t);
          let kind: VarInfo['kind'] = 'scalar'; let keyTypes: string[] = []; let valueType = ts;
          if (t?.type === 'Mapping') {
            kind = 'mapping'; let cur = t;
            while (cur?.type === 'Mapping') { keyTypes.push(typeStr(cur.keyType)); cur = cur.valueType; }
            valueType = typeStr(cur);
          } else if (t?.type === 'ArrayTypeName') { kind = 'array'; valueType = typeStr(t.baseTypeName); }
          else if (t?.type === 'UserDefinedTypeName') { kind = 'scalar'; }
          const init = v.expression ?? s.initialValue;
          c.vars.set(v.name, {
            name: v.name, contract: c.name, type: ts, kind, keyTypes, valueType,
            visibility: v.visibility || 'internal', constant: !!v.isDeclaredConst, immutable: !!v.isImmutable,
            initial: init?.range ? src.slice(init.range[0], init.range[1] + 1) : null,
            line: v.loc?.start.line ?? 0, file,
          });
        }
      } else if (s.type === 'UsingForDeclaration') {
        c.usings.push({ lib: s.libraryName, type: s.typeName ? typeStr(s.typeName) : null });
      } else if (s.type === 'FunctionDefinition' || s.type === 'ModifierDefinition') {
        const isMod = s.type === 'ModifierDefinition';
        let kind: FnInfo['kind'] = isMod ? 'modifier' : 'function';
        if (!isMod) { if (s.isConstructor) kind = 'constructor'; else if (s.isReceiveEther) kind = 'receive'; else if (s.isFallback) kind = 'fallback'; }
        const f: FnInfo = {
          contract: c.name, name: isMod ? s.name : (kind === 'function' ? s.name : kind), kind, node: s,
          params: (s.parameters || []).map((p: any) => ({ name: p.name || '', type: typeStr(p.typeName) })),
          returns: (s.returnParameters || []).map((p: any) => ({ name: p.name || '', type: typeStr(p.typeName) })),
          visibility: s.visibility || (kind === 'constructor' ? 'public' : 'public'),
          mutability: s.stateMutability || 'nonpayable',
          modifiers: (s.modifiers || []).map((m: any) => ({ name: m.name, args: m.arguments || [] })),
          file, line: s.loc?.start.line ?? 0, isLibrary: n.kind === 'library', virtual: !!s.isVirtual,
        };
        if (isMod) c.modifiers.set(f.name, f); else c.fns.push(f);
      }
    }
    if (this.contracts.has(c.name)) { const m = `duplicate contract name ${c.name}: ${this.contracts.get(c.name)!.file} vs ${file}; later definition wins (earlier one is NOT analyzed)`; this.warnings.push(m); this.duplicates.push(m); }
    this.contracts.set(c.name, c);
  }

  /** C3 linearization, most-derived first. Unknown bases are skipped. */
  lin(name: string): string[] {
    const cached = this.linCache.get(name); if (cached) return cached;
    const c = this.contracts.get(name); if (!c) return [];
    const seqs: string[][] = [];
    for (const b of [...c.bases].reverse()) if (this.contracts.has(b)) seqs.push(this.lin(b));
    seqs.push([...c.bases].reverse().filter(b => this.contracts.has(b)));
    const out = [name];
    const work = seqs.map(s => [...s]).filter(s => s.length);
    while (work.length) {
      let cand: string | null = null;
      for (const s of work) {
        const h = s[0];
        if (!work.some(o => o.indexOf(h) > 0)) { cand = h; break; }
      }
      if (!cand) { this.warnings.push(`C3 linearization failed for ${name}`); cand = work[0][0]; }
      out.push(cand);
      for (const s of work) { const i = s.indexOf(cand); if (i >= 0) s.splice(i, 1); }
      for (let i = work.length - 1; i >= 0; i--) if (!work[i].length) work.splice(i, 1);
    }
    this.linCache.set(name, out);
    return out;
  }

  allVars(contract: string): Map<string, VarInfo> {
    const m = new Map<string, VarInfo>();
    for (const cn of [...this.lin(contract)].reverse()) for (const [k, v] of this.contracts.get(cn)!.vars) {
      if (m.has(k) && m.get(k)!.contract !== v.contract) this.warnings.push(`state variable '${k}' declared in both ${m.get(k)!.contract} and ${v.contract} (pre-0.6 shadowing): analysis merges them by name`);
      m.set(k, v);
    }
    return m;
  }
  findFn(contract: string, name: string, argc: number): FnInfo | null {
    for (const cn of this.lin(contract)) {
      const c = this.contracts.get(cn)!;
      const hit = c.fns.find(f => f.name === name && f.params.length === argc && f.kind === 'function' && f.node.body);
      if (hit) return hit;
    }
    return null;
  }
  /** all same-name/same-arity candidates in the most-derived contract that declares one (overloads ⇒ >1) */
  findFns(contract: string, name: string, argc: number, after?: string): FnInfo[] {
    let lin = this.lin(contract);
    if (after) { const i = lin.indexOf(after); lin = i >= 0 ? lin.slice(i + 1) : lin; }
    for (const cn of lin) {
      const hits = this.contracts.get(cn)!.fns.filter(f => f.name === name && f.params.length === argc && f.kind === 'function' && f.node.body);
      if (hits.length) return hits;
    }
    return [];
  }
  findModifier(contract: string, name: string): FnInfo | null {
    for (const cn of this.lin(contract)) { const m = this.contracts.get(cn)!.modifiers.get(name); if (m) return m; }
    return null;
  }
  usingLibs(contract: string): string[] {
    const libs: string[] = [];
    for (const cn of this.lin(contract)) for (const u of this.contracts.get(cn)!.usings) if (!libs.includes(u.lib)) libs.push(u.lib);
    return libs;
  }
  /** base-constructor argument nodes supplied by inheritance clauses and constructor modifier-invocations */
  baseCtorArgs(contract: string): Map<string, any[]> {
    const m = new Map<string, any[]>();
    for (const cn of this.lin(contract)) {
      const c = this.contracts.get(cn)!;
      for (const b of c.node.baseContracts || []) if (b.arguments?.length && !m.has(b.baseName.namePath)) m.set(b.baseName.namePath, b.arguments);
      const ctor = c.fns.find(f => f.kind === 'constructor');
      for (const mo of ctor?.modifiers ?? []) if (this.contracts.has(mo.name) && mo.args.length && !m.has(mo.name)) m.set(mo.name, mo.args);
    }
    return m;
  }
  isContractName(n: string): boolean { return this.contracts.has(n); }
  isLibrary(n: string): boolean { return this.contracts.get(n)?.kind === 'library'; }

  /** public/external functions visible on `contract`, most-derived override wins. */
  entrypoints(contract: string): FnInfo[] {
    const seen = new Set<string>(); const out: FnInfo[] = [];
    for (const cn of this.lin(contract)) {
      for (const f of this.contracts.get(cn)!.fns) {
        if (f.kind === 'constructor') continue;
        if (!(f.visibility === 'public' || f.visibility === 'external' || f.kind === 'receive' || f.kind === 'fallback')) continue;
        if (!f.node.body) continue;
        const sig = `${f.name}(${f.params.map(p => p.type).join(',')})`;
        if (seen.has(sig)) continue; seen.add(sig); out.push(f);
      }
    }
    return out;
  }

  /** deployable leaf contracts; token-like (transfer+balanceOf) preferred. */
  pickTargets(explicit?: string): string[] {
    if (explicit) return explicit.split(',').map(s => s.trim()).filter(n => this.contracts.has(n));
    const all = [...this.contracts.values()].filter(c => c.kind === 'contract');
    const inherited = new Set<string>();
    for (const c of all) for (const b of this.lin(c.name).slice(1)) inherited.add(b);
    const leaves = all.filter(c => !inherited.has(c.name));
    const tokenLike = leaves.filter(c => {
      const eps = this.entrypoints(c.name).map(f => f.name);
      const hasBal = this.lin(c.name).some(cn => this.contracts.get(cn)!.fns.some(f => f.name === 'balanceOf'));
      return eps.includes('transfer') && hasBal;
    });
    return (tokenLike.length ? tokenLike : leaves).map(c => c.name);
  }
}
