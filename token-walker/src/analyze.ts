// token-walker :: analyze.ts — effect grouping, access class, sinks, accounting-divergence sites, external-call matrix
import { FnInfo, VarInfo } from './parse';
import { EntryResult } from './engine';
import { PathRec, WriteEv, CallEv, ReadEv, WalkerConfig } from './types';
import { TokenModel } from './model';

export interface Ctx { target: string; roles: Map<string, string[]>; model: TokenModel; vars: Map<string, VarInfo> }
export interface NodeFacts {
  id: string; access: string; reads: Set<string>; writes: Set<string>; accountingWrites: Set<string>;
  divergenceKinds: Set<string>; sinkKinds: Set<string>; hints: Set<string>; mutates: boolean; viewOnly: boolean; selfFeedback: boolean;
}
const base = (v: string) => v.split('.')[0];

function esc(s: string) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

export function analyzeEntry(id: string, fn: FnInfo, res: EntryResult, ctx: Ctx, cfg: WalkerConfig) {
  const rolesOf = (v: string) => ctx.roles.get(base(v)) ?? [];
  const hasRole = (v: string, r: string) => rolesOf(v).includes(r);
  const pairVars = ctx.model.pair_vars, routerVars = ctx.model.router_vars, mutexVars = ctx.model.mutex_vars;
  const authVarSet = new Set<string>([...ctx.model.owner_vars, ...ctx.model.exclusion_vars.filter(e => e.subrole === 'privileged_set').map(e => e.var)]);

  // ── access class ──
  const authOf = (p: PathRec): 'owner' | 'role' | 'self' | null => {
    for (const c of p.constraints) {
      if (c.kind !== 'require' || c.arm !== 'T' || c.text.startsWith('!') || !/msg\.sender|tx\.origin/.test(c.text)) continue;
      const ids = c.text.match(/[A-Za-z_]\w*/g) ?? [];
      if (ids.some(i => ctx.model.owner_vars.includes(i))) return 'owner';
      if (ids.some(i => authVarSet.has(i) || /role|admin|owner|operator|minter|governance/i.test(i))) return 'role';
      if (/\bthis\b/.test(c.text) && /==/.test(c.text)) return 'self';
    }
    return null;
  };
  const auths = res.paths.map(authOf);
  let accessClass = 'permissionless';
  if (fn.kind === 'constructor') accessClass = 'constructor';
  else if (res.paths.length && auths.every(a => a === 'owner')) accessClass = 'owner-only';
  else if (res.paths.length && auths.every(a => a !== null)) accessClass = auths.every(a => a === 'self') ? 'self-only' : 'role-gated';
  else if (auths.some(a => a !== null)) accessClass = 'mixed';
  const guards = [...new Set(res.paths.flatMap(p => p.constraints.filter(c => c.arm === 'T' && c.kind === 'require' && /msg\.sender|tx\.origin/.test(c.text)).map(c => c.text)))];

  // ── group paths by effect signature ──
  type G = { sig: string; paths: PathRec[]; sets: Set<string> };
  const groups = new Map<string, G>();
  for (const p of res.paths) {
    const w = p.trace.filter(e => e.k === 'W') as WriteEv[];
    const c = p.trace.filter(e => e.k === 'C') as CallEv[];
    const sig = w.map(x => x.delta).join(' ; ') + ' || ' + c.map(x => `${x.kind}:${x.target}.${x.fn}(${x.args.join(',')})${x.value ? '{' + x.value + '}' : ''}`).join(' ; ');
    let g = groups.get(sig); if (!g) { g = { sig, paths: [], sets: new Set() }; groups.set(sig, g); }
    g.paths.push(p); g.sets.add(p.constraints.map(c2 => c2.text).join(' && '));
  }

  const divMap = new Map<string, any>(), sinkMap = new Map<string, any>(), callMap = new Map<string, any>();
  const reads = new Set<string>(), writes = new Set<string>(), acct = new Set<string>(), dk = new Set<string>(), sk = new Set<string>(), hints = new Set<string>();
  let gi = 0; const groupJson: any[] = [];

  for (const g of groups.values()) {
    const gid = `${id}#G${++gi}`; const rep = g.paths[0];
    const trace = rep.trace;
    const ws = trace.filter(e => e.k === 'W') as WriteEv[];
    const cs = trace.filter(e => e.k === 'C') as CallEv[];
    const rs = dedupe(trace.filter(e => e.k === 'R') as ReadEv[], r => `${r.var}|${r.key}`);
    const eq = rep.eqFacts;
    const pairAlias = (key: string | null): 'definite' | 'possible' | 'no' => {
      if (key === null) return 'no';
      const k0 = key.split(', ')[0];
      if (pairVars.includes(k0) || eq.some(f => pairVars.some(p => f === `${k0} == ${p}` || f === `${p} == ${k0}`))) return 'definite';
      if (k0 === 'this' || /^(0x|address\(|\d)/.test(k0) || ctx.vars.has(k0)) return 'no';
      return k0 === 'msg.sender' || k0 === 'tx.origin' ? 'no' : 'possible';
    };
    const pseudoW = new Set<string>(), pseudoR = new Set<string>();
    const wj = ws.map((w, idx) => {
      const roles = rolesOf(w.var); const isBal = roles.includes('balance');
      const pa = isBal ? pairAlias(w.key) : 'no';
      if (pa !== 'no') pseudoW.add('PAIR_BALANCE');
      if (roles.includes('rate_driver') || roles.includes('supply')) pseudoW.add('PAIR_BALANCE');
      return { idx, var: w.var, key: w.key, key_class: w.keyClass, op: w.op, operand: w.operand, delta: w.delta, line: w.line, fn: w.fn, in_loop: w.inLoop, roles, pair_alias: pa, ext_derived: /ext</.test(w.expr) };
    });
    for (const r of rs) { if (/getReserves|price\d?Cumulative|kLast/.test(r.var)) pseudoR.add('PAIR_RESERVE'); }
    // sinks ───────────
    const sinks: any[] = [];
    cs.forEach((c, i) => {
      const t = c.target; const tIsPair = pairVars.some(p => t === p || t.endsWith(`(${p})`)); const tIsRouter = routerVars.some(p => t === p || t.endsWith(`(${p})`));
      if (c.likelyView) { if (c.fn === 'getReserves') pseudoR.add('PAIR_RESERVE'); if (c.fn === 'balanceOf' && /pair/i.test(c.args.join())) pseudoR.add('PAIR_BALANCE'); return; }
      let kind: string = c.kind;
      if (c.kind === 'external') {
        if (tIsPair) kind = `pair_${c.fn}`;
        else if (tIsRouter) kind = `router_${c.fn}`;
        else if (/^(transfer|safeTransfer)$/.test(c.fn)) kind = 'external_token_transfer';
        else if (/^(transferFrom|safeTransferFrom)$/.test(c.fn)) kind = 'external_token_pull';
        else if (/^(mint|_mint)$/.test(c.fn)) kind = 'external_mint';
        else if (/^(burn|burnFrom)$/.test(c.fn)) kind = 'external_burn';
        else kind = 'external_call';
      }
      sinks.push({ kind, line: c.line, fn: c.callerFn, target: t, target_class: c.targetClass, call: `${t}.${c.fn}(${c.args.join(', ')})`, value: c.value, zero_min_out: /^swapExact/.test(c.fn) && c.args[1] === '0' });
    });
    ws.forEach(w => {
      const roles = rolesOf(w.var);
      if (roles.includes('supply') && w.op === '+=') sinks.push({ kind: 'supply_increase', line: w.line, fn: w.fn, target: w.var, call: w.delta });
      if (roles.includes('supply') && w.op === '-=') sinks.push({ kind: 'supply_decrease', line: w.line, fn: w.fn, target: w.var, call: w.delta });
      if (roles.includes('balance') && /dead|address\(0\)|^0x0*$/i.test(w.key ?? '') && w.op !== '-=') sinks.push({ kind: 'burn_to_dead', line: w.line, fn: w.fn, target: `${w.var}[${w.key}]`, call: w.delta });
    });
    // accounting divergence ───────────
    const div: any[] = [];
    const pairWrites = wj.filter(w => w.roles.includes('balance') && w.pair_alias === 'definite');
    const syncIdx = cs.findIndex(c => !c.likelyView && /^sync$/.test(c.fn));
    for (const w of pairWrites) div.push({ kind: 'pair_balance_written_by_token_logic', confidence: w.pair_alias, line: w.line, fn: w.fn, detail: w.delta, note: syncIdx >= 0 ? 'pair.sync() also called in this path' : 'no pair.sync() in this path → reserve may lag balance' });
    for (const w of wj.filter(x => x.roles.includes('rate_driver'))) {
      const params = fn.params.map(p => p.name).filter(n => n && new RegExp(`\\b${n}\\b`).test(w.operand ?? ''));
      const feeScaled = ctx.model.fee_vars.some(f => new RegExp(`\\b${f}\\b`).test(w.operand ?? ''));
      const hint = !params.length ? 'no_user_control' : feeScaled ? 'user_controlled_fee_scaled' : 'user_controlled_unscaled';
      div.push({ kind: 'implicit_balance_shift', confidence: 'definite', line: w.line, fn: w.fn, detail: w.delta, operand_params: params, magnitude_hint: hint,
        note: `writes ${base(w.var)} which balanceOf() reads globally → every holder (incl. pair) changes balance without a balance-map write` });
    }
    for (const w of wj.filter(x => x.roles.includes('supply'))) div.push({ kind: 'supply_mutation', confidence: 'definite', line: w.line, fn: w.fn, detail: w.delta, note: 'totalSupply-driving variable changed' });
    const credits = wj.filter(x => x.roles.includes('balance') && /\+=/.test(x.op)), debits = wj.filter(x => x.roles.includes('balance') && /-=/.test(x.op));
    if (credits.length && !debits.length && !wj.some(x => x.roles.includes('supply'))) div.push({ kind: 'balance_credit_without_debit', confidence: 'possible', line: credits[0].line, fn: credits[0].fn, detail: credits.map(c => c.delta).join(' ; '), note: 'balance credited with no balance debit and no supply write in same path' });
    if (debits.length && !credits.length && !wj.some(x => x.roles.includes('supply'))) div.push({ kind: 'balance_debit_without_credit', confidence: 'possible', line: debits[0].line, fn: debits[0].fn, detail: debits.map(c => c.delta).join(' ; '), note: 'balance debited with no credit and no supply write (burn-like) in same path' });
    for (const w of debits.filter(x => ['state_addr', 'constant', 'other'].includes(x.key_class) && x.pair_alias !== 'definite'))
      div.push({ kind: 'third_party_debit', confidence: 'possible', line: w.line, fn: w.fn, detail: w.delta, note: 'balance of a non-caller, non-parameter address is reduced by token logic' });
    const readsSelfBal = rep.constraints.some(c => /balanceOf\(this\)|this\.balance|\$native_balance/.test(c.text)) || rs.some(r => r.key === 'this' && ctx.roles.get(base(r.var))?.includes('balance'));
    if (readsSelfBal && sinks.some(s => !['supply_increase', 'supply_decrease', 'burn_to_dead'].includes(s.kind)))
      div.push({ kind: 'contract_balance_triggered_sink', confidence: 'definite', line: sinks[0]?.line ?? 0, fn: sinks[0]?.fn ?? fn.name, detail: sinks.map(s => s.call).join(' ; '), note: 'external/native sink reachable once the token contract\'s own balance crosses a threshold — donation/threshold surface' });
    for (const s of sinks.filter(s => s.zero_min_out)) div.push({ kind: 'zero_slippage_swap', confidence: 'definite', line: s.line, fn: s.fn, detail: s.call, note: 'amountOutMin = 0 → sandwichable by anyone who can trigger this path' });

    // external-call matrix + reentrancy windows ───────────
    cs.forEach((c, i) => {
      const after = trace.slice(trace.indexOf(c) + 1);
      const wAfter = [...new Set((after.filter(e => e.k === 'W') as WriteEv[]).map(w => w.var))];
      let mutex: string | null = null;
      for (const m of mutexVars) {
        const before = trace.slice(0, trace.indexOf(c)).some(e => e.k === 'W' && (e as WriteEv).var === m && /true/.test((e as WriteEv).expr));
        const rel = after.some(e => e.k === 'W' && (e as WriteEv).var === m && /false/.test((e as WriteEv).expr));
        if (before && rel) mutex = m;
      }
      const hook = !c.likelyView && (['low_level_call', 'delegatecall', 'native_transfer', 'native_send'].includes(c.kind) ? 'yes' : (c.targetClass === 'param' || c.targetClass === 'derived' || c.targetClass === 'caller') ? 'yes' : 'possible');
      const ck = `${c.kind}|${c.target}|${c.fn}|${c.args.join(',')}|${c.line}`; const prev = callMap.get(ck);
      if (prev) { prev.group_count++; prev.state_writes_after_call = [...new Set([...prev.state_writes_after_call, ...wAfter])]; if (!mutex) prev.mutex_guard = prev.mutex_guard && prev.group_count > 1 ? null : prev.mutex_guard; return; }
      callMap.set(ck, { entry: id, group_count: 1, line: c.line, fn: c.callerFn, kind: c.kind, target: c.target, target_class: c.targetClass, target_type: c.targetType, function: c.fn, args: c.args, value: c.value, likely_view: c.likelyView, callback_surface: c.likelyView ? 'no' : hook, state_writes_after_call: wAfter, mutex_guard: mutex });
    });

    // graph facts ───────────
    for (const w of wj) { writes.add(base(w.var)); if (isAcct(w.roles)) acct.add(base(w.var)); }
    for (const r of rs) reads.add(base(r.var));
    pseudoW.forEach(p => { writes.add(p); acct.add(p); }); pseudoR.forEach(p => reads.add(p));
    div.forEach(d => { dk.add(d.kind); if (d.magnitude_hint) hints.add(d.magnitude_hint); }); sinks.forEach(s => sk.add(s.kind));
    const agg = (m: Map<string, any>, key: string, rec: any) => { const e = m.get(key); if (e) { e.group_count++; if (e.groups.length < 5) e.groups.push(gid); } else m.set(key, { ...rec, group_count: 1, groups: [gid] }); };
    div.forEach(d => agg(divMap, `${d.kind}|${d.line}|${d.detail}|${d.confidence}`, { entry: id, ...d }));
    sinks.forEach(s => agg(sinkMap, `${s.kind}|${s.line}|${s.call}`, { entry: id, ...s }));

    groupJson.push({
      group_id: gid, path_count: g.paths.length, outcome: 'completes',
      call_chain: rep.chain, flags: [...new Set(g.paths.flatMap(p => p.flags))],
      constraints: rep.constraints.map(c => ({ text: c.text, kind: c.kind, line: c.line, fn: c.fn })),
      constraint_sets_total: g.sets.size, constraint_sets: [...g.sets].slice(0, cfg.maxConstraintSets),
      eq_facts: eq, reads: rs.map(r => ({ var: r.var, key: r.key, line: r.line, fn: r.fn })), writes: wj,
      external_calls: cs.map(c => ({ kind: c.kind, target: c.target, target_class: c.targetClass, function: c.fn, args: c.args, value: c.value, likely_view: c.likelyView, line: c.line })),
      sinks: sinks.map(s => s.kind), divergence: div.map(d => d.kind),
      pseudo: { reads: [...pseudoR], writes: [...pseudoW] },
    });
  }

  // overall read/write union for graph (incl. reads from views)
  const mutates = writes.size > 0 || sk.size > 0;
  const node: NodeFacts = {
    id, access: accessClass, reads, writes, accountingWrites: acct, divergenceKinds: dk, sinkKinds: sk, hints,
    mutates, viewOnly: fn.mutability === 'view' || fn.mutability === 'pure', selfFeedback: [...writes].some(w => reads.has(w)),
  };
  const json: any = {
    id, contract: fn.contract, name: fn.name, kind: fn.kind, signature: `${fn.name}(${fn.params.map(p => p.type).join(',')})`,
    visibility: fn.visibility, mutability: fn.mutability, payable: fn.mutability === 'payable' || fn.kind === 'receive',
    params: fn.params, modifiers: fn.modifiers.map(m => m.name), line: fn.line, file: fn.file,
    access: { class: accessClass, guards },
    summary: { paths_enumerated: res.enumerated, paths_completing: res.paths.length, effect_groups: groups.size, reverting_guards: res.reverts.length, truncated: res.truncated, cap: cfg.maxPathsPerEntry, flags: [...new Set(res.paths.flatMap(p => p.flags))] },
    reverting_guards: res.reverts,
    reads_union: [...reads], writes_union: [...writes],
    effect_groups: groupJson,
  };
  if (cfg.rawPaths) json.paths = res.paths.map((p, i) => ({ path_id: `${id}#P${i + 1}`, call_chain: p.chain, constraints: p.constraints.map(c => c.text), trace: p.trace }));
  const num = (m: Map<string, any>, p: string) => [...m.values()].map((v, i) => ({ id: `${id}:${p}${i + 1}`, ...v }));
  const isCtor = fn.kind === 'constructor';
  return { json, node, sinks: isCtor ? [] : num(sinkMap, 'S'), divergences: isCtor ? [] : num(divMap, 'D'), calls: num(callMap, 'C') };

  function isAcct(roles: string[]) { return roles.some(r => ['balance', 'supply', 'rate_driver', 'allowance', 'fee', 'reward_exclusion', 'fee_exempt', 'pair', 'threshold', 'mutex', 'fee_accumulator', 'owner'].includes(r)); }
}

function dedupe<T>(a: T[], k: (x: T) => string): T[] { const s = new Set<string>(); return a.filter(x => { const kk = k(x); if (s.has(kk)) return false; s.add(kk); return true; }); }
void esc;
