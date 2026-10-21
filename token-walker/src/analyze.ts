// token-walker :: analyze.ts — effect grouping, access class, sinks, accounting-divergence sites, external-call matrix
import { FnInfo, VarInfo } from './parse';
import { EntryResult } from './engine';
import { PathRec, WriteEv, CallEv, ReadEv, WalkerConfig } from './types';
import { TokenModel, isAccounting } from './model';

export interface Ctx { target: string; roles: Map<string, string[]>; model: TokenModel; vars: Map<string, VarInfo> }
export interface NodeFacts {
  id: string; access: string; reads: Set<string>; writes: Set<string>; accountingWrites: Set<string>;
  divergenceKinds: Set<string>; sinkKinds: Set<string>; hints: Set<string>; incomplete: boolean; mutates: boolean; viewOnly: boolean; selfFeedback: boolean;
}
const base = (v: string) => v.split('.')[0];

function esc(s: string) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

export function analyzeEntry(id: string, fn: FnInfo, res: EntryResult, ctx: Ctx, cfg: WalkerConfig) {
  const rolesOf = (v: string) => ctx.roles.get(base(v)) ?? [];
  const hasRole = (v: string, r: string) => rolesOf(v).includes(r);
  const pairVars = ctx.model.pair_vars, routerVars = ctx.model.router_vars, mutexVars = ctx.model.mutex_vars;
  // ── access class: evidence-based; "permissionless" is only claimed when NO path carries any auth-shaped guard ──
  type Kind = 'owner' | 'role' | 'self' | 'unknown';
  type Auth = { kind: Kind; text: string; confident: boolean };
  const ROLEISH = /owner|admin|operator|minter|governance|governor|manager|guardian|authority|controller|keeper|role|multisig|timelock|treasury|marketing|pauser|deployer|whitelist|authori[sz]ed|allowed/i;
  const privSets = new Set(ctx.model.exclusion_vars.filter(e => e.subrole === 'privileged_set').map(e => e.var));
  const treasury = new Set(ctx.model.treasury_vars);
  // structural shape alone is NOT proof of privilege: only role-tagged / role-named subjects are 'role'; anything else is 'unknown'
  const classifyAlt = (alt: string): { kind: Kind; confident: boolean } | null => {
    alt = alt.trim().replace(/^\(+|\)+$/g, '');
    let m = /^(.+?) == (.+)$/.exec(alt);
    if (m) {
      const [a, b] = [m[1].trim(), m[2].trim()]; const other = /^(msg\.sender|tx\.origin)$/.test(a) ? b : /^(msg\.sender|tx\.origin)$/.test(b) ? a : null;
      if (other === null) return /msg\.sender|tx\.origin/.test(alt) ? { kind: 'unknown', confident: false } : null;
      if (other === 'this') return { kind: 'self', confident: true };
      if (/^[A-Za-z_]\w*$/.test(other) && ctx.vars.has(other)) {
        if (ctx.model.owner_vars.includes(other)) return { kind: 'owner', confident: true };
        if (treasury.has(other) || privSets.has(other)) return { kind: 'role', confident: true };
        return ROLEISH.test(other) ? { kind: 'role', confident: false } : { kind: 'unknown', confident: false };
      }
      if (/ext</.test(other)) return { kind: 'role', confident: false };
      return { kind: 'unknown', confident: false };
    }
    m = /^(\w+)\[(msg\.sender|tx\.origin)\]$/.exec(alt);
    if (m && ctx.vars.has(m[1])) {
      const r = ctx.roles.get(m[1]) ?? [];
      if (r.includes('blacklist')) return null;
      if (privSets.has(m[1])) return { kind: 'role', confident: true };
      return ROLEISH.test(m[1]) ? { kind: 'role', confident: false } : { kind: 'unknown', confident: false };
    }
    if (/ext<[^>]*>\(.*(msg\.sender|tx\.origin)/.test(alt)) return { kind: 'role', confident: false };   // registry / helper keyed by caller
    return null;
  };
  const authOf = (p: PathRec): Auth | null => {
    let best: Auth | null = null;
    for (const c of p.constraints) {
      if (c.kind !== 'require' || !/msg\.sender|tx\.origin/.test(c.text) || c.text.startsWith('!') || / != /.test(c.text) && !/ == /.test(c.text)) continue;
      const alts = c.text.split(' || ').map(classifyAlt).filter((x): x is { kind: Kind; confident: boolean } => x !== null);
      if (!alts.length) continue;
      const pick = alts.find(a => a.kind === 'owner') ?? alts.find(a => a.kind === 'role') ?? alts.find(a => a.kind === 'self') ?? alts[0];
      const cand: Auth = { kind: pick.kind, text: c.text, confident: alts.every(a => a.confident) };
      if (cand.kind === 'owner') return cand;
      if (!best || best.kind === 'unknown') best = cand;
    }
    return best;
  };
  const auths = res.paths.map(authOf);
  let accessClass = 'permissionless'; let accessUncertain = false;
  if (fn.kind === 'constructor') accessClass = 'constructor';
  else if (!res.paths.length) { accessClass = 'unknown'; accessUncertain = true; }
  else if (auths.every(a => a?.kind === 'owner')) accessClass = 'owner-only';
  else if (auths.every(a => a !== null)) { accessClass = auths.some(a => a!.kind === 'unknown') ? 'unknown' : auths.every(a => a!.kind === 'self') ? 'self-only' : 'role-gated'; accessUncertain = accessClass === 'unknown' || auths.some(a => !a!.confident); }
  else if (auths.some(a => a !== null)) { accessClass = 'mixed'; accessUncertain = true; }
  const guards = [...new Set(auths.filter((a): a is Auth => a !== null).map(a => a.text))];
  const constraintStateVars = [...new Set(res.paths.flatMap(p => p.constraints.flatMap(c => (c.text.match(/[A-Za-z_]\w*/g) ?? []).filter(x => ctx.vars.has(x)))))];

  // ── group paths by effect signature ──
  type G = { sig: string; paths: PathRec[]; sets: Set<string> };
  const groups = new Map<string, G>();
  for (const p of res.paths) {
    // signature = ORDERED interleaving of writes and calls (ordering matters for reentrancy windows)
    // + source lines and pair-relevant equality facts, so alias-/location-derived findings are valid for EVERY member of the group
    const pairFacts = p.eqFacts.filter(f => pairVars.some(pv => new RegExp(`\\b${pv}\\b`).test(f))).sort().join(',');
    const sig = p.trace.filter(e => e.k === 'W' || e.k === 'C').map(e => e.k === 'W' ? `W@${(e as WriteEv).line}:${(e as WriteEv).delta}` : `C@${(e as CallEv).line}:${(e as CallEv).kind}:${(e as CallEv).target}.${(e as CallEv).fn}(${(e as CallEv).args.join(',')})${(e as CallEv).value ? '{' + (e as CallEv).value + '}' : ''}`).join(' ; ') + ' || EQ:' + pairFacts;
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
    const rs = dedupe(g.paths.flatMap(pp => pp.trace.filter(e => e.k === 'R') as ReadEv[]), r => `${r.var}|${r.key}`);   // UNION over the group
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
      if (ctx.model.balance_of_inputs.global_inputs.includes(base(w.var))) pseudoW.add('PAIR_BALANCE');   // only vars balanceOf() provably reads
      return { idx, var: w.var, key: w.key, key_class: w.keyClass, op: w.op, operand: w.operand, delta: w.delta, line: w.line, fn: w.fn, in_loop: w.inLoop, roles, pair_alias: pa, ext_derived: /ext</.test(w.expr) };
    });
    for (const r of rs) { if (/getReserves|price\d?Cumulative|kLast/.test(r.var)) pseudoR.add('PAIR_RESERVE'); }
    // sinks ───────────
    const sinks: any[] = [];
    cs.forEach((c, i) => {
      const t = c.target; const tIsPair = pairVars.some(p => t === p || t.endsWith(`(${p})`)); const tIsRouter = routerVars.some(p => t === p || t.endsWith(`(${p})`));
      if (c.likelyView) { if (c.fn === 'getReserves') pseudoR.add('PAIR_RESERVE'); if (c.fn === 'balanceOf' && (pairVars.includes(c.args[0]) || /pair/i.test(c.args.join()))) pseudoR.add('PAIR_BALANCE'); return; }
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
      sinks.push({ kind, line: c.line, fn: c.callerFn, target: t, target_class: c.targetClass, call: `${t}.${c.fn}(${c.args.join(', ')})`, value: c.value, zero_min_out: (/^swapExactETH/.test(c.fn) && c.args[0] === '0') || (/^swapExact(?!ETH)/.test(c.fn) && c.args[1] === '0') });
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
    for (const w of pairWrites) div.push({ kind: 'pair_balance_written_by_token_logic', confidence: w.pair_alias, basis: 'path_constraint_or_pair_var_key', line: w.line, fn: w.fn, detail: w.delta, note: syncIdx >= 0 ? 'pair.sync() also called in this path' : 'no pair.sync() in this path → reserve may lag balance' });
    for (const w of wj.filter(x => x.roles.includes('rate_driver'))) {
      const params = fn.params.map(p => p.name).filter(n => n && new RegExp(`\\b${n}\\b`).test(w.operand ?? ''));
      const feeScaled = ctx.model.fee_vars.some(f => new RegExp(`\\b${f}\\b`).test(w.operand ?? ''));
      const hint = !params.length ? 'no_user_control' : feeScaled ? 'user_controlled_fee_scaled' : 'user_controlled_unscaled';
      const beh = (ctx.model.evidence[base(w.var)] ?? []).some(e => /read by balanceOf/.test(e));
      div.push({ kind: 'implicit_balance_shift', confidence: beh ? 'definite' : 'inferred', basis: beh ? 'behavioral:balanceOf-reads-var' : 'name_heuristic', line: w.line, fn: w.fn, detail: w.delta, operand_params: params, magnitude_hint: hint,
        note: `writes ${base(w.var)} which balanceOf() reads globally → every holder (incl. pair) changes balance without a balance-map write` });
    }
    for (const w of wj.filter(x => x.roles.includes('supply'))) div.push({ kind: 'supply_mutation', confidence: (ctx.model.evidence[base(w.var)] ?? []).some(e => /read by totalSupply/.test(e)) ? 'definite' : 'inferred', basis: 'role:supply', line: w.line, fn: w.fn, detail: w.delta, note: 'totalSupply-driving variable changed' });
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
      callMap.set(ck, { entry: id, group_count: 1, line: c.line, fn: c.callerFn, kind: c.kind, target: c.target, target_class: c.targetClass, target_type: c.targetType, function: c.fn, args: c.args, value: c.value, likely_view: c.likelyView, view_basis: c.viewBasis ?? 'unknown', callback_surface: c.likelyView ? 'no' : hook, state_writes_after_call: wAfter, mutex_guard: mutex });
    });

    // graph facts ───────────
    for (const w of wj) { writes.add(base(w.var)); if (isAcct(w.roles)) acct.add(base(w.var)); }
    for (const r of rs) reads.add(base(r.var));
    pseudoW.forEach(p => { writes.add(p); acct.add(p); }); pseudoR.forEach(p => reads.add(p));
    div.forEach(d => { dk.add(d.kind); if (d.magnitude_hint) hints.add(d.magnitude_hint); }); sinks.forEach(s => sk.add(s.kind));
    const agg = (m: Map<string, any>, key: string, rec: any) => { const e = m.get(key); if (e) { e.group_count++; if (e.groups.length < 5) e.groups.push(gid); } else m.set(key, { ...rec, group_count: 1, groups: [gid] }); };
    div.forEach(d => agg(divMap, `${d.kind}|${d.line}|${d.detail}|${d.confidence}`, { entry: id, basis: 'observed_path_fact', ...d }));
    sinks.forEach(s => agg(sinkMap, `${s.kind}|${s.line}|${s.call}`, { entry: id, ...s }));

    groupJson.push({
      group_id: gid, path_count: g.paths.length, outcome: 'completes',
      flags: [...new Set(g.paths.flatMap(p => p.flags))],
      call_chain_union: [...new Set(g.paths.flatMap(p => p.chain))],
      representative: { note: 'facts of the FIRST path in the group; other members may differ — see constraint_sets', call_chain: rep.chain, eq_facts: eq,
        constraints: rep.constraints.map(c => ({ text: c.text, kind: c.kind, line: c.line, fn: c.fn })) },
      constraint_sets_total: g.sets.size, constraint_sets_truncated: g.sets.size > cfg.maxConstraintSets, constraint_sets: [...g.sets].slice(0, cfg.maxConstraintSets),
      reads_scope: 'union', reads: rs.map(r => ({ var: r.var, key: r.key, line: r.line, fn: r.fn })), writes: wj,
      external_calls: cs.map(c => ({ kind: c.kind, target: c.target, target_class: c.targetClass, function: c.fn, args: c.args, value: c.value, likely_view: c.likelyView, line: c.line })),
      sinks: sinks.map(s => s.kind), divergence: div.map(d => d.kind),
      pseudo: { reads: [...pseudoR], writes: [...pseudoW] },
    });
  }

  // overall read/write union for graph (incl. reads from views)
  const allFlags = [...new Set(res.paths.flatMap(p => p.flags))];
  const incompleteReasons = [...allFlags.filter(f => /^(unsupported_stmt|unmodeled_|unresolved_|depth_limit|overload_ambiguous|loop_effects_bounded)/.test(f)), ...(res.truncated ? [`path_cap_truncation(discarded=${res.discarded})`] : []), ...(res.error ? [`engine_error:${res.error.slice(0, 80)}`] : [])];
  const mutates = writes.size > 0 || sk.size > 0;
  const node: NodeFacts = {
    id, access: accessClass, reads, writes, accountingWrites: acct, divergenceKinds: dk, sinkKinds: sk, hints,
    incomplete: incompleteReasons.length > 0, mutates, viewOnly: fn.mutability === 'view' || fn.mutability === 'pure', selfFeedback: [...writes].some(w => reads.has(w)),
  };
  const json: any = {
    id, contract: fn.contract, name: fn.name, kind: fn.kind, signature: `${fn.name}(${fn.params.map(p => p.type).join(',')})`,
    visibility: fn.visibility, mutability: fn.mutability, payable: fn.mutability === 'payable' || fn.kind === 'receive',
    params: fn.params, modifiers: fn.modifiers.map(m => m.name), line: fn.line, file: fn.file,
    access: { class: accessClass, guards, uncertain: accessUncertain },
    constraint_state_vars: constraintStateVars,
    summary: {
      paths_enumerated: res.enumerated, paths_completing: res.paths.length, paths_reverting: res.revertedPaths.length, effect_groups: groups.size, reverting_guards: res.reverts.length,
      states_generated: res.statesGenerated, paths_discarded_by_cap: res.discarded, peak_frontier: res.peakFrontier,
      truncated: res.truncated, cap: cfg.maxPathsPerEntry, flags: allFlags,
      complete: incompleteReasons.length === 0, incomplete_reasons: incompleteReasons,
      approximations: allFlags.filter(f => /^(loop_unrolled_once|ternary_effects_merged|self_external_call)$/.test(f)),
    },
    reverting_guards: res.reverts,
    execution_paths: [...res.paths, ...res.revertedPaths].map((p, i) => ({
      path_id: `${id}#P${i + 1}`, outcome: p.outcome, call_chain: p.chain,
      branch_conditions: p.constraints.map(c => ({ condition: c.text, arm: c.arm, kind: c.kind, line: c.line, fn: c.fn })),
      constraints: p.constraints.map(c => c.text), trace: p.trace.map((event, step) => ({ step: step + 1, ...event })), effects_committed: p.outcome === 'completes',
      failure: p.failure, flags: p.flags, return_value: p.ret,
    })),
    reads_union: [...reads], writes_union: [...writes],
    effect_groups: groupJson,
  };
  if (cfg.rawPaths) json.paths = res.paths.map((p, i) => ({ path_id: `${id}#P${i + 1}`, call_chain: p.chain, constraints: p.constraints.map(c => c.text), trace: p.trace }));
  const num = (m: Map<string, any>, p: string) => [...m.values()].map((v, i) => ({ id: `${id}:${p}${i + 1}`, ...v }));
  const isCtor = fn.kind === 'constructor';
  return { json, node, sinks: isCtor ? [] : num(sinkMap, 'S'), divergences: isCtor ? [] : num(divMap, 'D'), calls: num(callMap, 'C') };

  function isAcct(roles: string[]) { return isAccounting(roles); }
}

function dedupe<T>(a: T[], k: (x: T) => string): T[] { const s = new Set<string>(); return a.filter(x => { const kk = k(x); if (s.has(kk)) return false; s.add(kk); return true; }); }
void esc;
