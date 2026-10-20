// token-walker :: sequences.ts — cross-entrypoint dependency graph + depth-bounded sequence composition
import { NodeFacts } from './analyze';
import { TokenModel } from './model';
import { WalkerConfig } from './types';

const ENV_PREFIX = 'ENV:';

export function envNodes(model: TokenModel): NodeFacts[] {
  if (!model.pair_vars.length) return [];
  const bal = new Set(model.balance_vars);
  const mk = (id: string, reads: string[], writes: string[], div: string[]): NodeFacts => ({
    id, access: 'permissionless', reads: new Set([...reads, ...bal]), writes: new Set([...writes, ...bal]),
    accountingWrites: new Set([...writes, ...bal]), divergenceKinds: new Set(div), sinkKinds: new Set(['env_pair_primitive']), hints: new Set<string>(),
    mutates: true, viewOnly: false, selfFeedback: false,
  });
  return [
    { id: `${ENV_PREFIX}pair.sync()`, access: 'permissionless', reads: new Set(['PAIR_BALANCE']), writes: new Set(['PAIR_RESERVE']),
      accountingWrites: new Set(['PAIR_RESERVE']), divergenceKinds: new Set<string>(), sinkKinds: new Set(['env_pair_primitive']), hints: new Set<string>(), mutates: true, viewOnly: false, selfFeedback: false },
    mk(`${ENV_PREFIX}pair.skim(to)`, ['PAIR_BALANCE', 'PAIR_RESERVE'], ['PAIR_BALANCE'], ['pair_surplus_extraction']),
    mk(`${ENV_PREFIX}pair.swap(...)`, ['PAIR_BALANCE', 'PAIR_RESERVE'], ['PAIR_BALANCE', 'PAIR_RESERVE'], []),
  ];
}
export function buildGraph(nodes: NodeFacts[], relevant: Set<string>, cfg: WalkerConfig) {
  const edges: any[] = [];
  const adj = new Map<string, { to: NodeFacts; via: string[] }[]>();
  for (const a of nodes) for (const b of nodes) {
    if (b.viewOnly || !b.mutates) continue;
    const via = [...a.writes].filter(w => b.reads.has(w));
    if (!via.length) continue;
    const acct = via.filter(v => relevant.has(v));
    edges.push({ from: a.id, to: b.id, via, via_accounting: acct });
    if (acct.length) { const l = adj.get(a.id) ?? []; l.push({ to: b, via: acct }); adj.set(a.id, l); }
  }
  const startOk = (n: NodeFacts) => !n.viewOnly && n.mutates && n.access !== 'constructor' &&
    (cfg.includePrivileged || n.access === 'permissionless' || n.access === 'mixed');
  const out: any[] = []; let total = 0;
  const score = (path: NodeFacts[]) => {
    let s = 0; const dk = new Set<string>();
    for (const n of path) { s += 2 * n.divergenceKinds.size + 2 * n.sinkKinds.size + n.accountingWrites.size + (n.id.startsWith(ENV_PREFIX) ? 3 : 0) + (n.hints.has('user_controlled_unscaled') ? 30 : 0); n.divergenceKinds.forEach(d => dk.add(d)); }
    if ([...dk].some(d => /pair_balance|implicit_balance_shift|pair_surplus/.test(d)) && path.some(n => n.id.startsWith(ENV_PREFIX))) s += 6;
    return s;
  };
  const dfs = (path: NodeFacts[], links: any[]) => {
    if (path.length >= 2) {
      total++;
      const dk = new Set<string>(), sk = new Set<string>(), av = new Set<string>();
      path.forEach(n => { n.divergenceKinds.forEach(x => dk.add(x)); n.sinkKinds.forEach(x => sk.add(x)); n.accountingWrites.forEach(x => av.add(x)); });
      out.push({
        steps: path.map(n => n.id), length: path.length, score: score(path), links: [...links],
        touches: { divergence: [...dk], sinks: [...sk], accounting_vars: [...av] },
        flags: { contains_env: path.some(n => n.id.startsWith(ENV_PREFIX)), all_permissionless: path.every(n => n.access === 'permissionless' || n.access === 'mixed' || n.id.startsWith(ENV_PREFIX)), repeatable_steps: path.filter(n => n.selfFeedback).map(n => n.id) },
      });
      if (out.length > cfg.maxSequences * 4) { out.sort((a, b) => b.score - a.score); out.length = cfg.maxSequences * 2; }
    }
    if (path.length >= cfg.maxSeqDepth) return;
    const last = path[path.length - 1];
    for (const e of adj.get(last.id) ?? []) {
      if (path.includes(e.to)) continue;
      if (!(cfg.includePrivileged || e.to.access === 'permissionless' || e.to.access === 'mixed')) continue;
      path.push(e.to); links.push({ from: last.id, to: e.to.id, via: e.via }); dfs(path, links); path.pop(); links.pop();
    }
  };
  for (const n of nodes) if (startOk(n) && (n.accountingWrites.size || n.id.startsWith(ENV_PREFIX))) dfs([n], []);
  // collapse permutations/redundant variants: keep best 2 per "touch signature" (same divergence/sink/accounting-var footprint)
  out.sort((a, b) => a.length - b.length || b.score - a.score);          // shortest first within a signature
  const bySig = new Map<string, any[]>();
  for (const s of out) { const k = JSON.stringify([s.touches.divergence.slice().sort(), s.touches.sinks.slice().sort(), s.flags.contains_env]); const l = bySig.get(k) ?? []; l.push(s); bySig.set(k, l); }
  const collapsed: any[] = [];
  for (const l of bySig.values()) { l.slice(0, 3).forEach((s, i) => collapsed.push({ ...s, equivalent_variants: i === 0 ? l.length - 1 : 0 })); }
  collapsed.sort((a, b) => (b.score - 3 * b.length) - (a.score - 3 * a.length) || a.length - b.length);
  const kept = collapsed.slice(0, cfg.maxSequences).map((s, i) => ({ id: `SEQ-${String(i + 1).padStart(4, '0')}`, ...s }));
  return { edges, sequences: { max_depth: cfg.maxSeqDepth, total_generated: total, kept: kept.length, collapsed_by: 'touch-signature (best 3 shortest per signature; equivalent_variants = hidden count)', truncated: total > kept.length, items: kept } };
}
