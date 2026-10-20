#!/usr/bin/env node
// token-walker :: index.ts — CLI + orchestration → token-state-graph.json
import * as fs from 'fs';
import * as path from 'path';
import { Index } from './parse';
import { Walker } from './engine';
import { classify, isAccounting } from './model';
import { analyzeEntry, NodeFacts } from './analyze';
import { buildGraph, envNodes } from './sequences';
import { DEFAULT_CONFIG, Diagnostics, WalkerConfig } from './types';

const VERSION = '0.1.0';

function parseArgs(argv: string[]) {
  const a: any = { cfg: { ...DEFAULT_CONFIG }, out: 'token-state-graph.json', summary: true, timestamp: true };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    const nxt = () => argv[++i];
    if (x === '--out' || x === '-o') a.out = nxt();
    else if (x === '--contract') a.contract = nxt();
    else if (x === '--depth') a.cfg.maxSeqDepth = Math.min(6, Math.max(2, +nxt()));
    else if (x === '--max-paths') a.cfg.maxPathsPerEntry = +nxt();
    else if (x === '--max-seq') a.cfg.maxSequences = +nxt();
    else if (x === '--include-privileged') a.cfg.includePrivileged = true;
    else if (x === '--raw-paths') a.cfg.rawPaths = true;
    else if (x === '--quiet') a.summary = false;
    else if (x === '--no-timestamp') a.timestamp = false;
    else if (x === '-h' || x === '--help') a.help = true;
    else rest.push(x);
  }
  a.input = rest[0];
  return a;
}

const HELP = `token-walker ${VERSION}
usage: token-walker <file.sol | dir> [-o token-state-graph.json] [--contract Name[,Name]]
       [--depth 4] [--max-paths 20000] [--max-seq 3000] [--include-privileged] [--raw-paths] [--quiet] [--no-timestamp]`;

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.input) { console.log(HELP); process.exit(args.help ? 0 : 1); }
  const cfg: WalkerConfig = args.cfg;
  const diag: Diagnostics = { warnings: [], unresolved_calls: [], unsupported_nodes: [], truncated_entries: [] };
  const ix = new Index();
  const root = path.resolve(args.input);
  const files = Index.collectSol(root);
  if (!files.length) { console.error('no .sol files found'); process.exit(1); }
  for (const f of files) ix.addFile(f);
  diag.warnings.push(...ix.warnings);
  const targets = ix.pickTargets(args.contract);
  if (!targets.length) { console.error('no analyzable contract found (use --contract)'); process.exit(1); }

  const outTargets: any[] = [];
  for (const target of targets) outTargets.push(runTarget(ix, target, cfg, diag));

  const doc = {
    schema_version: '1.0',
    tool: { name: 'token-walker', version: VERSION },
    generated_at: args.timestamp ? new Date().toISOString() : null,
    input: { path: root, files: files.map(f => path.relative(root, f) || path.basename(f)) },
    config: cfg,
    targets: outTargets,
    diagnostics: diag,
  };
  fs.writeFileSync(args.out, JSON.stringify(doc, null, 1));
  if (args.summary) printSummary(doc, args.out);
}

function runTarget(ix: Index, target: string, cfg: WalkerConfig, diag: Diagnostics) {
  const walker = new Walker(ix, target, cfg, diag);
  const c = ix.contracts.get(target)!;

  // behavioural facts for role tagging: what do balanceOf()/totalSupply() read?
  const probe = (name: string) => {
    const f = ix.findFn(target, name, name === 'balanceOf' ? 1 : 0);
    if (!f) return { reads: [] as { var: string; key: string | null }[], param: null as string | null };
    const r = walker.runEntry(f);
    const reads = r.paths.flatMap(p => p.trace.filter(e => e.k === 'R').map((e: any) => ({ var: e.var as string, key: e.key as string | null })));
    return { reads, param: f.params[0]?.name || null };
  };
  const bo = probe('balanceOf'); const ts = probe('totalSupply');
  const { roles, model } = classify(ix, target, { reads: bo.reads, param: bo.param, totalSupplyReads: ts.reads.map(r => r.var) });

  const vars = ix.allVars(target);
  const stateVars = [...vars.values()].map(v => ({
    id: `${v.contract}.${v.name}`, name: v.name, contract: v.contract, type: v.type, kind: v.kind, key_types: v.keyTypes, value_type: v.valueType,
    visibility: v.visibility, constant: v.constant, immutable: v.immutable, initial: v.initial, line: v.line, file: path.basename(v.file),
    roles: roles.get(v.name) ?? [],
  }));

  const ctx = { target, roles, model, vars };
  const nodes: NodeFacts[] = []; const entries: any[] = []; const sinks: any[] = []; const divs: any[] = []; const calls: any[] = [];
  const eps = ix.entrypoints(target);
  const seen = new Map<string, number>();
  const list: { fn: any; ctor: boolean }[] = [{ fn: ctorFn(ix, target), ctor: true }, ...eps.map(fn => ({ fn, ctor: false }))];
  for (const { fn, ctor } of list) {
    const base = `${target}.${fn.name}`; const n = (seen.get(base) ?? 0) + 1; seen.set(base, n);
    const id = n === 1 ? base : `${base}#${n}`;
    const res = ctor ? walker.runConstructor() : walker.runEntry(fn);
    if (res.truncated) diag.truncated_entries.push(`${target}:${id} (cap ${cfg.maxPathsPerEntry})`);
    const a = analyzeEntry(id, fn, res, ctx, cfg);
    entries.push(a.json); nodes.push(a.node); sinks.push(...a.sinks); divs.push(...a.divergences); calls.push(...a.calls);
  }
  const relevant = new Set<string>(['PAIR_BALANCE', 'PAIR_RESERVE', '$native_balance']);
  for (const [v, r] of roles) if (isAccounting(r)) relevant.add(v);
  const seqNodes = [...nodes.filter(n => !n.id.endsWith('.constructor')), ...envNodes(model)];
  const g = buildGraph(seqNodes, relevant, cfg);

  return {
    contract: target, file: path.basename(c.file), linearization: ix.lin(target),
    token_model: model,
    attacker_capabilities: ['flash_loan_any_amount', 'fresh_addresses', 'direct_token_donation_to_any_address', 'pair.sync/skim/swap', 'router_swaps', 'callbacks_from_own_contracts', 'same_tx_multi_call'],
    state_vars: stateVars,
    entrypoints: entries,
    env_entrypoints: envNodes(model).map(n => ({ id: n.id, reads: [...n.reads], writes: [...n.writes], note: 'synthetic AMM primitive; not part of token source' })),
    entrypoint_graph: g.edges,
    sequences: g.sequences,
    divergence_sites: divs,
    sinks,
    external_call_matrix: calls,
  };
}

function ctorFn(ix: Index, target: string): any {
  const c = ix.lin(target).map(n => ix.contracts.get(n)!).find(x => x.fns.some(f => f.kind === 'constructor'));
  const f = c?.fns.find(x => x.kind === 'constructor');
  return { contract: target, name: 'constructor', kind: 'constructor', params: f?.params ?? [], returns: [], visibility: 'public', mutability: f?.mutability ?? 'nonpayable', modifiers: [], node: f?.node ?? { body: { statements: [] } }, file: c?.file ?? '', line: f?.line ?? 0 };
}

function printSummary(doc: any, out: string) {
  const L = (s: string) => process.stderr.write(s + '\n');
  for (const t of doc.targets) {
    L(`\n== ${t.contract} (${t.token_model.ledger_types.join(', ')}) ==`);
    L(`balance: ${t.token_model.balance_vars.join(', ')} | supply: ${t.token_model.supply_vars.join(', ')} | rate_drivers: ${t.token_model.rate_drivers.join(', ')} | pair: ${t.token_model.pair_vars.join(', ') || '-'}`);
    L('entrypoint'.padEnd(34) + 'access'.padEnd(16) + 'paths'.padEnd(8) + 'groups'.padEnd(8) + 'diverg  sinks');
    for (const e of t.entrypoints) {
      const d = t.divergence_sites.filter((x: any) => x.entry === e.id).length, s = t.sinks.filter((x: any) => x.entry === e.id).length;
      L(e.id.padEnd(34) + e.access.class.padEnd(16) + String(e.summary.paths_completing).padEnd(8) + String(e.summary.effect_groups).padEnd(8) + `${String(d).padEnd(8)}${s}${e.summary.truncated ? '  TRUNCATED' : ''}`);
    }
    const kinds: Record<string, number> = {};
    for (const d of t.divergence_sites) kinds[d.kind] = (kinds[d.kind] ?? 0) + 1;
    L('divergence kinds: ' + JSON.stringify(kinds));
    L(`sequences: ${t.sequences.total_generated} generated, ${t.sequences.kept} kept (depth<=${t.sequences.max_depth}). top 8:`);
    for (const s of t.sequences.items.slice(0, 8)) L(`  [${s.score}] ${s.steps.join(' -> ')}`);
  }
  const dg = doc.diagnostics;
  L(`\nwarnings=${dg.warnings.length} unresolved=${dg.unresolved_calls.length} unsupported=${dg.unsupported_nodes.length} truncated=${dg.truncated_entries.length}`);
  for (const w of dg.warnings.slice(0, 10)) L('  ! ' + w);
  L(`wrote ${out} (${(fs.statSync(out).size / 1024).toFixed(0)} KB)`);
}

main();
