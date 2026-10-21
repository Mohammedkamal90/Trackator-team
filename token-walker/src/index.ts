#!/usr/bin/env node
// token-walker :: index.ts — CLI + orchestration → token-state-graph.json
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as readline from 'readline';
import { Index } from './parse';
import { Walker, EntryResult } from './engine';
import { classify, isAccounting } from './model';
import { analyzeEntry, NodeFacts } from './analyze';
import { buildGraph, envNodes } from './sequences';
import { DEFAULT_CONFIG, Diagnostics, WalkerConfig } from './types';

const VERSION = '0.5.0';
const HELP = `token-walker ${VERSION}
usage: token-walker <file.sol | dir> [options]
  -o, --out <file>           output path (default token-state-graph.json)
  --contract <A[,B]>         analyze these contracts (error if unknown)
  --exclude <substr[,..]>    skip source files whose path contains any substring
  --depth <2-6>              sequence depth (default 4)
  --max-paths <n>            per-entrypoint completing-path cap (default 20000)
  --max-seq <n>              max sequences kept (default 3000)
  --include-privileged       allow owner/role-gated entrypoints in sequences
  --no-env                   do not add synthetic ENV:pair.* nodes
  --amm <v2[,v3,v4]>         select AMM analysis scenarios (default: V2)
  --raw-paths                also dump every path with ordered trace
  --abs-paths                record absolute input path in output (default: relative/basename)
  --no-timestamp             omit generated_at (byte-identical output)
  --strict                   exit 4 if parse errors, failed files or incomplete entrypoints exist
  --quiet                    no console summary
exit codes: 0 ok, 1 runtime/no input, 2 usage, 3 i/o, 4 strict violation`;

class UsageError extends Error {}

function intArg(name: string, v: string | undefined, min: number, max: number): number {
  if (v === undefined || v.startsWith('-')) throw new UsageError(`${name} requires a value`);
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new UsageError(`${name} must be an integer in [${min}, ${max}] (got '${v}')`);
  return n;
}
function strArg(name: string, v: string | undefined): string {
  if (v === undefined || v.startsWith('-')) throw new UsageError(`${name} requires a value`);
  return v;
}

type AmmModel = 'v2' | 'v3' | 'v4';
function parseAmm(value: string): AmmModel[] {
  const parts = value.split(',').map(s => s.trim().toLowerCase());
  if (!parts.length || parts.some(s => !s)) throw new UsageError("--amm expects a comma-separated list from: v2,v3,v4");
  const seen = new Set<string>();
  for (const part of parts) {
    if (!['v2', 'v3', 'v4'].includes(part)) throw new UsageError(`invalid AMM model '${part}' (expected v2, v3, or v4)`);
    if (seen.has(part)) throw new UsageError(`duplicate AMM model '${part}'`);
    seen.add(part);
  }
  return (['v2', 'v3', 'v4'] as AmmModel[]).filter(x => seen.has(x));
}

async function chooseAmm(args: any): Promise<{ models: AmmModel[]; source: 'cli_argument' | 'interactive_user_input' | 'backward_compatible_default' }> {
  if (args.amm) return { models: args.amm, source: 'cli_argument' };
  if (!(process.stdin.isTTY && process.stdout.isTTY) || process.env.CI) return { models: ['v2'], source: 'backward_compatible_default' };
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await new Promise<string>(resolve => {
      rl.once('close', () => resolve(''));
      rl.question('Select AMM model(s), comma-separated [v2/v3/v4] (default v2): ', resolve);
    });
    return { models: answer.trim() ? parseAmm(answer) : ['v2'], source: 'interactive_user_input' };
  } finally { rl.close(); }
}

function parseArgs(argv: string[]) {
  const a: any = { cfg: { ...DEFAULT_CONFIG }, out: null, outProvided: false, summary: true, timestamp: true, absPaths: false, strict: false, exclude: [] as string[] };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    switch (x) {
      case '-o': case '--out': a.out = strArg(x, argv[++i]); a.outProvided = true; break;
      case '--contract': a.contract = strArg(x, argv[++i]); break;
      case '--amm': a.amm = parseAmm(strArg(x, argv[++i])); break;
      case '--exclude': a.exclude = strArg(x, argv[++i]).split(',').filter(Boolean); break;
      case '--depth': a.cfg.maxSeqDepth = intArg(x, argv[++i], 2, 6); break;
      case '--max-paths': a.cfg.maxPathsPerEntry = intArg(x, argv[++i], 1, 1_000_000); break;
      case '--max-seq': a.cfg.maxSequences = intArg(x, argv[++i], 1, 1_000_000); break;
      case '--include-privileged': a.cfg.includePrivileged = true; break;
      case '--no-env': a.cfg.envModel = false; break;
      case '--raw-paths': a.cfg.rawPaths = true; break;
      case '--abs-paths': a.absPaths = true; break;
      case '--strict': a.strict = true; break;
      case '--quiet': a.summary = false; break;
      case '--no-timestamp': a.timestamp = false; break;
      case '-h': case '--help': a.help = true; break;
      default:
        if (x.startsWith('-')) throw new UsageError(`unknown option '${x}'`);
        rest.push(x);
    }
  }
  if (!a.help) {
    if (rest.length !== 1) throw new UsageError(rest.length ? `expected exactly one input path, got ${rest.length}` : 'missing input path');
    a.input = rest[0];
  }
  return a;
}

async function main(): Promise<number> {
  let args: any;
  try { args = parseArgs(process.argv.slice(2)); }
  catch (e: any) { if (e instanceof UsageError) { console.error(`error: ${e.message}\n\n${HELP}`); return 2; } throw e; }
  if (args.help) { console.log(HELP); return 0; }
  let ammSelection: Awaited<ReturnType<typeof chooseAmm>>;
  try { ammSelection = await chooseAmm(args); }
  catch (e: any) { if (e instanceof UsageError) { console.error(`error: ${e.message}\n\n${HELP}`); return 2; } throw e; }

  const cfg: WalkerConfig = args.cfg;
  const root = path.resolve(args.input);
  if (!fs.existsSync(root)) { console.error(`error: input not found: ${args.input}`); return 1; }

  const diag: Diagnostics = { warnings: [], unresolved_calls: [], unsupported_nodes: [], truncated_entries: [], parse_errors: [], failed_files: [], excluded_files: [], incomplete_entries: [] };
  const ix = new Index();
  const rootDir = fs.statSync(root).isDirectory() ? root : path.dirname(root);
  const rel = (f: string) => path.relative(rootDir, f) || path.basename(f);
  const walkErrors: string[] = [];
  let files = Index.collectSol(root, walkErrors);
  diag.failed_files.push(...walkErrors);
  const kept: string[] = [];
  for (const f of files) { if (args.exclude.some((s: string) => f.includes(s))) diag.excluded_files.push(rel(f)); else kept.push(f); }
  files = kept;
  if (!files.length) { console.error('error: no .sol files found (after --exclude)'); return 1; }
  for (const f of files) ix.addFile(f);
  diag.warnings.push(...ix.warnings);
  diag.parse_errors.push(...ix.parseErrors.map(e => e.replace(rootDir + path.sep, '')));
  diag.failed_files.push(...ix.failedFiles.map(rel));

  if (args.contract) {
    const wanted = (args.contract as string).split(',').map(s => s.trim()).filter(Boolean);
    const missing = wanted.filter(n => !ix.contracts.has(n));
    if (missing.length) { console.error(`error: unknown contract(s): ${missing.join(', ')}\navailable: ${[...ix.contracts.keys()].join(', ')}`); return 2; }
  }
  const targets = ix.pickTargets(args.contract);
  if (!targets.length) { console.error('error: no analyzable contract found (use --contract)'); return 1; }
  if (!args.out) args.out = targets.length === 1 ? `${targets[0]}-state-graph.json` : 'token-state-graph.json';
  const outAbs = path.resolve(args.out);
  if (!fs.existsSync(path.dirname(outAbs))) { console.error(`error: output directory does not exist: ${path.dirname(outAbs)}`); return 3; }

  const outTargets: any[] = [];
  for (const target of targets) outTargets.push(runTarget(ix, target, cfg, diag, rel, ammSelection.models));
  diag.warnings = [...new Set(diag.warnings)];

  let parserVersion = 'unknown';
  try { parserVersion = require('@solidity-parser/parser/package.json').version; } catch { /* optional */ }
  const hashes = files.map(f => ({ p: rel(f), h: crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex') })).sort((a, b) => a.p.localeCompare(b.p));
  const treeHash = crypto.createHash('sha256').update(hashes.map(h => `${h.p}\0${h.h}`).join('\n')).digest('hex');   // identifies the whole analysed tree, not just the basename
  const doc = {
    schema_version: '1.5',
    summary: buildSummary(outTargets, diag),
    amm_selection: ammSelection,          // human-readable overview lives at the TOP of the JSON file
    report_outcome: 'completes',
    tool: { name: 'token-walker', version: VERSION, parser: `@solidity-parser/parser@${parserVersion}`, node: process.version },
    generated_at: args.timestamp ? new Date().toISOString() : null,
    input: {
      path: args.absPaths ? root : path.basename(root),
      tree_sha256: treeHash,
      files: files.map(f => { const b = fs.readFileSync(f); return { path: rel(f), sha256: crypto.createHash('sha256').update(b).digest('hex'), bytes: b.length }; }),
    },
    config: cfg,
    targets: outTargets,
    diagnostics: diag,
  };
  const reverted = splitOutcome(doc, 'reverts');
  const successful = splitOutcome(doc, 'completes');
  const revertAbs = path.join(path.dirname(outAbs), `R-${path.basename(outAbs)}`);
  try { fs.writeFileSync(outAbs, JSON.stringify(successful, null, 1)); fs.writeFileSync(revertAbs, JSON.stringify(reverted, null, 1)); }
  catch (e: any) { console.error(`error: cannot write ${outAbs}: ${e.message}`); return 3; }
  if (args.summary) printRunSummary(successful, args.out);
  if (args.strict && (diag.parse_errors.length || diag.failed_files.length || diag.incomplete_entries.length || ix.duplicates.length)) {
    console.error('strict: parse errors / failed files / duplicate contracts / incomplete entrypoints present'); return 4;
  }
  return 0;
}

function splitOutcome(doc: any, outcome: 'completes' | 'reverts') {
  const copy = JSON.parse(JSON.stringify(doc));
  copy.report_outcome = outcome;
  copy.targets = copy.targets.map((t: any) => ({ ...t, entrypoints: t.entrypoints.map((e: any) => ({ ...e, execution_paths: e.execution_paths.filter((p: any) => outcome === 'completes' ? p.outcome === 'completes' : p.outcome === 'reverts' || p.outcome === 'failed'), paths: outcome === 'completes' ? e.paths : (e.paths ? [] : undefined) })) }));
  copy.summary = buildSummary(copy.targets, copy.diagnostics, outcome);
  return copy;
}

function runTarget(ix: Index, target: string, cfg: WalkerConfig, diag: Diagnostics, rel: (f: string) => string, ammModels: AmmModel[]) {
  const walker = new Walker(ix, target, cfg, diag);
  const c = ix.contracts.get(target)!;
  const base = (s: string) => s.split('.')[0];

  // 1) behavioural probes: what do balanceOf()/totalSupply() read?
  const probe = (name: string) => {
    const fs_ = ix.findFns(target, name, name === 'balanceOf' ? 1 : 0);
    if (!fs_.length) return { reads: [] as { var: string; key: string | null }[], param: null as string | null };
    if (fs_.length > 1) diag.warnings.push(`overload ambiguity: ${target}.${name} has ${fs_.length} same-arity candidates — role probe uses the UNION of their reads`);
    const reads = fs_.flatMap(f => walker.runEntry(f).paths.flatMap(p => p.trace.filter(e => e.k === 'R').map((e: any) => ({ var: e.var as string, key: e.key as string | null }))));
    return { reads, param: fs_[0].params[0]?.name || null };
  };
  const bo = probe('balanceOf'); const ts = probe('totalSupply');

  // 2) run every entrypoint once (engine is role-agnostic)
  const eps = ix.entrypoints(target);
  const seen = new Map<string, number>();
  const runs: { id: string; fn: any; ctor: boolean; res: EntryResult }[] = [];
  for (const { fn, ctor } of [{ fn: ctorFn(ix, target), ctor: true }, ...eps.map(fn => ({ fn, ctor: false }))]) {
    const b = `${target}.${fn.name}`; const n = (seen.get(b) ?? 0) + 1; seen.set(b, n);
    const id = n === 1 ? b : `${b}#${n}`;
    let res: EntryResult;
    try { res = ctor ? walker.runConstructor() : walker.runEntry(fn); }
    catch (err: any) {                                  // an engine bug must never take down the whole run or fake a complete result
      diag.warnings.push(`ENGINE ERROR in ${id}: ${err?.message ?? err} — entrypoint reported with no paths and marked incomplete`);
      const message = String(err?.message ?? err);
      res = { paths: [], revertedPaths: [{ outcome: 'failed', chain: [`${target}.${fn.name}`], constraints: [], eqFacts: [], trace: [{ k: 'X', outcome: 'failed', reason: message, line: fn.line ?? 0, fn: `${target}.${fn.name}` }], flags: ['engine_error'], ret: null, failure: { kind: 'engine-error', reason: message, line: fn.line ?? 0, fn: `${target}.${fn.name}` } }], reverts: [], truncated: false, enumerated: 0, statesGenerated: 0, discarded: 0, peakFrontier: 0, error: message };
    }
    runs.push({ id, fn, ctor, res });
  }
  const writtenVars = new Set<string>();
  for (const r of runs) if (!r.ctor) for (const p of r.res.paths) for (const e of p.trace) if (e.k === 'W') writtenVars.add(base(e.var));

  // 3) role tagging (needs written-var set to demote read-only balanceOf inputs)
  const { roles, model } = classify(ix, target, { reads: bo.reads, param: bo.param, totalSupplyReads: ts.reads.map(r => r.var), writtenVars });
  const vars = ix.allVars(target);
  const stateVars = [...vars.values()].map(v => ({
    id: `${v.contract}.${v.name}`, name: v.name, contract: v.contract, type: v.type, kind: v.kind, key_types: v.keyTypes, value_type: v.valueType,
    visibility: v.visibility, constant: v.constant, immutable: v.immutable, initial: v.initial, line: v.line, file: rel(v.file),
    roles: roles.get(v.name) ?? [],
  }));

  // 4) analysis
  const ctx = { target, roles, model, vars };
  const nodes: NodeFacts[] = []; const entries: any[] = []; const sinks: any[] = []; const divs: any[] = []; const calls: any[] = [];
  for (const r of runs) {
    if (r.res.truncated) diag.truncated_entries.push(`${target}:${r.id} (cap ${cfg.maxPathsPerEntry}, discarded ${r.res.discarded})`);
    const a = analyzeEntry(r.id, r.fn, r.res, ctx, cfg);
    if (!a.json.summary.complete) diag.incomplete_entries.push(`${target}:${r.id}: ${a.json.summary.incomplete_reasons.join(', ')}`);
    entries.push(a.json); nodes.push(a.node); sinks.push(...a.sinks); divs.push(...a.divergences); calls.push(...a.calls);
  }
  // mutex evidence: which entrypoints actually CHECK the lock variable in a path constraint?
  for (const call of calls) {
    if (!call.mutex_guard) continue;
    call.mutex_checked_by = entries.filter(e => e.kind !== 'constructor' && (e.constraint_state_vars as string[]).includes(call.mutex_guard)).map(e => e.id);
  }

  const relevant = new Set<string>(['PAIR_BALANCE', 'PAIR_RESERVE', '$native_balance']);
  for (const [v, r] of roles) if (isAccounting(r)) relevant.add(v);
  const env = cfg.envModel && ammModels.includes('v2') ? envNodes(model) : [];
  const g = buildGraph([...nodes.filter(n => !n.id.endsWith('.constructor')), ...env], relevant, cfg);

  return {
    contract: target, file: rel(c.file), linearization: ix.lin(target),
    token_model: model,
    attacker_capabilities: ['flash_loan_any_amount', 'fresh_addresses', 'direct_token_donation_to_any_address', 'pair.sync/skim/swap', 'router_swaps', 'callbacks_from_own_contracts', 'same_tx_multi_call'],
    state_vars: stateVars,
    entrypoints: entries,
    env_model: {
      enabled: ammModels.includes('v2') && cfg.envModel && env.length > 0,
      assumptions: ['one UniswapV2-style pair per pair-role variable; pair identity is the variable value (not resolved on-chain)', 'ENV nodes are synthetic and permissionless', 'PAIR_BALANCE is written only by balance-map writes whose key aliases a pair var, or by writes to variables balanceOf() provably reads'],
      pair_vars: model.pair_vars,
      nodes: env.map(n => ({ id: n.id, reads: [...n.reads], writes: [...n.writes] })),
    },
    amm_models: ammModels.map(amm => amm === 'v2'
      ? { model: 'v2', status: 'implemented', result: { environment_nodes: env.map(n => n.id), entrypoint_graph: g.edges, sequences: g.sequences } }
      : { model: amm, status: 'unsupported', reason: `Uniswap ${amm.toUpperCase()} analysis model is not implemented; no ${amm.toUpperCase()} semantics were run.` }),
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

function buildSummary(targets: any[], diag: Diagnostics, reportOutcome: 'completes' | 'reverts' = 'completes') {
  const pad = (s: string, n: number) => (s.length >= n ? s.slice(0, n - 1) + ' ' : s.padEnd(n));
  return {
    run: {
      warnings: diag.warnings.length, unresolved: diag.unresolved_calls.length, unsupported: diag.unsupported_nodes.length, truncated: diag.truncated_entries.length,
      incomplete: diag.incomplete_entries.length, parse_errors: diag.parse_errors.length, failed_files: diag.failed_files.length,
    },
    targets: targets.map(t => {
      const eps = t.entrypoints.map((e: any) => ({
        id: e.id, access: e.access.class, access_uncertain: e.access.uncertain, mutability: e.mutability,
        paths: e.execution_paths.length,
        groups: reportOutcome === 'completes' ? e.summary.effect_groups : pathEffectGroupCount(e.execution_paths),
        divergence: reportOutcome === 'completes' ? t.divergence_sites.filter((x: any) => x.entry === e.id).length : null,
        sinks: reportOutcome === 'completes' ? t.sinks.filter((x: any) => x.entry === e.id).length : null,
        status: e.summary.complete ? 'ok' : 'INCOMPLETE', incomplete_reasons: e.summary.incomplete_reasons,
      }));
      const count = (arr: any[], k: (x: any) => string) => { const m: Record<string, number> = Object.create(null); for (const a of arr) m[k(a)] = (m[k(a)] ?? 0) + 1; return m; };
      const w = Math.max(10, ...eps.map((e: any) => e.id.length)) + 2;
      const lines = [pad('entrypoint', w) + pad('access', 16) + pad('paths', 8) + pad('groups', 8) + pad('diverg', 8) + pad('sinks', 7) + 'status',
        ...eps.map((e: any) => pad(e.id, w) + pad(e.access + (e.access_uncertain ? '?' : ''), 16) + pad(String(e.paths), 8) + pad(String(e.groups), 8) + pad(e.divergence === null ? '—' : String(e.divergence), 8) + pad(e.sinks === null ? '—' : String(e.sinks), 7) + e.status)];
      return {
        contract: t.contract, ledger_types: t.token_model.ledger_types,
        balance_vars: t.token_model.balance_vars, supply_vars: t.token_model.supply_vars, rate_drivers: t.token_model.rate_drivers, pair_vars: t.token_model.pair_vars,
        divergence_kinds: count(t.divergence_sites, (x: any) => x.kind), sink_kinds: count(t.sinks, (x: any) => x.kind), access_counts: count(eps, (x: any) => x.access),
        table_text: lines,                       // readable table first; machine-readable per-entrypoint rows last
        sequences: {
          generated: t.sequences.total_generated, kept: t.sequences.kept, max_depth: t.sequences.max_depth,
          top: t.sequences.items.slice(0, 10).map((s: any) => ({ id: s.id, score: s.score, steps: s.steps, incomplete: s.flags.involves_incomplete_entry, access_uncertain: s.flags.access_uncertain })),
        },
        report_outcome: reportOutcome, entrypoints: eps,
      };
    }),
  };
}

function pathEffectGroupCount(paths: any[]): number {
  const signatures = new Set(paths.map(p => JSON.stringify(p.trace.filter((e: any) => e.k === 'W' || e.k === 'C').map((e: any) => e.k === 'W'
    ? ['W', e.line, e.delta]
    : ['C', e.line, e.kind, e.target, e.fn, e.args, e.value]))));
  return signatures.size;
}

/** terminal output = process summary only; the tables live in the JSON (`summary` key, first in the file) */
function printRunSummary(doc: any, out: string) {
  const L = (s: string) => process.stderr.write(s + '\n');
  const dg = doc.diagnostics;
  L(`warnings=${dg.warnings.length} unresolved=${dg.unresolved_calls.length} unsupported=${dg.unsupported_nodes.length} truncated=${dg.truncated_entries.length} incomplete=${dg.incomplete_entries.length} parse_errors=${dg.parse_errors.length} failed_files=${dg.failed_files.length}`);
  const cap = 15;
  for (const w of dg.warnings.slice(0, cap)) L('  ! ' + w);
  if (dg.warnings.length > cap) L(`  ! … ${dg.warnings.length - cap} more warnings (see diagnostics.warnings)`);
  for (const w of dg.incomplete_entries.slice(0, cap)) L('  ~ ' + w);
  if (dg.incomplete_entries.length > cap) L(`  ~ … ${dg.incomplete_entries.length - cap} more incomplete entrypoints (see summary / diagnostics.incomplete_entries)`);
  for (const w of dg.parse_errors.slice(0, 5)) L('  x ' + w);
  for (const w of dg.failed_files.slice(0, 5)) L('  x ' + w);
  L(`wrote ${out} (${(fs.statSync(out).size / 1024).toFixed(0)} KB)`);
}

main().then(code => { process.exitCode = code; }).catch(err => { console.error(`error: ${err?.message ?? err}`); process.exitCode = 1; });
