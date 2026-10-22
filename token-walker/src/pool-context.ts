import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Index, FnInfo } from './parse';
import { AstTransactionAdapter } from './ast-transaction';
import { knownValue, SymbolicValue, symbolicValue } from './transaction';

export class PoolContextError extends Error {}

type AmmSelection = { models: ('v2' | 'v3' | 'v4')[]; source: string };
type Options = {
  pairRoot: string;
  tokenRoot: string;
  bindings: string[];
  scenarioText?: string;
  ammSelection: AmmSelection;
  maxPaths: number;
  absPaths: boolean;
};

const ENTRYPOINTS = ['skim', 'sync', 'swap'] as const;
type Slot = 'token0' | 'token1';

function sourceFiles(root: string): string[] {
  const errors: string[] = [];
  const files = Index.collectSol(root, errors);
  if (errors.length) throw new PoolContextError(`cannot read Solidity input: ${errors.slice(0, 3).join('; ')}`);
  if (!files.length) throw new PoolContextError(`no Solidity source files found at ${root}`);
  return files;
}

function parseScenario(text?: string): Record<string, Record<string, unknown>> {
  if (!text) return {};
  let value: unknown;
  try { value = JSON.parse(text); } catch (e: any) { throw new PoolContextError(`--scenario must be valid JSON: ${e.message}`); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PoolContextError('--scenario must be a JSON object keyed by entrypoint');
  const result = value as Record<string, Record<string, unknown>>;
  for (const [fn, args] of Object.entries(result)) {
    if (!(ENTRYPOINTS as readonly string[]).includes(fn)) throw new PoolContextError(`unsupported scenario entrypoint '${fn}' (use skim, sync, or swap)`);
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw new PoolContextError(`scenario for ${fn} must be an object`);
    const allowed = fn === 'skim' ? ['to'] : fn === 'sync' ? [] : ['amount0Out', 'amount1Out', 'to', 'data'];
    const extra = Object.keys(args).filter(k => !allowed.includes(k));
    if (extra.length) throw new PoolContextError(`unsupported ${fn} scenario field(s): ${extra.join(', ')}`);
    if (fn === 'swap') {
      for (const k of ['amount0Out', 'amount1Out']) {
        const n = args[k];
        if (n !== undefined && (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0)) {
          throw new PoolContextError(`scenario ${fn}.${k} must be a non-negative safe integer; omit it for a symbolic input`);
        }
      }
      if (args.data !== undefined && (typeof args.data !== 'string' || !/^(?:0x)?(?:[0-9a-fA-F]{2})*$/.test(args.data))) {
        throw new PoolContextError('scenario swap.data must be even-length hex bytes such as 0x or 0x1234');
      }
    }
  }
  return result;
}

function slotBindings(values: string[], tokenContracts: Set<string>): Map<Slot, string> {
  const out = new Map<Slot, string>();
  for (const value of values) {
    const match = /^(token0|token1)=([A-Za-z_$][\w$]*)$/.exec(value);
    if (!match) throw new PoolContextError(`invalid --bind-token '${value}' (expected token0=ContractName or token1=ContractName)`);
    const slot = match[1] as Slot, contract = match[2];
    if (out.has(slot)) throw new PoolContextError(`duplicate --bind-token for ${slot}`);
    if (!tokenContracts.has(contract)) throw new PoolContextError(`bound token contract '${contract}' was not found in the supplied Token source`);
    out.set(slot, contract);
  }
  return out;
}

function identifyPair(ix: Index, pairFiles: Set<string>): string {
  const candidates = [...ix.contracts.values()].filter(c => pairFiles.has(c.file) && c.kind === 'contract' &&
    ENTRYPOINTS.every(name => ix.findFns(c.name, name, name === 'sync' ? 0 : name === 'skim' ? 1 : 4).length === 1));
  if (candidates.length !== 1) {
    const names = candidates.map(c => c.name);
    throw new PoolContextError(candidates.length
      ? `multiple V2 Pair contracts found (${names.join(', ')}); supply one Pair.sol file`
      : 'Pair input must contain exactly one source contract implementing swap, skim, and sync');
  }
  return candidates[0].name;
}

function makeArgs(fn: FnInfo, supplied: Record<string, unknown> | undefined): SymbolicValue[] {
  return fn.params.map(param => {
    const name = param.name;
    if (supplied && Object.prototype.hasOwnProperty.call(supplied, name)) {
      const value = supplied[name];
      return knownValue(value, `${name}=${JSON.stringify(value)}`, 'user_assumption');
    }
    return symbolicValue(`input.${fn.name}.${name}`, 'user_assumption');
  });
}

function sha256(file: string) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }

export function buildPoolContextReport(options: Options): any {
  const pairFilesArray = sourceFiles(options.pairRoot);
  const tokenFilesArray = sourceFiles(options.tokenRoot);
  const allFiles = [...new Set([...pairFilesArray, ...tokenFilesArray])].sort();
  const pairFiles = new Set(pairFilesArray), tokenFiles = new Set(tokenFilesArray);
  const ix = new Index();
  for (const file of allFiles) ix.addFile(file);
  if (ix.failedFiles.length) throw new PoolContextError(`failed to parse source file(s): ${ix.failedFiles.join(', ')}`);

  const pairContract = identifyPair(ix, pairFiles);
  const tokenContracts = new Set([...ix.contracts.values()]
    .filter(c => tokenFiles.has(c.file) && c.kind === 'contract' && ix.findFns(c.name, 'transfer', 2).length === 1 && ix.findFns(c.name, 'balanceOf', 1).length === 1)
    .map(c => c.name));
  if (!tokenContracts.size) throw new PoolContextError('Token input must contain a uniquely resolved contract with transfer(address,uint) and balanceOf(address)');
  const bindings = slotBindings(options.bindings, tokenContracts);
  const scenario = parseScenario(options.scenarioText);

  const instances: any[] = [{ id: 'pair', contract: pairContract, source: ix.contracts.get(pairContract)!.file }];
  const receivers: Record<string, string> = {};
  for (const [slot, contract] of bindings) {
    const id = slot;
    instances.push({ id, contract, source: ix.contracts.get(contract)!.file, binding: { kind: 'user_supplied_source_analysis', detail: `${slot}=${contract}; source binding only, not deployed address evidence` } });
    receivers[`pair.${slot}`] = id;
  }
  const adapter = new AstTransactionAdapter(ix, instances, { receivers });
  const pathLimit = Math.max(1, options.maxPaths);
  const entrypoints: any[] = [];
  for (const name of ENTRYPOINTS) {
    const argc = name === 'sync' ? 0 : name === 'skim' ? 1 : 4;
    const candidates = ix.findFns(pairContract, name, argc);
    if (candidates.length !== 1) throw new PoolContextError(`${pairContract}.${name} is not uniquely resolvable`);
    const fn = candidates[0];
    const args = makeArgs(fn, scenario[name]);
    const runs = adapter.runRoot('pair', name, args, symbolicValue('transaction.msg.sender', 'user_assumption'));
    let sampled: any[];
    if (runs.length <= pathLimit) sampled = runs;
    else {
      // Stride across the full result set and reserve a slot for each observed
      // outcome class so a small report cap cannot hide the unresolved callback arm.
      const chosen = new Set<number>();
      for (const status of ['returned', 'reverted', 'unresolved']) {
        const index = runs.findIndex((r: any) => r.status === status);
        if (index >= 0 && chosen.size < pathLimit) chosen.add(index);
      }
      for (let i = 0; chosen.size < pathLimit && i < pathLimit * 4; i++) chosen.add(Math.floor(i * runs.length / (pathLimit * 4)));
      for (let i = 0; chosen.size < pathLimit && i < runs.length; i++) chosen.add(i);
      sampled = [...chosen].sort((a, b) => a - b).slice(0, pathLimit).map(i => runs[i]);
    }
    const paths = sampled.map((run: any, i: number) => {
      const p = run.path;
      const unresolved = run.status === 'unresolved' || p.flags.length > 0 || p.trace.some((e: any) => e.kind === 'call_unresolved');
      const resolvedStatus = run.status === 'reverted' ? 'revert_candidate' : run.status === 'unresolved' ? 'unresolved_path' : 'normal_return_candidate';
      return {
        id: `${pairContract}.${name}#${i + 1}`,
        status: unresolved ? 'unresolved_path' : run.status === 'reverted' ? 'revert_candidate' : 'resolved_source_interpreted',
        modeled_outcome: resolvedStatus,
        reachability: p.classification.reachability,
        execution_evidence: p.classification.execution_evidence,
        constraints: [...p.constraints],
        assumptions: args.map(a => ({ expression: a.expression, provenance: a.provenance })),
        unresolved_operations: [...new Set([...p.flags, ...p.trace.filter((e: any) => e.kind === 'call_unresolved').map((e: any) => String(e.detail.reason ?? 'unresolved operation'))])],
        storage_reads: p.trace.filter((e: any) => e.kind === 'read').map((e: any) => e.step),
        storage_writes: p.writes,
        events: p.trace.filter((e: any) => e.kind === 'event').map((e: any) => e.step),
        branch_outcomes: p.trace.filter((e: any) => e.kind === 'branch').map((e: any) => e.step),
        call_trace: p.trace,
        return_value: run.returnValue ?? null,
      };
    });
    const isUnresolved = (run: any) => run.status === 'unresolved' || run.path.flags.length > 0 || run.path.trace.some((e: any) => e.kind === 'call_unresolved');
    const unresolved = runs.filter(isUnresolved).length;
    const reverts = runs.filter((r: any) => r.status === 'reverted' && !isUnresolved(r)).length;
    const normal = runs.filter((r: any) => r.status === 'returned' && !isUnresolved(r)).length;
    const conditional = runs.filter((r: any) => r.path.classification.reachability !== 'established_under_assumptions').length;
    const omitted = runs.length - sampled.length;
    entrypoints.push({
      id: `${pairContract}.${name}`, source: fn.file, line: fn.line,
      analysis_status: unresolved || omitted ? 'partial' : 'modeled_paths_resolved',
      full_analysis: false,
      path_count: paths.length, generated_path_count: runs.length, omitted_by_report_cap: omitted,
      summary: { resolved_paths: runs.length - unresolved, conditional_paths: conditional, unresolved_paths: unresolved, revert_candidates: reverts, normal_return_candidates: normal, summary_scope: 'all_generated_paths' },
      paths,
    });
  }
  const summary = entrypoints.reduce((s: any, e: any) => {
    s.resolved_paths += e.summary.resolved_paths; s.conditional_paths += e.summary.conditional_paths;
    s.unresolved_paths += e.summary.unresolved_paths; s.revert_candidates += e.summary.revert_candidates;
    s.normal_return_candidates += e.summary.normal_return_candidates; s.omitted_paths += e.omitted_by_report_cap;
    return s;
  }, { resolved_paths: 0, conditional_paths: 0, unresolved_paths: 0, revert_candidates: 0, normal_return_candidates: 0, omitted_paths: 0 });
  const parserVersion = require('@solidity-parser/parser/package.json').version;
  return {
    schema_version: 'pool-context-v1',
    report_kind: 'static_source_interpretation',
    summary,
    tool: { name: 'token-walker', version: '0.5.0', parser: `@solidity-parser/parser@${parserVersion}`, node: process.version },
    amm_selection: options.ammSelection,
    pool_context: {
      protocol_model: 'v2', pair_contract: pairContract,
      pair_source: options.absPaths ? ix.contracts.get(pairContract)!.file : path.basename(ix.contracts.get(pairContract)!.file),
      token_source: options.absPaths ? options.tokenRoot : path.basename(options.tokenRoot),
      bindings: [...bindings].map(([slot, contract]) => ({ slot, contract, kind: 'user_supplied_source_analysis_binding', proves_deployed_address: false })),
      unbound_slots: (['token0', 'token1'] as Slot[]).filter(slot => !bindings.has(slot)),
      initial_storage: 'symbolic_unknown_unless_established_by_this modeled trace; no on-chain state is loaded',
      execution_claim: 'Static AST interpretation only. Normal return and revert are modeled candidates, not concrete EVM outcomes.',
    },
    scenario: {
      supplied: scenario,
      unspecified_parameters: 'symbolic user-assumption inputs; paths that require unsupported symbolic behavior remain unresolved',
      supported_entrypoints: [...ENTRYPOINTS],
    },
    sources: allFiles.map(file => ({ path: options.absPaths ? file : path.basename(file), sha256: sha256(file) })),
    limitations: [
      'Solidity 0.5 timestamp wraparound, all narrow casts, and full compiler arithmetic semantics are not modeled.',
      'Only source-resolvable calls with explicit token-slot bindings are followed; missing dependencies and callbacks remain unresolved.',
      'ABI support is narrow to the low-level ERC20 transfer patterns and bool return data exercised by these V2 sources.',
      'The report path cap limits serialization after interpretation; it does not bound AST path-generation memory.',
    ],
    entrypoints,
  };
}
