// token-walker :: model.ts — role tagging of state variables (labels only; NEVER used to drop paths)
import { Index, VarInfo } from './parse';

export interface TokenModel {
  ledger_types: string[];
  balance_vars: string[]; supply_vars: string[]; rate_drivers: string[]; allowance_vars: string[];
  fee_vars: string[]; exclusion_vars: { var: string; subrole: string }[];
  pair_vars: string[]; router_vars: string[]; owner_vars: string[]; treasury_vars: string[];
  mutex_vars: string[]; toggle_vars: string[]; threshold_vars: string[];
  balance_of_inputs: { per_account_maps: string[]; global_inputs: string[] };
  evidence: Record<string, string[]>;
}

export interface BalanceOfFacts { reads: { var: string; key: string | null }[]; param: string | null; totalSupplyReads: string[]; writtenVars?: Set<string> }

const ADDR = /address/;
const isUint = (t: string) => /^u?int\d*$/.test(t.split(' ')[0]);

export function classify(ix: Index, target: string, bo: BalanceOfFacts): { roles: Map<string, string[]>; model: TokenModel } {
  const vars = ix.allVars(target);
  const roles = new Map<string, string[]>();
  const ev: Record<string, string[]> = {};
  const add = (v: string, r: string, why: string) => {
    const a = roles.get(v) ?? []; if (!a.includes(r)) a.push(r); roles.set(v, a);
    (ev[v] ??= []).push(`${r}: ${why}`);
  };
  const base = (s: string) => s.split('.')[0];

  // behavioral: what balanceOf()/totalSupply() read
  const perAcct = new Set<string>(); const globals = new Set<string>();
  for (const r of bo.reads) {
    const b = base(r.var); const vi = vars.get(b); if (!vi || b.startsWith('$')) continue;
    if (vi.kind === 'mapping' && bo.param && r.key === bo.param) {
      if (/bool/.test(vi.valueType)) add(b, 'reward_exclusion', 'read by balanceOf keyed by account');
      else { perAcct.add(b); add(b, 'balance', 'read by balanceOf keyed by account'); }
    } else if (vi.kind !== 'mapping') { globals.add(b); }
  }
  for (const g of globals) {
    if (bo.writtenVars && !bo.writtenVars.has(g)) { add(g, 'balance_of_readonly_input', 'read by balanceOf but never written outside the constructor'); globals.delete(g); }
    else add(g, 'rate_driver', 'global state read by balanceOf (shifts every holder implicitly when written)');
  }
  for (const s of bo.totalSupplyReads) if (vars.has(base(s))) add(base(s), 'supply', 'read by totalSupply()');

  for (const [name, v] of vars) {
    const n = name.toLowerCase(); const t = v.type;
    if (v.kind === 'mapping' && v.keyTypes.length === 2 && isUint(v.valueType)) add(name, 'allowance', 'mapping(address=>mapping(address=>uint))');
    else if (v.kind === 'mapping' && v.keyTypes.length === 1 && isUint(v.valueType) && /balance|owned|holder|^_?[rt]owned|shares|gons/.test(n)) add(name, 'balance', 'name+type');
    if (v.kind === 'scalar' && isUint(t) && /(^|_)(total ?supply|[rt]total|supply)$/.test(n)) add(name, 'supply', 'name');
    if (v.kind === 'scalar' && isUint(t) && /(rtotal|ttotal|reflection|gonsperfragment|scalingfactor|rebase|index$)/.test(n) && (!bo.writtenVars || bo.writtenVars.has(name))) add(name, 'rate_driver', 'name (and written outside constructor)');
    if (v.kind === 'scalar' && isUint(t) && /fee|tax|burnrate|divisor|bps|commission/.test(n) && !/feetotal|totalfee|previous/.test(n)) add(name, 'fee', 'name');
    if (/previous.*(fee|tax)/.test(n)) add(name, 'fee_backup', 'name');
    if (/feetotal|totalfees/.test(n)) add(name, 'fee_accumulator', 'name');
    if (v.kind === 'mapping' && /bool/.test(v.valueType) && v.keyTypes.length === 1) {
      if (/exclu(ded)?fromfee|feeexempt|isexempt|nofee|whitelist/.test(n)) add(name, 'fee_exempt', 'name');
      else if (/excludedfromreward|^_?isexcluded$|rewardexcl/.test(n)) add(name, 'reward_exclusion', 'name');
      else if (/blacklist|bot|banned|blocked/.test(n)) add(name, 'blacklist', 'name');
      else if (/exempt|limit|authori[sz]ed|minter|operator/.test(n)) add(name, 'privileged_set', 'name');
    }
    const addrLike = ADDR.test(t) || ix.isContractName(t) || /^I[A-Z]/.test(t);
    if (addrLike && v.kind === 'scalar') {
      if (/pair|(^|_)lp$|liquiditypool|amm/.test(n) || /createPair|getPair/.test(v.initial ?? '')) add(name, 'pair', 'name/initializer');
      if (/router|dex|swap/.test(n) && !/pair/.test(n)) add(name, 'router', 'name');
      if (/(^|_)(owner|admin|governor|governance|operator|minter|authority|manager|guardian)$/.test(n) || /previousowner/.test(n)) add(name, 'owner', 'name');
      if (/marketing|treasury|dev|team|feewallet|feereceiver|feeto|recipient|charity|rewardwallet/.test(n)) add(name, 'treasury', 'name');
      if (/dead|burn/.test(n)) add(name, 'burn_sink', 'name');
    }
    if (v.kind === 'scalar' && /bool/.test(t)) {
      if (/inswap|inswapandliquify|locked|entered|reentr|lockthe|processing|swapping/.test(n)) add(name, 'mutex', 'name');
      else if (/enabled|paused|trading|live|open|started|buyback|swapand/.test(n)) add(name, 'toggle', 'name');
    }
    if (v.kind === 'scalar' && isUint(t) && /max|min|limit|threshold|cooldown|numtokens|buyback|upper|lower/.test(n) && !roles.get(name)?.includes('fee')) add(name, 'threshold', 'name');
  }

  const pick = (r: string) => [...vars.keys()].filter(k => roles.get(k)?.includes(r));
  const lt: string[] = [];
  const has = (n: string) => vars.has(n);
  if ((has('_rOwned') && has('_tOwned')) || pick('rate_driver').some(x => /rtotal/i.test(x))) lt.push('reflection');
  if ([...vars.keys()].some(k => /gons|scalingfactor|rebase/i.test(k))) lt.push('rebasing');
  if (pick('fee').length && pick('pair').length) lt.push('tax_token_with_pair');
  else if (pick('fee').length) lt.push('fee_on_transfer');
  if ([...vars.keys()].some(k => /totalassets|convertto(shares|assets)/i.test(k)) || ix.lin(target).some(c => ix.contracts.get(c)!.fns.some(f => /^(convertToShares|totalAssets)$/.test(f.name)))) lt.push('vault_token');
  if (pick('pair').length || [...ix.contracts.get(target)!.vars.values()].some(v => /router|pair/i.test(v.name))) lt.push('liquidity_pair_integrated');
  if (!lt.length) lt.push('plain_erc20');

  const model: TokenModel = {
    ledger_types: lt,
    balance_vars: pick('balance'), supply_vars: pick('supply'), rate_drivers: pick('rate_driver'), allowance_vars: pick('allowance'),
    fee_vars: pick('fee'),
    exclusion_vars: [...vars.keys()].flatMap(k => (roles.get(k) ?? []).filter(r => ['fee_exempt', 'reward_exclusion', 'blacklist', 'privileged_set'].includes(r)).map(r => ({ var: k, subrole: r }))),
    pair_vars: pick('pair'), router_vars: pick('router'), owner_vars: pick('owner'), treasury_vars: pick('treasury'),
    mutex_vars: pick('mutex'), toggle_vars: pick('toggle'), threshold_vars: pick('threshold'),
    balance_of_inputs: { per_account_maps: [...perAcct], global_inputs: [...globals] },
    evidence: ev,
  };
  return { roles, model };
}

export const ACCOUNTING_ROLES = ['balance', 'supply', 'rate_driver', 'allowance', 'fee', 'reward_exclusion', 'fee_exempt', 'pair', 'threshold', 'mutex', 'fee_accumulator', 'owner'];
export function isAccounting(roles: string[] | undefined): boolean { return !!roles?.some(r => ACCOUNTING_ROLES.includes(r)); }
export type { VarInfo };
