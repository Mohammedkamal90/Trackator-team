// ============================================================
// TRACKATOR Tier 2 - X-Ray Ingestor
// Parses and ingests X-Ray threat model analysis output
// ============================================================

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import {
  XRayOutput,
  ProtocolType,
  ThreatModel,
  Invariant,
  TrustAssumption,
  AdversaryProfile,
  AttackVector,
  AssetInfo,
  EntryPoint,
  PrivilegeBoundary,
  ActorRole,
  SolidityContract,
  FunctionDef
} from '../types';

export interface XRayIngestOptions {
  xrayFile?: string;
  protocolType?: ProtocolType;
  contracts?: SolidityContract[];
  verbose?: boolean;
}

/**
 * Main entry point for X-Ray ingestion
 */
export function ingestXRay(options: XRayIngestOptions): XRayOutput {
  const {
    xrayFile,
    protocolType: overrideProtocolType,
    contracts = [],
    verbose = false
  } = options;
  
  // Try to load from file if provided
  let rawData: any = null;
  
  if (xrayFile && fs.existsSync(xrayFile)) {
    if (verbose) console.log(`Loading X-Ray data from ${xrayFile}`);
    rawData = loadXRayFile(xrayFile);
  }
  
  // If no file, generate from contracts using built-in templates
  if (!rawData && contracts.length > 0) {
    if (verbose) console.log('Generating X-Ray analysis from contract templates');
    rawData = generateXRayFromContracts(contracts, overrideProtocolType);
  }
  
  // If still no data, return empty/default X-Ray output
  if (!rawData) {
    return createEmptyXRayOutput();
  }
  
  // Parse and structure the raw data
  return parseXRayData(rawData, overrideProtocolType, contracts);
}

/**
 * Load X-Ray data from file (JSON or YAML)
 */
function loadXRayFile(filePath: string): any {
  const content = fs.readFileSync(filePath, 'utf-8');
  const ext = path.extname(filePath).toLowerCase();
  
  try {
    if (ext === '.yaml' || ext === '.yml') {
      return yaml.load(content);
    } else {
      return JSON.parse(content);
    }
  } catch (error: any) {
    throw new Error(`Failed to parse X-Ray file: ${error.message}`);
  }
}

/**
 * Generate X-Ray analysis from contracts using templates
 * This is used when no external X-Ray analysis is available
 */
function generateXRayFromContracts(
  contracts: SolidityContract[],
  overrideProtocolType?: ProtocolType
): any {
  const detectedProtocol = overrideProtocolType || detectProtocolType(contracts);
  
  // Build basic threat model from contract analysis
  const assets = extractAssets(contracts);
  const entryPoints = extractEntryPoints(contracts);
  const invariants = generateTemplateInvariants(detectedProtocol, contracts);
  const threats = getThreatsForProtocol(detectedProtocol);
  const adversaries = getAdversariesForProtocol(detectedProtocol);
  
  return {
    protocolType: detectedProtocol,
    threatModel: { assetsAtRisk: assets, entryPoints, privilegeBoundaries: [], keyActors: [] },
    invariants,
    trustAssumptions: getTrustAssumptionsForProtocol(detectedProtocol),
    adversaryProfiles: adversaries,
    attackVectors: threats,
    generatedAt: new Date().toISOString()
  };
}

/**
 * Detect protocol type from contract patterns
 */
function detectProtocolType(contracts: SolidityContract[]): ProtocolType {
  const allFunctions = contracts.flatMap(c => c.functions.map(f => ({ ...f, contract: c.name })));
  const functionNames = allFunctions.map(f => f.name.toLowerCase());
  const stateVarTypes = contracts.flatMap(c => c.stateVariables.map(v => v.type.toLowerCase()));
  
  // Lending patterns
  if (functionNames.some(n => ['borrow', 'repay', 'liquidate', 'deposit', 'collateral'].some(p => n.includes(p)))) {
    return 'lending';
  }
  
  // DEX patterns
  if (functionNames.some(n => ['swap', 'addliquidity', 'removeliquidity', 'flashswap'].some(p => n.includes(p)))) {
    return 'dex';
  }
  
  // Bridge patterns
  if (functionNames.some(n => ['bridge', 'lock', 'release', 'relay', 'crosschain'].some(p => n.includes(p)))) {
    return 'bridge';
  }
  
  // Vault/Yield patterns
  if (functionNames.some(n => ['deposit', 'withdraw', 'harvest', 'compound', 'yield'].some(p => n.includes(p)))) {
    return stateVarTypes.includes('ierc4626') ? 'vault' : 'yield';
  }
  
  // NFT patterns
  if (stateVarTypes.some(t => t.includes('erc721') || t.includes('erc1155'))) {
    return 'nft';
  }
  
  // Governance/DAO patterns
  if (functionNames.some(n => ['vote', 'propose', 'execute', 'governance', 'timelock'].some(p => n.includes(p)))) {
    return 'dao';
  }
  
  // LSD patterns
  if (functionNames.some(n => ['stake', 'unstake', 'claimrewards', 'restake'].some(p => n.includes(p)))) {
    return 'lsd';
  }
  
  // Perp DEX patterns
  if (functionNames.some(n => ['position', 'leverage', 'margin', 'perpetual', 'funding'].some(p => n.includes(p)))) {
    return 'perp-dex';
  }
  
  return 'unknown';
}

/**
 * Extract asset information from contracts
 */
function extractAssets(contracts: SolidityContract[]): AssetInfo[] {
  const assets: AssetInfo[] = [];
  
  for (const contract of contracts) {
    for (const sv of contract.stateVariables) {
      // Detect common asset types
      if (sv.type.toLowerCase().includes('ierc20') || 
          sv.type.toLowerCase().includes('address') && 
          (sv.name.toLowerCase().includes('token') || sv.name.toLowerCase().includes('asset'))) {
        assets.push({
          type: 'erc20',
          name: sv.name,
          location: `${contract.name}.${sv.name}`
        });
      }
      
      if (sv.type.toLowerCase().includes('uint256') && 
          (sv.name.toLowerCase().includes('balance') || sv.name.toLowerCase().includes('total'))) {
        assets.push({
          type: 'erc20',
          name: sv.name,
          location: `${contract.name}.${sv.name}`,
          liquiditySource: 'state variable'
        });
      }
    }
    
    // Check for ETH handling
    const hasPayable = contract.functions.some(f => f.stateMutability === 'payable');
    if (hasPayable) {
      assets.push({
        type: 'eth',
        name: 'ETH',
        location: contract.name,
        liquiditySource: 'payable functions'
      });
    }
  }
  
  return assets;
}

/**
 * Extract entry points from contracts
 */
function extractEntryPoints(contracts: SolidityContract[]): EntryPoint[] {
  const entryPoints: EntryPoint[] = [];
  
  for (const contract of contracts) {
    for (const func of contract.functions) {
      if ((func.visibility === 'external' || func.visibility === 'public') &&
          func.stateMutability !== 'view' &&
          func.stateMutability !== 'pure' &&
          !['constructor', 'fallback', 'receive'].includes(func.kind)) {
        
        // Determine access level
        let access: EntryPoint['access'] = 'anyone';
        let criticality: EntryPoint['criticality'] = 'low';
        
        // Check modifiers for access control
        if (func.modifiers.some(m => m.toLowerCase().includes('onlyowner'))) {
          access = 'owner-only';
        } else if (func.modifiers.some(m => m.toLowerCase().includes('role'))) {
          access = 'role-based';
        }
        
        // Determine criticality based on function characteristics
        if (func.body.hasExternalCall || func.body.hasTransfer) {
          criticality = func.body.ceiPattern === 'violated' ? 'critical' : 'high';
        } else if (func.stateVariablesWritten.length > 0) {
          criticality = 'medium';
        }
        
        // Check for high-risk patterns
        const nameLower = func.name.toLowerCase();
        if (['transfer', 'mint', 'burn', 'approve', 'execute', 'flash', 'swap'].some(p => nameLower.includes(p))) {
          criticality = criticality === 'low' ? 'medium' : criticality;
        }
        
        entryPoints.push({
          name: func.name,
          contract: contract.name,
          access,
          criticality,
          description: `External function: ${func.name}(${func.parameters.map(p => p.type).join(', ')})`
        });
      }
    }
  }
  
  return entryPoints;
}

/**
 * Parse raw X-Ray data into structured format
 */
function parseXRayData(
  rawData: any,
  overrideProtocolType?: ProtocolType,
  contracts: SolidityContract[] = []
): XRayOutput {
  const protocolType = overrideProtocolType || rawData.protocolType || detectProtocolType(contracts);
  
  // Parse threat model
  const threatModel: ThreatModel = parseThreatModel(rawData.threatModel || {}, contracts);
  
  // Parse invariants
  const invariants: Invariant[] = parseInvariants(rawData.invariants || [], protocolType, contracts);
  
  // Parse trust assumptions
  const trustAssumptions: TrustAssumption[] = parseTrustAssumptions(
    rawData.trustAssumptions || [],
    protocolType
  );
  
  // Parse adversary profiles
  const adversaryProfiles: AdversaryProfile[] = parseAdversaryProfiles(
    rawData.adversaryProfiles || rawData.adversaries || [],
    protocolType
  );
  
  // Parse attack vectors
  const attackVectors: AttackVector[] = parseAttackVectors(
    rawData.attackVectors || rawData.threats || [],
    protocolType
  );
  
  return {
    protocolType,
    threatModel,
    invariants,
    trustAssumptions,
    adversaryProfiles,
    attackVectors,
    generatedAt: rawData.generatedAt || new Date().toISOString()
  };
}

function parseThreatModel(raw: any, contracts: SolidityContract[]): ThreatModel {
  return {
    assetsAtRisk: parseAssets(raw.assetsAtRisk || []),
    entryPoints: parseEntryPoints(raw.entryPoints || []),
    privilegeBoundaries: parsePrivilegeBoundaries(raw.privilegeBoundaries || []),
    keyActors: parseKeyActors(raw.keyActors || [])
  };
}

function parseAssets(raw: any[]): AssetInfo[] {
  return raw.map((a: any) => ({
    type: a.type || 'unknown',
    name: a.name || 'Unknown Asset',
    location: a.location || '',
    estimatedValue: a.estimatedValue,
    liquiditySource: a.liquiditySource
  }));
}

function parseEntryPoints(raw: any[]): EntryPoint[] {
  return raw.map((e: any) => ({
    name: e.name || '',
    contract: e.contract || '',
    access: e.access || 'anyone',
    criticality: e.criticality || 'medium',
    description: e.description || ''
  }));
}

function parsePrivilegeBoundaries(raw: any[]): PrivilegeBoundary[] {
  return raw.map((b: any) => ({
    from: b.from || '',
    to: b.to || '',
    mechanism: b.mechanism || 'none',
    strength: b.strength || 'weak'
  }));
}

function parseKeyActors(raw: any[]): ActorRole[] {
  return raw.map((a: any) => ({
    role: a.role || '',
    capabilities: a.capabilities || [],
    constraints: a.constraints || []
  }));
}

function parseInvariants(raw: any[], protocolType: ProtocolType, contracts: SolidityContract[]): Invariant[] {
  // If we have raw invariants, parse them
  if (raw.length > 0) {
    return raw.map((inv: any, index: number) => ({
      id: inv.id || `INV_${index + 1}`,
      category: inv.category || 'accounting',
      protocolType: inv.protocolType || protocolType,
      template: inv.template || '',
      instance: inv.instance || inv.template || '',
      severity: inv.severity || 'high',
      checkable: inv.checkable ?? true,
      expression: inv.expression,
      relatedStateVars: inv.relatedStateVars || [],
      relatedFunctions: inv.relatedFunctions || []
    }));
  }
  
  // Otherwise generate template invariants
  return generateTemplateInvariants(protocolType, contracts);
}

function parseTrustAssumptions(raw: any[], protocolType: ProtocolType): TrustAssumption[] {
  const parsed = raw.map((ta: any, index: number) => ({
    id: ta.id || `TA_${index + 1}`,
    category: ta.category || 'oracle',
    assumption: ta.assumption || '',
    ifViolated: ta.ifViolated || 'Undefined impact',
    mitigation: ta.mitigation,
    confidence: ta.confidence || 'medium'
  }));
  
  // Add default trust assumptions for protocol type if none provided
  if (parsed.length === 0) {
    parsed.push(...getTrustAssumptionsForProtocol(protocolType) as any[]);
  }
  
  return parsed;
}

function parseAdversaryProfiles(raw: any[], protocolType: ProtocolType): AdversaryProfile[] {
  if (raw.length > 0) {
    return raw.map((ap: any, index: number) => ({
      id: ap.id || `ADV_${index + 1}`,
      type: ap.type || 'external',
      capabilities: ap.capabilities || [],
      goals: ap.goals || [],
      constraints: ap.constraints || [],
      likelyAttacks: ap.likelyAttacks || []
    }));
  }
  
  return getAdversariesForProtocol(protocolType);
}

function parseAttackVectors(raw: any[], protocolType: ProtocolType): AttackVector[] {
  if (raw.length > 0) {
    return raw.map((av: any, index: number) => ({
      id: av.id || `AV_${index + 1}`,
      name: av.name || av.attack || 'Unnamed Attack',
      category: av.category || '',
      prerequisite: av.prerequisite || av.prerequisites || [],
      impact: av.impact || av.description || '',
      likelihood: av.likelihood || 'possible',
      severity: av.severity || 'high',
      relatedInvariants: av.relatedInvariants || [],
      detectionMethod: av.detectionMethod
    }));
  }
  
  return getThreatsForProtocol(protocolType);
}

// ============================================================
// PROTOCOL-SPECIFIC TEMPLATES
// ============================================================

function generateTemplateInvariants(
  protocolType: ProtocolType,
  contracts: SolidityContract[]
): Invariant[] {
  const invariants: Invariant[] = [];
  let counter = 1;
  
  // Common invariants across all protocols
  invariants.push({
    id: `INV_${counter++}`,
    category: 'accounting',
    protocolType,
    template: 'Total supply accounting must balance',
    instance: 'sum(user_balances) == total_supply',
    severity: 'critical',
    checkable: true,
    expression: 'Σ balances == totalSupply',
    relatedStateVars: ['totalSupply', 'balances'],
    relatedFunctions: ['mint', 'burn', 'transfer']
  });
  
  invariants.push({
    id: `INV_${counter++}`,
    category: 'bounds',
    protocolType,
    template: 'No underflow or overflow in arithmetic operations',
    instance: 'All arithmetic must use SafeMath or Solidity 0.8+',
    severity: 'critical',
    checkable: true,
    expression: 'result >= 0 && result <= MAX_UINT256',
    relatedStateVars: [],
    relatedFunctions: []
  });
  
  // Protocol-specific invariants
  switch (protocolType) {
    case 'lending':
      invariants.push(...getLendingInvariants(counter));
      break;
    case 'dex':
      invariants.push(...getDexInvariants(counter));
      break;
    case 'vault':
      invariants.push(...getVaultInvariants(counter));
      break;
    case 'bridge':
      invariants.push(...getBridgeInvariants(counter));
      break;
    case 'perp-dex':
      invariants.push(...getPerpDexInvariants(counter));
      break;
    case 'lsd':
      invariants.push(...getLSDInvariants(counter));
      break;
  }
  
  return invariants;
}

function getLendingInvariants(startId: number): Invariant[] {
  const inv: Invariant[] = [];
  let id = startId;
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'lending',
    template: 'Collateral value must always cover borrowed amount',
    instance: 'collateral_value >= borrow_amount * collateral_factor',
    severity: 'critical',
    checkable: true,
    expression: 'collateral[token] * price[token] >= borrow[token] * liquidationThreshold',
    relatedStateVars: ['collateral', 'borrows'],
    relatedFunctions: ['borrow', 'depositCollateral', 'liquidate']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'oracle',
    protocolType: 'lending',
    template: 'Oracle prices must be within acceptable bounds',
    instance: 'price deviation < threshold (e.g., 5% from TWAP)',
    severity: 'critical',
    checkable: true,
    expression: '|spotPrice - twapPrice| / twapPrice < maxDeviation',
    relatedStateVars: ['oraclePrices'],
    relatedFunctions: ['getPrice', 'liquidate']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'bounds',
    protocolType: 'lending',
    template: 'Interest rates must remain within configured bounds',
    instance: '0 <= interest_rate <= max_interest_rate',
    severity: 'high',
    checkable: true,
    expression: 'ratePerBlock >= 0 && ratePerBlock <= maxRate',
    relatedStateVars: ['interestRate'],
    relatedFunctions: ['accrueInterest']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'lending',
    template: 'Exchange rate between underlying and cToken must be accurate',
    instance: 'exchangeRate = totalUnderlying / totalSupply',
    severity: 'critical',
    checkable: true,
    expression: 'exchangeRate == cash + borrows - reserves / totalSupply',
    relatedStateVars: ['totalBorrows', 'totalSupply', 'cash', 'reserves'],
    relatedFunctions: ['exchangeRateCurrent', 'redeem', 'mint']
  });
  
  return inv;
}

function getDexInvariants(startId: number): Invariant[] {
  const inv: Invariant[] = [];
  let id = startId;
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'dex',
    template: 'Constant product invariant (k = x * y)',
    instance: 'reserve_x * reserve_y >= k (before fees)',
    severity: 'critical',
    checkable: true,
    expression: 'reserve0 * reserve1 >= k',
    relatedStateVars: ['reserve0', 'reserve1', 'k'],
    relatedFunctions: ['swap', 'addLiquidity', 'removeLiquidity']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'dex',
    template: 'LP token supply matches actual liquidity',
    instance: 'lp_total_supply proportional to total_liquidity',
    severity: 'high',
    checkable: true,
    expression: 'lpBalance[user] / lpTotalSupply == userShare',
    relatedStateVars: ['lpTotalSupply', 'balances'],
    relatedFunctions: ['mint', 'burn', 'swap']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'bounds',
    protocolType: 'dex',
    template: 'Slippage protection must prevent excessive price impact',
    instance: 'output_amount >= min_output (amountOutMin)',
    severity: 'high',
    checkable: true,
    expression: 'amountOut >= amountOutMin',
    relatedStateVars: [],
    relatedFunctions: ['swap']
  });
  
  return inv;
}

function getVaultInvariants(startId: number): Invariant[] {
  const inv: Invariant[] = [];
  let id = startId;
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'vault',
    template: 'Share inflation protection (ERC4626)',
    instance: 'shares minted <= deposit amount converted at current rate',
    severity: 'critical',
    checkable: true,
    expression: 'shares <= assets * totalSupply / totalAssets (rounded down)',
    relatedStateVars: ['totalAssets', 'totalSupply'],
    relatedFunctions: ['deposit', 'mint', 'withdraw', 'redeem']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'vault',
    template: 'Asset backing per share must be non-decreasing during deposits',
    instance: 'convertToShares(assets) after deposit >= convertToShares(assets) before',
    severity: 'high',
    checkable: true,
    expression: 'newConvertToShares >= oldConvertToShares',
    relatedStateVars: ['totalAssets', 'totalSupply'],
    relatedFunctions: ['deposit', 'mint']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'bounds',
    protocolType: 'vault',
    template: 'Round-trip (deposit-withdraw) must not lose more than fees',
    instance: 'withdraw(deposit(amount)) >= amount - (fees)',
    severity: 'medium',
    checkable: true,
    expression: 'finalAmount >= initialAmount - expectedFees',
    relatedStateVars: [],
    relatedFunctions: ['deposit', 'withdraw']
  });
  
  return inv;
}

function getBridgeInvariants(startId: number): Invariant[] {
  const inv: Invariant[] = [];
  let id = startId;
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'bridge',
    template: 'Locked tokens on source chain must equal minted/bridged on destination',
    instance: 'locked_amount_source == bridged_amount_destination',
    severity: 'critical',
    checkable: true,
    expression: 'sourceLocks == destinationMints',
    relatedStateVars: ['lockedTokens', 'bridgedTokens'],
    relatedFunctions: ['lock', 'release', 'mint', 'burn']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'ordering',
    protocolType: 'bridge',
    template: 'Messages must be processed in order (no replay)',
    instance: 'nonce strictly increasing',
    severity: 'critical',
    checkable: true,
    expression: 'processedNonce > lastProcessedNonce',
    relatedStateVars: ['nonce', 'lastProcessedNonce'],
    relatedFunctions: ['relay', 'verifyAndExecute']
  });
  
  return inv;
}

function getPerpDexInvariants(startId: number): Invariant[] {
  const inv: Invariant[] = [];
  let id = startId;
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'perp-dex',
    template: 'Global accountings must balance (zero-sum game)',
    instance: 'sum(all_positions_value + insurance_fund) == 0',
    severity: 'critical',
    checkable: true,
    expression: 'Σ(positions) + insuranceFund == 0',
    relatedStateVars: ['positions', 'insuranceFund'],
    relatedFunctions: ['openPosition', 'closePosition', 'liquidate']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'oracle',
    protocolType: 'perp-dex',
    template: 'Funding rate must not cause oracle manipulation incentive',
    instance: 'funding payment < cost_of_manipulation',
    severity: 'high',
    checkable: true,
    expression: 'fundingPayment < manipulationCost',
    relatedStateVars: ['fundingRate', 'markPrice', 'indexPrice'],
    relatedFunctions: ['settleFunding', 'trade']
  });
  
  return inv;
}

function getLSDInvariants(startId: number): Invariant[] {
  const inv: Invariant[] = [];
  let id = startId;
  
  inv.push({
    id: `INV_${id++}`,
    category: 'accounting',
    protocolType: 'lsd',
    template: 'Staked ETH must equal derivative token supply (1:1 or ratio-based)',
    instance: 'totalStakedEth == stakedTokenSupply * exchangeRate',
    severity: 'critical',
    checkable: true,
    expression: 'stakedETH == stTokenSupply * rate',
    relatedStateVars: ['totalStaked', 'totalSupply'],
    relatedFunctions: ['stake', 'unstake']
  });
  
  inv.push({
    id: `INV_${id++}`,
    category: 'bounds',
    protocolType: 'lsd',
    template: 'Rewards distribution must match accumulated rewards',
    instance: 'distributed_rewards <= accumulated_rewards',
    severity: 'high',
    checkable: true,
    expression: 'sum(distributions) <= totalAccumulated',
    relatedStateVars: ['rewards', 'distributedRewards'],
    relatedFunctions: ['claimRewards', 'distribute']
  });
  
  return inv;
}

function getTrustAssumptionsForProtocol(protocolType: ProtocolType): TrustAssumption[] {
  const assumptions: TrustAssumption[] = [
    {
      id: 'TA_1',
      category: 'oracle',
      assumption: 'Oracle prices reflect true market values',
      ifViolated: 'Incorrect liquidations, manipulated swaps, unfair exchanges',
      mitigation: 'Use TWAP, multiple oracles, circuit breakers',
      confidence: 'medium'
    },
    {
      id: 'TA_2',
      category: 'external-contract',
      assumption: 'Integrated external contracts behave as specified',
      ifViolated: 'Loss of funds through unexpected behavior',
      mitigation: 'Upgradeability, pausability, regular audits',
      confidence: 'medium'
    },
    {
      id: 'TA_3',
      category: 'governance',
      assumption: 'Governance processes are not captured by malicious actors',
      ifViolated: 'Unauthorized parameter changes, fund drains',
      mitigation: 'Timelocks, multisig, proposal review',
      confidence: 'medium'
    }
  ];
  
  // Add protocol-specific assumptions
  switch (protocolType) {
    case 'lending':
      assumptions.push({
        id: 'TA_L1',
        category: 'price-feed',
        assumption: 'Price feeds cannot be manipulated within a single transaction/block',
        ifViolated: 'Cheap collateral borrowed against, bad debt accumulation',
        mitigation: 'TWAP oracles, flash loan detection',
        confidence: 'low'
      });
      break;
    case 'dex':
      assumptions.push({
        id: 'TA_D1',
        category: 'math',
        assumption: 'Arithmetic operations do not overflow/underflow',
        ifViolated: 'Incorrect swap amounts, LP manipulation',
        mitigation: 'Solidity 0.8+, SafeMath',
        confidence: 'high'
      });
      break;
    case 'bridge':
      assumptions.push({
        id: 'TA_B1',
        category: 'external-contract',
        assumption: 'Validators/relayers act honestly and are not compromised',
        ifViolated: 'False minting, double-spend attacks',
        mitigation: 'Multi-validator consensus, fraud proofs',
        confidence: 'low'
      });
      break;
  }
  
  return assumptions;
}

function getAdversariesForProtocol(protocolType: ProtocolType): AdversaryProfile[] {
  const baseAdversaries: AdversaryProfile[] = [
    {
      id: 'ADV_EXT',
      type: 'external',
      capabilities: ['Call public functions', 'Submit transactions', 'Front-run transactions'],
      goals: ['Extract value', 'Drain funds', 'Manipulate state'],
      constraints: ['Must pay gas', 'Cannot directly modify storage', 'Subject to access control'],
      likelyAttacks: ['Flash loan attacks', 'Oracle manipulation', 'Reentrancy']
    }
  ];
  
  switch (protocolType) {
    case 'lending':
      baseAdversaries.push({
        id: 'ADV_LIQ',
        type: 'liquidator',
        capabilities: ['Trigger liquidations', 'Observe collateral prices', 'Compete for rewards'],
        goals: ['Maximize liquidation profits', 'Acquire cheap collateral'],
        constraints: ['Must meet liquidation requirements', 'Gas costs affect profitability'],
        likelyAttacks: ['Oracle manipulation before liquidation', 'Sandwich attacks on liquidation']
      });
      baseAdversaries.push({
        id: 'ADV_ORACLE',
        type: 'oracle-manipulator',
        capabilities: ['Influence oracle prices temporarily', 'Create large trades'],
        goals: ['Manipulate prices for profit', 'Trigger false liquidations'],
        constraints: ['Capital requirements', 'Slippage costs', 'Time window limits'],
        likelyAttacks: ['Flash loan price manipulation', 'TWAP distortion']
      });
      break;
      
    case 'dex':
      baseAdversaries.push({
        id: 'ADV_MEV',
        type: 'mev-bot',
        capabilities: ['Observe mempool', 'Insert transactions', 'Bundle transactions'],
        goals: ['Extract MEV', 'Sandwich trades', 'Arbitrage'],
        constraints: ['Competition with other bots', 'Gas costs', 'Timing requirements'],
        likelyAttacks: ['Sandwich trading', 'Just-in-time liquidity', 'FRont-running']
      });
      break;
      
    case 'bridge':
      baseAdversaries.push({
        id: 'ADV_VAL',
        type: 'insider',
        capabilities: ['Validate messages', 'Relay transactions', 'Influence consensus'],
        goals: ['False message validation', 'Delay or censor transactions'],
        constraints: ['May need collusion', 'Reputation risk', 'Legal risk'],
        likelyAttacks: ['Validator collusion', 'Message forgery', 'Censorship']
      });
      break;
  }
  
  return baseAdversaries;
}

function getThreatsForProtocol(protocolType: ProtocolType): AttackVector[] {
  const threats: AttackVector[] = [];
  let counter = 1;
  
  // Universal threats
  threats.push({
    id: `AV_${counter++}`,
    name: 'Reentrancy Attack',
    category: 'logic-error',
    prerequisite: ['External call before state update', 'No reentrancy guard'],
    impact: 'Drain contract funds, corrupt state',
    likelihood: 'likely',
    severity: 'critical',
    relatedInvariants: ['INV_1'],
    detectionMethod: 'Check CEI pattern compliance'
  });
  
  threats.push({
    id: `AV_${counter++}`,
    name: 'Access Control Bypass',
    category: 'access-control',
    prerequisite: ['Missing or weak access control', 'Function visibility issue'],
    impact: 'Unauthorized state changes, fund theft',
    likelihood: 'possible',
    severity: 'critical',
    relatedInvariants: [],
    detectionMethod: 'Check modifier coverage on sensitive functions'
  });
  
  threats.push({
    id: `AV_${counter++}`,
    name: 'Oracle Price Manipulation',
    category: 'oracle-manipulation',
    prerequisite: ['Single oracle source', 'Flash loan capability', 'Low liquidity'],
    impact: 'Incorrect pricing, stolen funds via liquidations/swaps',
    likelihood: protocolType === 'lending' ? 'likely' : 'possible',
    severity: 'critical',
    relatedInvariants: [],
    detectionMethod: 'Monitor price deviations from TWAP'
  });
  
  threats.push({
    id: `AV_${counter++}`,
    name: 'Flash Loan Attack',
    category: 'flash-loan',
    prerequisite: ['No flash loan detection', 'State dependencies across calls'],
    impact: 'Manipulate protocol state for profit',
    likelihood: 'possible',
    severity: 'high',
    relatedInvariants: [],
    detectionMethod: 'Check for balance changes within single transaction'
  });
  
  // Protocol-specific threats
  switch (protocolType) {
    case 'lending':
      threats.push({
        id: `AV_${counter++}`,
        name: 'Improper Liquidation',
        category: 'liquidation',
        prerequisite: ['Incorrect health factor calculation', 'Oracle manipulation'],
        impact: 'User funds lost through unjustified liquidation',
        likelihood: 'possible',
        severity: 'critical',
        relatedInvariants: [],
        detectionMethod: 'Verify health factor calculations'
      });
      threats.push({
        id: `AV_${counter++}`,
        name: 'Interest Rate Manipulation',
        category: 'logic-error',
        prerequisite: ['Interest rate depends on utilization', 'Large position influence'],
        impact: 'Manipulated interest rates, economic attack',
        likelihood: 'unlikely',
        severity: 'medium',
        relatedInvariants: [],
        detectionMethod: 'Monitor rate changes relative to utilization'
      });
      break;
      
    case 'vault':
      threats.push({
        id: `AV_${counter++}`,
        name: 'Share Inflation Attack (ERC4626)',
        category: 'share-inflation',
        prerequisite: ['Donation possible', 'Pausable mint', 'Round errors exploitable'],
        impact: 'Dilute existing shareholders, steal yield',
        likelihood: 'possible',
        severity: 'high',
        relatedInvariants: [],
        detectionMethod: 'Monitor share-to-asset ratio changes'
      });
      break;
      
    case 'bridge':
      threats.push({
        id: `AV_${counter++}`,
        name: 'Fake Deposit / Double Spend',
        category: 'logic-error',
        prerequisite: ['Validator compromise', 'Weak validation logic'],
        impact: 'Mint tokens without locking, double-spend',
        likelihood: 'depends-on-setup',
        severity: 'critical',
        relatedInvariants: [],
        detectionMethod: 'Verify cross-chain message authenticity'
      });
      break;
  }
  
  return threats;
}

function createEmptyXRayOutput(): XRayOutput {
  return {
    protocolType: 'unknown',
    threatModel: {
      assetsAtRisk: [],
      entryPoints: [],
      privilegeBoundaries: [],
      keyActors: []
    },
    invariants: [],
    trustAssumptions: [],
    adversaryProfiles: [],
    attackVectors: [],
    generatedAt: new Date().toISOString()
  };
}
