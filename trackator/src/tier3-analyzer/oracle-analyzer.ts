// ============================================================
// TRACKATOR Tier 3 - Oracle Analyzer
// Detects price manipulation and oracle anomalies
// ============================================================

import {
  FoundryTrace,
  TraceStep,
  LogEntry,
  OracleAnalysis,
  PriceObservation,
  PriceDeviation,
  TWAPAnalysis,
  ManipulationIndicator,
  DecodedLogEvent
} from '../types';

export interface OracleAnalyzerOptions {
  knownOracles?: Map<string, OracleConfig>;
  deviationThreshold?: number; // Default 5%
  twapWindow?: number;         // Default 30 minutes
  verbose?: boolean;
}

export interface OracleConfig {
  address: string;
  name: string;
  asset: string;
  type: 'chainlink' | 'uniswap' | 'custom' | 'spot';
  decimals: number;
  updateThreshold?: number;   // Minimum time between updates
  maxDeviation?: number;      // Max allowed deviation from TWAP
}

/**
 * Main entry point for oracle analysis
 */
export function analyzeOracles(
  trace: FoundryTrace,
  options: OracleAnalyzerOptions = {}
): OracleAnalysis {
  const {
    knownOracles = new Map(),
    deviationThreshold = 5,
    twapWindow = 1800, // 30 minutes in seconds
    verbose = false
  } = options;
  
  if (verbose) console.log('Analyzing oracle interactions...');
  
  // Collect all price observations from trace
  const pricesObserved = collectPriceObservations(trace, knownOracles);
  
  // Compute deviations
  const deviations = computePriceDeviations(pricesObserved, deviationThreshold);
  
  // Analyze TWAP if multiple observations
  let twapAnalysis: TWAPAnalysis | undefined;
  if (pricesObserved.length >= 2) {
    twapAnalysis = computeTWAP(pricesObserved, twapWindow);
  }
  
  // Detect manipulation patterns
  const manipulationIndicators = detectManipulationPatterns(trace, pricesObserved, deviations);
  
  return {
    pricesObserved,
    deviations,
    twapAnalysis,
    manipulationIndicators
  };
}

/**
 * Collect price observations from trace execution
 */
function collectPriceObservations(
  trace: FoundryTrace,
  knownOracles: Map<string, OracleConfig>
): PriceObservation[] {
  const observations: PriceObservation[] = [];
  const processedCalls = new Set<number>();
  
  for (const step of trace.trace) {
    collectPricesFromStep(step, observations, processedCalls, knownOracles);
  }
  
  return observations;
}

function collectPricesFromStep(
  step: TraceStep,
  observations: PriceObservation[],
  processedCalls: Set<number>,
  knownOracles: Map<string, OracleConfig>
): void {
  if (processedCalls.has(step.stepIndex)) return;
  processedCalls.add(step.stepIndex);
  
  // Check if this call is to a known oracle
  const oracleConfig = knownOracles.get(step.address.toLowerCase());
  
  if (oracleConfig || isLikelyOracleCall(step)) {
    const observation = extractPriceFromCall(step, oracleConfig);
    if (observation) {
      observations.push(observation);
    }
  }
  
  // Also check logs for price updates
  if (step.subcalls) {
    for (const subcall of step.subcalls) {
      collectPricesFromStep(subcall, observations, processedCalls, knownOracles);
    }
  }
}

/**
 * Determine if a call looks like an oracle interaction
 */
function isLikelyOracleCall(step: TraceStep): boolean {
  const input = step.input.toLowerCase();
  const address = step.address.toLowerCase();
  
  // Common Chainlink functions
  const chainlinkSelectors = [
    '0x50538e0c', // latestRoundData
    '0x87049743', // getRoundData
    '0xfeaf968c'  // latestAnswer
  ];
  
  // Common Uniswap/DEX oracle functions
  const dexOracleSelectors = [
    '0x1698ae82', // price0CumulativeLast
    '0x226c3852', // price1CumulativeLast
    '0xd21220a7', // consult
    '0x502e4147'  // getPrice
  ];
  
  const selector = input.slice(0, 10);
  
  if ([...chainlinkSelectors, ...dexOracleSelectors].includes(selector)) {
    return true;
  }
  
  // Check contract name hints
  if (step.contractName) {
    const nameLower = step.contractName.toLowerCase();
    if (nameLower.includes('oracle') || 
        nameLower.includes('price') ||
        nameLower.includes('feed') ||
        nameLower.includes('chainlink')) {
      return true;
    }
  }
  
  return false;
}

/**
 * Extract price from an oracle call
 */
function extractPriceFromCall(
  step: TraceStep,
  config?: OracleConfig
): PriceObservation | null {
  try {
    let price = 0;
    let asset = config?.asset || 'unknown';
    let source: PriceObservation['source'] = config?.type || 'custom';
    
    // Try to extract price from return data
    if (step.output && step.output !== '0x') {
      // Chainlink latestRoundData returns (roundId, answer, startedAt, updatedAt, answeredInRound)
      // The answer is at offset 32 (after roundId)
      if (step.output.length >= 130) { // At least 2 uint256
        const answerHex = step.output.slice(66, 130); // Skip 0x + first 32 bytes
        price = Number(BigInt('0x' + answerHex));
        
        // Adjust for decimals
        if (config?.decimals) {
          price = price / Math.pow(10, config.decimals);
        }
      } else {
        // Single value return
        price = Number(BigInt('0x' + step.output.slice(2)));
        if (config?.decimals) {
          price = price / Math.pow(10, config.decimals);
        }
      }
    }
    
    // If we couldn't extract price, skip this observation
    if (price === 0 && !step.output) {
      return null;
    }
    
    return {
      oracle: config?.name || step.address,
      asset,
      price,
      timestamp: Date.now(), // Would use block timestamp in real implementation
      source,
      confidence: config ? 'high' : 'medium',
      slotRead: undefined, // Would need storage access tracking
      functionCalled: decodeFunctionSelector(step.input)
    };
  } catch (error) {
    return null;
  }
}

/**
 * Decode function selector to name
 */
function decodeFunctionSelector(calldata: string): string {
  if (!calldata || calldata.length < 10) return 'unknown';
  
  const selectors: Record<string, string> = {
    '0x50538e0c': 'latestRoundData()',
    '0x87049743': 'getRoundData(uint80)',
    '0xfeaf968c': 'latestAnswer()',
    '0x1698ae82': 'price0CumulativeLast()',
    '0x226c3852': 'price1CumulativeLast()',
    '0xd21220a7': 'consult(address,uint256)',
    '0x502e4147': 'getPrice(address)',
    '0x3ab23a0b': 'getUnderlyingPrice(address)'
  };
  
  return selectors[calldata.slice(0, 10)] || `unknown(${calldata.slice(0, 10)})`;
}

/**
 * Compute price deviations from expected values
 */
function computePriceDeviations(
  observations: PriceObservation[],
  thresholdPercent: number
): PriceDeviation[] {
  const deviations: PriceDeviation[] = [];
  
  // Group by oracle/asset
  const grouped = new Map<string, PriceObservation[]>();
  
  for (const obs of observations) {
    const key = `${obs.oracle}:${obs.asset}`;
    const existing = grouped.get(key) || [];
    existing.push(obs);
    grouped.set(key, existing);
  }
  
  // For each group, check for deviations
  for (const [key, obsList] of grouped) {
    if (obsList.length < 2) continue;
    
    // Use first observation as baseline (in real impl, would use TWAP or external feed)
    const expectedPrice = obsList[0].price;
    
    for (let i = 1; i < obsList.length; i++) {
      const observedPrice = obsList[i].price;
      
      if (expectedPrice === 0) continue;
      
      const deviationPercent = Math.abs((observedPrice - expectedPrice) / expectedPrice * 100);
      
      deviations.push({
        oracle: obsList[i].oracle,
        asset: key.split(':')[1],
        observedPrice,
        expectedPrice,
        deviationPercent,
        thresholdExceeded: deviationPercent > thresholdPercent,
        thresholdPercent,
        timeWindow: Math.abs(obsList[i].timestamp - obsList[0].timestamp)
      });
    }
  }
  
  // Also check for same-asset different-oracle discrepancies
  const assetGroups = new Map<string, PriceObservation[]>();
  for (const obs of observations) {
    const existing = assetGroups.get(obs.asset) || [];
    existing.push(obs);
    assetGroups.set(obs.asset, existing);
  }
  
  for (const [asset, assetObs] of assetGroups) {
    const uniqueOracles = new Set(assetObs.map(o => o.oracle));
    
    if (uniqueOracles.size > 1) {
      // Cross-check oracles for same asset
      const prices = assetObs.map(o => o.price);
      const minPrice = Math.min(...prices);
      const maxPrice = Math.max(...prices);
      
      if (minPrice > 0) {
        const spread = ((maxPrice - minPrice) / minPrice) * 100;
        
        if (spread > thresholdPercent) {
          deviations.push({
            oracle: 'multiple',
            asset,
            observedPrice: maxPrice,
            expectedPrice: minPrice,
            deviationPercent: spread,
            thresholdExceeded: true,
            thresholdPercent,
            timeWindow: 0
          });
        }
      }
    }
  }
  
  return deviations;
}

/**
 * Compute Time-Weighted Average Price (TWAP)
 */
function computeTWAP(
  observations: PriceObservation[],
  _windowSeconds: number
): TWAPAnalysis | undefined {
  if (observations.length < 2) return undefined;
  
  // Sort by timestamp
  const sorted = [...observations].sort((a, b) => a.timestamp - b.timestamp);
  
  // Calculate weighted average
  let weightedSum = 0;
  let totalWeight = 0;
  
  for (let i = 0; i < sorted.length - 1; i++) {
    const current = sorted[i];
    const next = sorted[i + 1];
    const duration = next.timestamp - current.timestamp;
    
    weightedSum += current.price * duration;
    totalWeight += duration;
  }
  
  const avgPrice = totalWeight > 0 ? weightedSum / totalWeight : sorted[0].price;
  const currentPrice = sorted[sorted.length - 1].price;
  
  const deviation = avgPrice > 0 ? Math.abs((currentPrice - avgPrice) / avgPrice * 100) : 0;
  
  return {
    period: _windowSeconds,
    avgPrice,
    currentPrice,
    deviation,
    sampleCount: sorted.length,
    firstBlock: sorted[0].timestamp,
    lastBlock: sorted[sorted.length - 1].timestamp
  };
}

/**
 * Detect potential manipulation patterns
 */
function detectManipulationPatterns(
  trace: FoundryTrace,
  _observations: PriceObservation[],
  deviations: PriceDeviation[]
): ManipulationIndicator[] {
  const indicators: ManipulationIndicator[] = [];
  
  // Pattern 1: Flash loan price swing
  const flashLoanIndicator = detectFlashLoanPattern(trace);
  if (flashLoanIndicator) {
    indicators.push(flashLoanIndicator);
  }
  
  // Pattern 2: Large price deviation around liquidation
  const liquidationIndicator = detectLiquidationManipulation(trace, deviations);
  if (liquidationIndicator) {
    indicators.push(liquidationIndicator);
  }
  
  // Pattern 3: Oracle flip (sudden direction change)
  const oracleFlipIndicator = detectOracleFlip(deviations);
  if (oracleFlipIndicator) {
    indicators.push(oracleFlipIndicator);
  }
  
  // Pattern 4: Stale price usage
  const staleIndicator = detectStalePrice(trace);
  if (staleIndicator) {
    indicators.push(staleIndicator);
  }
  
  return indicators;
}

/**
 * Detect flash loan + price manipulation pattern
 */
function detectFlashLoanPattern(trace: FoundryTrace): ManipulationIndicator | null {
  // Look for flash loan followed by large trade/swap
  let hasFlashLoan = false;
  let hasLargeTrade = false;
  const affectedFunctions: string[] = [];
  
  for (const step of trace.trace) {
    const input = step.input.toLowerCase();
    
    // Flash loan detection (common patterns)
    if (input.startsWith('0x15ed952c') || // flashLoan on Aave
        step.contractName?.toLowerCase().includes('flashloan')) {
      hasFlashLoan = true;
      affectedFunctions.push(`${step.contractName}.flashLoan`);
    }
    
    // Large swap/trade detection
    if (input.startsWith('0x128acb08') || // swapExactTokensForTokens
        input.startsWith('0x7ff36ab5') || // swapExactETHForTokens
        input.startsWith('0x18cbafe5') || // swapExactTokensForETH
        step.contractName?.toLowerCase().includes('swap') ||
        step.contractName?.toLowerCase().includes('router')) {
      hasLargeTrade = true;
      affectedFunctions.push(`${step.contractName}.${step.contractName || 'trade'}`);
    }
  }
  
  if (hasFlashLoan && hasLargeTrade) {
    return {
      type: 'flash-loan-price-swing',
      confidence: 0.85,
      evidence: [
        'Flash loan detected in transaction flow',
        'Large trade/swap executed within same transaction',
        'Potential price manipulation via flash loan'
      ],
      affectedFunctions
    };
  }
  
  return null;
}

/**
 * Detect manipulation around liquidation events
 */
function detectLiquidationManipulation(
  trace: FoundryTrace,
  deviations: PriceDeviation[]
): ManipulationIndicator | null {
  // Check for liquidation calls combined with price deviations
  let hasLiquidation = false;
  const affectedFunctions: string[] = [];
  
  for (const step of trace.trace) {
    const input = step.input.toLowerCase();
    
    if (input.includes('liquidate') ||
        step.contractName?.toLowerCase().includes('liquidat')) {
      hasLiquidation = true;
      affectedFunctions.push(`${step.contractName}.liquidate`);
    }
  }
  
  // Check if there are significant price deviations
  const significantDeviation = deviations.some(d => d.thresholdExceeded && d.deviationPercent > 3);
  
  if (hasLiquidation && significantDeviation) {
    return {
      type: 'liquidation-cascade',
      confidence: 0.75,
      evidence: [
        'Liquidation operation detected',
        'Significant price deviation observed',
        'Possible oracle manipulation before liquidation'
      ],
      affectedFunctions
    };
  }
  
  return null;
}

/**
 * Detect sudden oracle direction changes (flips)
 */
function detectOracleFlip(deviations: PriceDeviation[]): ManipulationIndicator | null {
  // Find large deviations that reverse direction
  const largeDeviations = deviations.filter(d => d.deviationPercent > 10);
  
  if (largeDeviations.length >= 2) {
    // Check if they're in opposite directions relative to some baseline
    const positive = largeDeviations.filter(d => d.observedPrice > d.expectedPrice);
    const negative = largeDeviations.filter(d => d.observedPrice < d.expectedPrice);
    
    if (positive.length > 0 && negative.length > 0) {
      return {
        type: 'oracle-flip',
        confidence: 0.65,
        evidence: [
          'Multiple large price deviations detected',
          'Deviations in both directions suggest volatility or manipulation',
          `${positive.length} high, ${negative.length} low readings`
        ],
        affectedFunctions: ['oracle reads']
      };
    }
  }
  
  return null;
}

/**
 * Detect stale price usage
 */
function detectStalePrice(_trace: FoundryTrace): ManipulationIndicator | null {
  // This would need block timestamp comparison with oracle's updatedAt
  // Simplified version - would need more context
  
  return null; // Placeholder - real implementation would check staleness
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * Create default oracle configurations for common protocols
 */
export function createDefaultOracleConfigs(): Map<string, OracleConfig> {
  const configs = new Map<string, OracleConfig>();
  
  // Common Chainlink price feeds (mainnet addresses)
  const chainlinkFeeds = [
    { address: '0x5f4ec3df9cbd43714fe2740f36e36cc3ddce80d0', name: 'Chainlink BTC/USD', asset: 'BTC', decimals: 8 },
    { address: '0x777ae6f3f25dd913c9d090174f80f40ff5a9b5e5', name: 'Chainlink ETH/USD', asset: 'ETH', decimals: 8 },
    { address: '0xa02770cb3288ad05dc319ebc604574efb1d270fd', name: 'Chainlink DAI/USD', asset: 'DAI', decimals: 8 },
    { address: '0xc929ad75b72593967e83a71410b06e1843d92698', name: 'Chainlink USDC/USD', asset: 'USDC', decimals: 8 },
    { address: '0xdfd8c96a27b4d0c9e763733632c7d67c78bb0990', name: 'Chainlink USDT/USD', asset: 'USDT', decimals: 8 },
    { address: '0x863ac11b90fbc3c8b35e0c5eb2b1d345c1508252', name: 'Chainlink LINK/USD', asset: 'LINK', decimals: 8 },
    { address: '0xf4030086522a5beea4988f8ca5b36dbc97bee88c', name: 'Chainlink UNI/USD', asset: 'UNI', decimals: 8 },
    { address: '0xb159638929Ea32A82e97348bF41CFC46b72BAd1B', name: 'Chainlink WBTC/USD', asset: 'WBTC', decimals: 8 }
  ];
  
  for (const feed of chainlinkFeeds) {
    configs.set(feed.address.toLowerCase(), {
      ...feed,
      type: 'chainlink',
      maxDeviation: 3 // 3% max deviation for Chainlink
    });
  }
  
  return configs;
}
