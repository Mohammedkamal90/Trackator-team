// ============================================================
// TRACKATOR - Phase Integration Module
// Orchestrates all 4 analysis phases into unified pipeline
// ============================================================

import * as fs from 'fs';
import * as path from 'path';

import { analyzeStorageDependencies, StorageDependencyAnalysisOptions, StorageDependencyAnalysisResult } from '../tier2-enricher/storage-dependency-analyzer';
import { analyzeStateCouplings, StateCouplingAnalysisOptions, StateCouplingAnalysisResult } from '../tier2-enricher/state-coupling-detector';
import { analyzeSynchronization, SyncAnalysisOptions, SyncAnalysisResult } from '../tier2-enricher/sync-analyzer';
import { validateEvidence, EvidenceValidationOptions, EvidenceValidationResult, calibrateConfidence, CalibratedConfidenceResult, exportCalibratedResults } from './evidence-validator';
import { generateWeaponizedAttacks, WeaponizedCouplingResult } from '../tier2-enricher/state-coupling-detector';

import {
  SolidityContract,
  FunctionRegistry,
  RegisteredFunction,
  Invariant,
  CallEdge,
  XRayOutput,
  BreakdownOutput,
  AlertRule
} from '../types';

// ============================================================
// UNIFIED ANALYSIS OPTIONS
// ============================================================

export interface UnifiedAnalysisOptions {
  // Source data (required)
  contracts: SolidityContract[];
  
  // Optional enriched data (from previous tiers)
  functionRegistry?: Map<string, RegisteredFunction[]>;
  callEdges?: CallEdge[];
  invariants?: Invariant[];
  xrayData?: XRayOutput;
  breakdownData?: BreakdownOutput;
  alertRules?: AlertRule[];
  
  // Analysis configuration
  runPhase1?: boolean;    // Storage Dependency Analysis
  runPhase2?: boolean;    // State Coupling Detection
  runPhase3?: boolean;    // Synchronization Analysis
  runPhase4?: boolean;    // Evidence Validation
  
  // Output options
  outputDir?: string;
  verbose?: boolean;
}

export interface UnifiedAnalysisResult {
  timestamp: string;
  duration: number;  // ms
  
  // Phase results (populated if phase ran)
  phase1?: StorageDependencyAnalysisResult;
  phase2?: StateCouplingAnalysisResult;
  phase3?: SyncAnalysisResult;
  phase4?: EvidenceValidationResult;
  
  // NEW: Advanced analysis results (Fix D & Fix A)
  calibratedConfidence?: CalibratedConfidenceResult;   // Fix D: Multi-dimensional calibration
  weaponizedAttacks?: WeaponizedCouplingResult;         // Fix A: Attack scenarios
  
  // Unified summary
  summary: UnifiedSummary;
  
  // Output paths
  outputFiles: string[];
}

export interface UnifiedSummary {
  totalFindings: number;
  criticalFindings: number;
  potentialBugs: number;
  confirmedBugs: number;
  falsePositives: number;
  byDesign: number;
  requiresInvestigation: number;
  recommendations: RecommendationItem[];
}

export interface RecommendationItem {
  priority: 'immediate' | 'short-term' | 'long-term' | 'review';
  category: string;
  title: string;
  description: string;
  affectedPhases: number[];
}

// ============================================================
// MAIN INTEGRATION FUNCTION
// ============================================================

/**
 * Run complete 4-phase analysis pipeline
 * Implements all Prompt requirements in unified execution
 */
export async function runUnifiedAnalysis(
  options: UnifiedAnalysisOptions
): Promise<UnifiedAnalysisResult> {
  const startTime = Date.now();
  const {
    contracts,
    functionRegistry,
    callEdges = [],
    invariants = [],
    runPhase1 = true,
    runPhase2 = true,
    runPhase3 = true,
    runPhase4 = true,
    outputDir,
    verbose = false
  } = options;

  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║     TRACKATOR COMPLETE 4-PHASE AUDIT PIPELINE              ║');
  console.log('╚═════════════════════════════════════════════════════════════╝');
  console.log('');

  const result: UnifiedAnalysisResult = {
    timestamp: new Date().toISOString(),
    duration: 0,
    outputFiles: [],
    summary: {
      totalFindings: 0,
      criticalFindings: 0,
      potentialBugs: 0,
      confirmedBugs: 0,
      falsePositives: 0,
      byDesign: 0,
      requiresInvestigation: 0,
      recommendations: []
    }
  };

  // ========================================
  // PHASE 1: Storage Dependency Analysis
  // ========================================
  if (runPhase1) {
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  PHASE 1: Storage Dependency & Permissionless Mapping        │');
    console.log('└─────────────────────────────────────────────────────────────┘');

    try {
      const phase1Opts: StorageDependencyAnalysisOptions = {
        contracts,
        functionRegistry,
        callEdges,
        invariants,
        includeTrustBoundaries: true,
        verbose
      };

      result.phase1 = analyzeStorageDependencies(phase1Opts);
      
      console.log(`  ✓ Phase 1 complete: ${result.phase1.storageWriteGraph.summary.totalVariablesTracked} variables tracked`);
      console.log(`  ✓ ${result.phase1.highRiskFindings.length} high-risk findings generated`);
      
      // Extract counts for summary
      result.summary.totalFindings += result.phase1.highRiskFindings.length;
      result.summary.criticalFindings += result.phase1.highRiskFindings.filter(f => f.severity === 'critical').length;
      result.summary.potentialBugs += result.phase1.highRiskFindings.filter(f => f.severity === 'high').length;
      
    } catch (error) {
      console.error('  ✗ Phase 1 failed:', error.message);
      if (verbose) console.error(error);
    }
  }

  // ========================================
  // PHASE 2: State Coupling Analysis
  // ========================================
  if (runPhase2) {
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  PHASE 2: State Dependency & Cross-Function Analysis       │');
    console.log('└─────────────────────────────────────────────────────────────┘');

    try {
      const phase2Opts: StateCouplingAnalysisOptions = {
        contracts,
        functionRegistry,
        callEdges,
        invariants,
        storageWriteGraph: result.phase1?.storageWriteGraph,
        verbose
      };

      result.phase2 = analyzeStateCouplings(phase2Opts);
      
      console.log(`  ✓ Phase 2 complete: ${result.phase2.functionDependencyMatrix.statistics.totalFunctions} functions analyzed`);
      console.log(`  ✓ ${result.phase2.functionDependencyMatrix.statistics.totalDependencies} dependencies found`);
      console.log(`  ✓ ${result.phase2.hiddenCouplings.couplings.length} hidden couplings detected`);
      console.log(`  ✓ ${result.phase2.topStateIntersections.intersections.length} state intersections ranked`);
      console.log(`  ✓ ${result.phase2.criticalFindings.length} critical findings from coupling analysis`);

      // Update summary
      result.summary.totalFindings += result.phase2.criticalFindings.length;
      result.summary.criticalFindings += result.phase2.criticalFindings.filter(f => f.severity === 'critical').length;
      result.summary.potentialBugs += result.phase2.criticalFindings.filter(f => f.severity === 'high').length;
      
    } catch (error) {
      console.error('  ✗ Phase 2 failed:', error.message);
      if (verbose) console.error(error);
    }
  }

  // ========================================
  // PHASE 3: Synchronization Analysis
  // ========================================
  if (runPhase3) {
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  PHASE 3: Assumption Consumers & Desync Analysis            │');
    console.log('└─────────────────────────────────────────────────────────────┘');

    try {
      const phase3Opts: SyncAnalysisOptions = {
        contracts,
        functionRegistry,
        callEdges,
        invariants,
        storageWriteGraph: result.phase1?.storageWriteGraph,
        verbose
      };

      result.phase3 = analyzeSynchronization(phase3Opts);
      
      console.log(`  ✓ Phase 3 complete: ${result.phase3.desynchronizationAnalysis.summary.totalSyncGroups} sync groups identified`);
      console.log(`  ✓ ${result.phase3.desynchronizationAnalysis.summary.atRiskGroups} at-risk groups`);
      console.log(`  ✓ ${result.phase3.desynchronizationAnalysis.summary.totalDesyncSources} desync sources found`);
      console.log(`  ✓ ${result.phase3.desynchronizationAnalysis.detectedRisks.length} desync risks detected`);
      console.log(`  ✓ ${result.phase3.syncBoundaries.boundaries.length} sync boundaries mapped`);
      console.log(`  ✓ ${result.phase3.topSyncRelationships.relationships.length} top sync relationships ranked`);

      // Update summary
      result.summary.totalFindings += result.phase3.desynchronizationAnalysis.detectedRisks.length;
      result.summary.criticalFindings += result.phase3.desynchronizationAnalysis.detectedRisks.filter(r => r.severity === 'critical' || r.impact === 'critical').length;
      result.summary.potentialBugs += result.phase3.desynchronizationAnalysis.detectedRisks.filter(r => r.severity === 'high' || r.impact === 'high').length;
      
    } catch (error) {
      console.error('  ✗ Phase 3 failed:', error.message);
      if (verbose) console.error(error);
    }
  }

  // ========================================
  // PHASE 4: Evidence Validation
  // ========================================
  if (runPhase4) {
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  PHASE 4: Evidence Validation & Reachability Analysis         │');
    console.log('└─────────────────────────────────────────────────────────────┘');

    try {
      // Collect findings from all phases for validation
      const phase1Findings = result.phase1?.highRiskFindings || [];
      const phase2Findings = result.phase2?.criticalFindings || [];
      const phase3Risks = result.phase3?.desynchronizationAnalysis.detectedRisks || [];
      // FIX (integration bug): previously sourced from phase3.assumptionDependencyGraph.nodes
      // (AssumptionNode[] — no validatedBy/detectability/exploitability fields), cast `as any`,
      // which crashed initialClassifyAssumption() on assumption.validatedBy.length every run.
      // HiddenAssumption[] with the correct shape already exists on phase2's output — use that.
      const phase3Assumptions = result.phase2?.hiddenAssumptions.assumptions || [];

      const phase4Opts: EvidenceValidationOptions = {
        contracts,
        functionRegistry,
        callEdges,
        invariants,
        storageWriteGraph: result.phase1?.storageWriteGraph,
        phase1Findings,
        phase2Findings,
        phase3Risks,
        phase3Assumptions,
        verbose
      };

      result.phase4 = validateEvidence(phase4Opts);
      
      console.log(`  ✓ Phase 4 complete: ${result.phase4.classificationRegistry.statistics.totalFindings} findings classified`);
      console.log(`  ✓ Classification distribution:`, result.phase4.classificationRegistry.statistics.byClassification);
      console.log(`  ✓ Reachable paths: ${result.phase4.reachabilityAnalysis.summary.reachablePaths}`);
      console.log(`  ✓ Disproof attempts: ${result.phase4.disproofAnalysis.summary.totalAttempts}`);
      console.log(`  ✓ Final verdicts: ${result.phase4.finalVerdict.verdicts.length} entries generated`);

      // Update final summary from verdict table
      const v = result.phase4.finalVerdict.summary;
      result.summary.confirmedBugs = v.confirmedVulns;
      result.summary.potentialBugs = v.potentialVulns;
      result.summary.falsePositives = v.falsePositives;
      result.summary.byDesign = v.byDesign;
      result.summary.requiresInvestigation = v.cannotDetermine;

    } catch (error) {
      console.error('  ✗ Phase 4 failed:', error.message);
      if (verbose) console.error(error);
    }
  }

  // ========================================
  // FIX D: CONFIDENCE CALIBRATION (Post-Phase 4)
  // ========================================
  if (runPhase4 && result.phase4) {
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  FIX D: Multi-Dimensional Confidence Calibration        │');
    console.log('└─────────────────────────────────────────────────────────────┘');

    try {
      result.calibratedConfidence = calibrateConfidence(
        result.phase4.confidenceAssessments,
        result.phase4.classificationRegistry,
        result.phase4.reachabilityAnalysis,
        result.phase4.disproofAnalysis,
        {
          phase1Findings: result.phase1?.highRiskFindings,
          phase2Findings: result.phase2?.criticalFindings,
          phase3Risks: result.phase3?.desynchronizationAnalysis.detectedRisks,
          verbose
        }
      );
      
      const cc = result.calibratedConfidence.calibrationSummary;
      console.log(`  ✓ Calibration complete: ${cc.totalCalibrated} findings calibrated`);
      console.log(`  ✓ Avg confidence: ${cc.averageOriginalConfidence}% → ${cc.averageCalibratedConfidence}%`);
      console.log(`  ✓ High-value targets: ${cc.highValueTargets}`);
      console.log(`  ✓ Historically confirmed: ${cc.historicalMatches}`);
      console.log(`  ✓ Cross-phase confirmed: ${cc.crossPhaseConfirmed}`);
      
    } catch (error) {
      console.error('  ✗ Confidence calibration failed:', error instanceof Error ? error.message : error);
      if (verbose) console.error(error);
    }
  }

  // ========================================
  // FIX A: DEEP COUPLING EXPLOITATION (Post-Phase 2)
  // ========================================
  if (runPhase2 && result.phase2) {
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  FIX A: Weaponized Coupling Attack Generation            │');
    console.log('└─────────────────────────────────────────────────────────────┘');

    try {
      result.weaponizedAttacks = generateWeaponizedAttacks(result.phase2, {
        storageWriteGraph: result.phase1?.storageWriteGraph,
        verbose
      });
      
      const wa = result.weaponizedAttacks.summary;
      console.log(`  ✓ Attack generation complete: ${wa.totalAttacksGenerated} scenarios`);
      console.log(`  ✓ Critical attacks: ${wa.criticalAttacks}`);
      console.log(`  ✓ Atomicity violations: ${result.weaponizedAttacks.atomicityViolations.length}`);
      console.log(`  ✓ TOCTOU attacks: ${result.weaponizedAttacks.toctouAttacks.length}`);
      console.log(`  ✓ High-value targets: ${result.weaponizedAttacks.redteamOptimizedOutput.rankedTargets.filter(t => t.combinedScore >= 70).length}`);
      
    } catch (error) {
      console.error('  ✗ Attack generation failed:', error instanceof Error ? error.message : error);
      if (verbose) console.error(error);
    }
  }

  // ========================================
  // GENERATE UNIFIED SUMMARY & RECOMMENDATIONS
  // ========================================
  result.duration = Date.now() - startTime;

  // Generate cross-phase recommendations
  generateUnifiedRecommendations(result);

  // Print summary
  printUnifiedSummary(result);

  // Save advanced analysis outputs (Fix D & Fix A)
  saveAdvancedOutputs(result, outputDir);

  return result;
}

// ============================================================
// RECOMMENDATION GENERATOR
// ============================================================

function generateUnifiedRecommendations(result: UnifiedAnalysisResult): void {
  const recs: RecommendationItem[] = [];

  // From Phase 4 verdicts - confirmed/potential bugs need attention
  if (result.phase4) {
    for (const v of result.phase4.finalVerdict.verdicts) {
      if (v.finalVerdict === 'confirmed-vulnerability') {
        recs.push({
          priority: 'immediate',
          category: 'vulnerability-fix',
          title: `Fix confirmed vulnerability: ${v.observation.substring(0, 50)}...`,
          description: `This finding has been validated as a reachable bug with confidence ${v.confidence}%`,
          affectedPhases: [4]
        });
      } else if (v.finalVerdict === 'potential-vulnerability' && v.confidence >= 60) {
        recs.push({
          priority: 'short-term',
          category: 'investigation',
          title: `Investigate high-confidence potential vulnerability`,
          description: `${v.observation.substring(0, 50)}... has ${v.confidence}% confidence and should be investigated.`,
          affectedPhases: [4]
        });
      }
    }
  }

  // From Phase 3 - critical desync risks
  if (result.phase3) {
    for (const risk of result.phase3.criticalDesyncRisks.slice(0, 5)) {
      recs.push({
        priority: risk.impact === 'critical' ? 'immediate' : 'short-term',
        category: 'desync-mitigation',
        title: `Address desync risk: ${risk.riskType.replace(/-/g, ' ')}`,
        description: risk.scenario.substring(0, 100),
        affectedPhases: [3]
      });
    }
  }

  // From Phase 2 - critical couplings
  if (result.phase2) {
    for (const cf of result.phase2.criticalFindings.slice(0, 5)) {
      if (!recs.some(r => r.title.includes(cf.title.substring(0, 30)))) {
        recs.push({
          priority: cf.severity === 'critical' ? 'immediate' : 'short-term',
          category: 'coupling-hardening',
          title: `Address critical coupling: ${cf.title.substring(0, 50)}...`,
          description: cf.description.substring(0, 100),
          affectedPhases: [2]
        });
      }
    }
  }

  // General recommendations based on overall state
  if (result.summary.falsePositives > result.summary.totalFindings * 0.3) {
    recs.push({
      priority: 'review',
      category: 'quality-improvement',
      title: 'Review and refine classification criteria',
      description: 'High false positive rate (' + ((result.summary.falsePositives / result.summary.totalFindings * 100).toFixed(1) + '%). Consider adjusting classification thresholds.'),
      affectedPhases: [1, 2, 3, 4]
    });
  }

  if (result.summary.requiresInvestigation > 5) {
    recs.push({
      priority: 'long-term',
      category: 'analysis-completion',
      title: 'Complete investigation of uncertain findings',
      description: result.summary.requiresInvestigation + ' findings could not be definitively classified. Additional context or manual review needed.',
      affectedPhases: [4]
    });
  }

  result.summary.recommendations = recs;
}

// ============================================================
// UNIFIED SUMMARY PRINTER
// ============================================================

function printUnifiedSummary(result: UnifiedAnalysisResult): void {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║           UNIFIED ANALYSIS COMPLETE                      ║');
  console.log('╚═════════════════════════════════════════════════════════════╝');
  console.log('');

  // Summary table
  console.log('┌─────────────────────────────────────────────────────────────┐');
  console.log('│                    SUMMARY                              │');
  console.log('├─────────────────────────────────────────────────────────────┤');
  
  console.log('│  Duration: ' + (result.duration / 1000).toFixed(1) + 's                               │');
  console.log('│  Total Findings Analyzed: ' + result.summary.totalFindings + '                       │');
  console.log('│  ── Confirmed Bugs: ' + result.summary.confirmedBugs + '                          │');
  console.log('  ├─ Potential Bugs: ' + result.summary.potentialBugs + '                        │');
  console.log('  ├─ False Positives: ' + result.summary.falsePositives + '                      │');
  console.log('  ├─ By Design: ' + result.summary.byDesign + '                                │');
  console.log('  └─ Needs Investigation: ' + result.summary.requiresInvestigation + '             │');
  console.log('├─────────────────────────────────────────────────────────────┤');
  
  // Phase summaries
  if (result.phase1) {
    const s = result.phase1.storageWriteGraph.summary;
    console.log('│  Phase 1: ' + s.totalVariablesTracked + ' vars, ' + s.contendedVariableCount + ' contented │');
  }
  if (result.phase2) {
    const s = result.phase2.functionDependencyMatrix.statistics;
    console.log('│  Phase 2: ' + s.totalFunctions + ' funcs, ' + s.totalDependencies + ' deps, ' + s.stronglyCoupledPairs + ' strong couplings │');
  }
  if (result.phase3) {
    const s = result.phase3.desynchronizationAnalysis.summary;
    console.log('│  Phase 3: ' + s.totalSyncGroups + ' sync groups, ' + s.atRiskGroups + ' at-risk, ' + s.criticalRisks + ' critical │');
  }
  if (result.phase4) {
    const v = result.phase4.finalVerdict.summary;
    console.log('│  Phase 4: ' + v.totalEntries + ' verdicts, ' + v.confirmedVulns + ' confirmed, ' + v.averageConfidence + '% avg confidence │');
  }
  
  // NEW: Fix D & Fix A summaries
  if (result.calibratedConfidence) {
    const cc = result.calibratedConfidence.calibrationSummary;
    console.log('│  Fix D:   ' + cc.totalCalibrated + ' calibrated, ' + cc.highValueTargets + ' high-value, ' + cc.crossPhaseConfirmed + ' cross-phase ✓ │');
  }
  if (result.weaponizedAttacks) {
    const wa = result.weaponizedAttacks.summary;
    console.log('│  Fix A:   ' + wa.totalAttacksGenerated + ' attacks, ' + wa.criticalAttacks + ' critical, ' + result.weaponizedAttacks.atomicityViolations.length + ' atomicity flaws │');
  }
  
  console.log('├─────────────────────────────────────────────────────────────┤');
  
  // Recommendations
  if (result.summary.recommendations.length > 0) {
    console.log('│                                                           │');
    console.log('│  RECOMMENDATIONS:                                            │');
    
    for (const rec of result.summary.recommendations.slice(0, 5)) {
      let icon = '[ ]';
      if (rec.priority === 'immediate') icon = '[!!]';
      else if (rec.priority === 'short-term') icon = '[!]';
      else if (rec.priority === 'long-term') icon = '[*]';
      const line = '│  ' + icon + ' [' + rec.priority.toUpperCase() + '] ' + rec.title;
      console.log(line.padEnd(51) + ' │');
    }
    
    if (result.summary.recommendations.length > 5) {
      console.log('│  ... and ' + (result.summary.recommendations.length - 5) + ' more     │');
    }
  }
  
  console.log('╰─────────────────────────────────────────────────────────────╯');
  console.log('');
}

// ============================================================
// ADVANCED OUTPUT SAVER (Fix D & Fix A)
// ============================================================

/**
 * Save calibrated confidence and weaponized attacks to JSON files
 * These files are optimized for RedTeam-Trackator consumption
 */
function saveAdvancedOutputs(result: UnifiedAnalysisResult, outputDir?: string): void {
  if (!outputDir) return;
  
  const resolvedDir = path.resolve(outputDir);
  if (!fs.existsSync(resolvedDir)) {
    fs.mkdirSync(resolvedDir, { recursive: true });
  }
  
  // Save Fix D: Calibrated Confidence Results
  if (result.calibratedConfidence) {
    const calibratedPath = path.join(resolvedDir, 'trackator-calibrated.json');
    const calibratedOutput = exportCalibratedResults(result.calibratedConfidence);
    
    // Add full summary metadata
    const calibratedWithMeta = {
      _metadata: {
        generatedAt: result.timestamp,
        version: '1.0.0-fixD',
        description: 'Multi-dimensional confidence calibration for RedTeam integration'
      },
      calibrationSummary: result.calibratedConfidence.calibrationSummary,
      redteamOptimizedOutput: calibratedOutput.redteamOptimizedOutput,
      detailedAssessments: calibratedOutput.detailedAssessments
    };
    
    fs.writeFileSync(calibratedPath, JSON.stringify(calibratedWithMeta, null, 2));
    result.outputFiles.push(calibratedPath);
  }
  
  // Save Fix A: Weaponized Attack Scenarios
  if (result.weaponizedAttacks) {
    const attacksPath = path.join(resolvedDir, 'trackator-attacks.json');
    const wa = result.weaponizedAttacks;
    
    const attacksOutput = {
      _metadata: {
        generatedAt: result.timestamp,
        version: '1.0.0-fixA',
        description: 'Weaponized coupling attack scenarios for RedTeam integration'
      },
      summary: wa.summary,
      // Redteam-optimized format for quick consumption
      attackSurfaceSummary: wa.redteamOptimizedOutput.attackSurfaceSummary,
      rankedTargets: wa.redteamOptimizedOutput.rankedTargets,
      quickAttackPatterns: wa.redteamOptimizedOutput.attackPatterns,
      integrationHints: wa.redteamOptimizedOutput.integrationHints,
      // Full attack scenarios for deep-dive
      criticalAttackScenarios: wa.attackScenarios.filter(a => 
        a.severity === 'critical' || a.severity === 'high'
      ),
      atomicityViolations: wa.atomicityViolations,
      toctouAttacks: wa.toctouAttacks
    };
    
    fs.writeFileSync(attacksPath, JSON.stringify(attacksOutput, null, 2));
    result.outputFiles.push(attacksPath);
  }
  
  // Log what was saved
  const savedCount = (result.calibratedConfidence ? 1 : 0) + (result.weaponizedAttacks ? 1 : 0);
  if (savedCount > 0) {
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  ADVANCED OUTPUTS SAVED                                    │');
    console.log('├─────────────────────────────────────────────────────────────┤');
    if (result.calibratedConfidence) {
      console.log('│  ✓ trackator-calibrated.json (Fix D: Confidence)         │');
    }
    if (result.weaponizedAttacks) {
      console.log('│  ✓ trackator-attacks.json (Fix A: Attack Scenarios)     │');
    }
    console.log('╰─────────────────────────────────────────────────────────────╯');
  }
}
