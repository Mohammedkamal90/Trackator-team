### 4.0: Evidence Calibration (v2.0 → v2.1 ENHANCED)

**Purpose**: Consume **Evidence Validator outputs** (Fix D) for court-ready confidence scoring.

**v2.1 ENHANCEMENT (Fix D Integration)**: Now consumes ALL output fields from enhanced `evidence-validator.ts`:
- ✅ `classificationRegistry` with full 6-class system (`proven-property`, `potential-bug`, `reachable-bug`, `false-positive`, `by-design`, `insufficient-evidence`)
- ✅ `reachabilityAnalysis[]` with execution paths, cross-contract prerequisites
- ✅ `disproofEngine` with 11 disproof strategies and confidence scores
- ✅ `confidenceAssessments[]` with multi-dimensional score breakdown
- ✅ `proofRequirements[]` with 9-criteria checklist for ReachableBug
- ✅ `finalVerdict[]` with RecommendedAction enum alignment

**When Evidence Data Available** (`context.evidence` exists):

```javascript
// ═══════════════════════════════════════════════════════════════
// v2.1 NEW: Enhanced Evidence Consumer for Fix D outputs
// ═══════════════════════════════════════════════════════════════
function calibrateEvidenceWithTrackator(finding, context) {
    if (!context.evidence) {
        console.log('⚠️ No evidence data available - using basic classification');
        return basicClassification(finding);
    }
    
    const calibration = {
        findingId: finding.id,
        
        // ═══════════════════════════════════════════════════
        // PART 1: 6-Class Classification (from Fix D)
        // ═══════════════════════════════════════════════════
        classification: null,
        classificationConfidence: 0,
        criteriaMet: [],
        criteriaFailed: [],
        
        // ═══════════════════════════════════════════════════
        // PART 2: Reachability Analysis (from Fix D)
        // ═══════════════════════════════════════════════════
        reachability: null,
        executionPath: null,
        crossContractPrereqs: [],
        blockingRequirement: null,
        
        // ═══════════════════════════════════════════════════
        // PART 3: Disproof Analysis (from Fix D)
        // ═══════════════════════════════════════════════════
        disproofResult: null,
        disproofConfidence: 0,
        disproofStrategiesAttempted: [],
        
        // ═══════════════════════════════════════════════════
        // PART 4: Multi-Dimensional Confidence (from Fix D)
        // ═══════════════════════════════════════════════════
        confidenceBreakdown: {
            overall: 0,
            evidenceStrength: 0,
            reachabilityConfidence: 0,
            impactConfidence: 0,
            falsePositiveRisk: 0
        },
        
        // ═══════════════════════════════════════════════════
        // PART 5: Proof Requirements (9-criteria from Fix D)
        // ═══════════════════════════════════════════════════
        proofRequirements: {
            met: 0,
            total: 9,
            requirements: [],
            status: 'not-proven'
        },
        
        // ═══════════════════════════════════════════════════
        // PART 6: Final Verdict & Action (from Fix D)
        // ═══════════════════════════════════════════════════
        finalVerdict: null,
        recommendedAction: null,
        remainingUnknowns: []
    };
    
    const { 
        classificationRegistry, 
        reachabilityAnalysis, 
        disproofAnalysis,
        confidenceAssessments,
        proofRequirementsList,
        finalVerdict
    } = context.evidence;
    
    // ──────────────────────────────────────────────
    // STEP 1: Apply 6-Class Classification
    // ──────────────────────────────────────────────
    if (classificationRegistry && classificationRegistry.entries) {
        // Find matching entry from Trackator's classification
        const matchingEntry = classificationRegistry.entries.find(e => 
            e.findingId === finding.id || 
            e.title === finding.title ||
            e.originalFindingId === finding.trackatorEvidence?.originalFindingId
        );
        
        if (matchingEntry) {
            calibration.classification = matchingEntry.classification;  // One of 6 classes
            calibration.classificationConfidence = matchingEntry.confidence;  // 0-100
            
            // Map criteria met/failed
            calibration.criteriaMet = matchingEntry.supportingEvidence?.map(e => e.itemId) || [];
            calibration.criteriaFailed = matchingEntry.blockingEvidence?.map(e => e.itemId) || [];
            
            console.log(`  📋 Classification: ${calibration.classification} (${calibration.classificationConfidence}%)`);
        } else {
            // No direct match - run local classification
            const localClass = classifyFindingV21(finding, context);
            calibration.classification = localClass.class;
            calibration.classificationConfidence = localClass.confidence;
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 2: Apply Reachability Analysis
    // ──────────────────────────────────────────────
    if (reachabilityAnalysis && reachabilityAnalysis.paths) {
        const matchingPath = reachabilityAnalysis.paths.find(p => p.findingId === finding.id);
        
        if (matchingPath) {
            calibration.reachability = matchingPath.isReachable ? 'reachable' : 'unreachable';
            calibration.executionPath = matchingPath.callChain;  // Full ExecutionStep[]
            
            // v2.1 NEW: Extract cross-contract prerequisites
            calibration.crossContractPrereqs = (matchingPath.crossContractPrereqs || []).map(ccp => ({
                targetContract: ccp.targetContract,
                requiredState: ccp.requiredState,
                dependencyType: ccp.dependencyType,
                canBeSatisfied: ccp.canBeSatisfied
            }));
            
            // Extract blocking requirement if unreachable
            if (!matchingPath.isReachable && matchingPath.blockingRequirement) {
                calibration.blockingRequirement = {
                    requirement: matchingPath.blockingRequirement.requirement,
                    type: matchingPath.blockingRequirement.type,
                    whyBlocking: matchingPath.blockingRequirement.whyBlocking,
                    potentialBypass: matchingPath.blockingRequirement.potentialBypass
                };
            }
            
            console.log(`  🎯 Reachability: ${calibration.reachability}${calibration.blockingRequirement ? ' (blocked: ' + calibration.blockingRequirement.type + ')' : ''}`);
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 3: Apply Disproof Analysis
    // ──────────────────────────────────────────────
    if (disproofAnalysis && disproofAnalysis.results) {
        const matchingDisproof = disproofAnalysis.results.find(r => r.findingId === finding.id);
        
        if (matchingDisproof) {
            calibration.disproofResult = matchingDisproof.newClassification;  // Reclassified?
            calibration.disproofConfidence = matchingDisproof.confidence;  // Confidence in reclassification
            
            // What strategies were tried?
            calibration.disproofStrategiesAttempted = (disproofAnalysis.disproofAttempts || [])
                .filter(a => a.targetFindingId === finding.id)
                .map(a => a.strategy);
            
            console.log(`  🛡️ Disproof: ${calibration.disproofResult} (${calibration.disproofConfidence}% confidence)`);
            console.log(`     Strategies tried: ${calibration.disproofStrategiesAttempted.join(', ') || 'none'}`);
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 4: Multi-Dimensional Confidence Score
    // ──────────────────────────────────────────────
    if (confidenceAssessments) {
        const matchingAssessment = confidenceAssessments.find(a => a.findingId === finding.id);
        
        if (matchingAssessment) {
            // v2.1 NEW: Full score breakdown from Fix D
            calibration.confidenceBreakdown = {
                overall: matchingAssessment.overallConfidence,
                evidenceStrength: matchingAssessment.evidenceStrength,
                reachabilityConfidence: matchingAssessment.reachabilityConfidence,
                impactConfidence: matchingAssessment.impactConfidence,
                falsePositiveRisk: matchingAssessment.falsePositiveRisk  // Higher = more likely FP
            };
            
            // v2.1 NEW: Track remaining unknowns for investigation
            calibration.remainingUnknowns = (matchingAssessment.remainingUnknowns || []).map(u => ({
                factor: u.factor,
                whyUnknown: u.whyUnknown,
                impactIfWrong: u.impactIfWrong,
                suggestedInvestigation: u.suggestedInvestigation
            }));
            
            console.log(`  📊 Confidence: ${calibration.confidenceBreakdown.overall}%`);
            console.log(`     Evidence: ${calibration.confidenceBreakdown.evidenceStrength}%, Reachability: ${calibration.confidenceBreakdown.reachabilityConfidence}%`);
            console.log(`     Impact: ${calibration.confidenceBreakdown.impactConfidence}%, FP Risk: ${calibration.confidenceBreakdown.falsePositiveRisk}%`);
            if (calibration.remainingUnknowns.length > 0) {
                console.log(`     ⚠️ Unknowns: ${calibration.remainingUnknowns.map(u => u.factor).join(', ')}`);
            }
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 5: Proof Requirements (9-criteria checklist)
    // ──────────────────────────────────────────────
    if (proofRequirementsList) {
        const matchingProofReq = proofRequirementsList.find(r => r.findingId === finding.id);
        
        if (matchingProofReq) {
            calibration.proofRequirements = {
                met: matchingProofReq.metRequirements,
                total: matchingProofReq.totalRequirements,
                status: matchingProofReq.overallStatus,  // proven-reachable | not-proven | disproven | insufficient-evidence
                requirements: (matchingProofReq.requirements || []).map(req => ({
                    id: req.reqId,
                    requirement: req.requirement,
                    category: req.category,
                    status: req.status,
                    hasEvidence: req.evidence !== undefined && req.evidence !== null,
                    explanation: req.explanation
                }))
            };
            
            console.log(`  ✓ Proof Requirements: ${calibration.proofRequirements.met}/${calibration.proofRequirements.total} (${calibration.proofRequirements.status})`);
        }
    }
    
    // ──────────────────────────────────────────────
    // STEP 6: Final Verdict & Recommended Action
    // ──────────────────────────────────────────────
    if (finalVerdict && finalVerdict.verdicts) {
        const matchingVerdict = finalVerdict.verdicts.find(v => v.findingId === finding.id);
        
        if (matchingVerdict) {
            calibration.finalVerdict = matchingVerdict.finalVerdict;  // confirmed-vulnerability | potential-vulnerability | false-positive | by-design | cannot-determine | deferred
            calibration.recommendedAction = matchingVerdict.recommendedAction;  // immediate-fix | short-term-investigation | long-term-monitoring | accept-risk | dismiss | escalate-to-auditor | defer
            
            console.log(`  ⚖️ Verdict: ${calibration.finalVerdict}`);
            console.log(`  ➡️ Action: ${calibration.recommendedAction}`);
        }
    }
    
    // If no final verdict from Trackator, derive from available data
    if (!calibration.finalVerdict) {
        calibration.finalVerdict = deriveVerdict(calibration);
        calibration.recommendedAction = deriveRecommendedAction(calibration);
    }
    
    return calibration;
}

// v2.1: Local classification fallback when no Trackator entry matches
function classifyFindingV21(finding, context) {
    // Use 6-class system from Fix D
    const classMapping = {
        'confirmed-vulnerability': { class: 'reachable-bug', minConfidence: 85 },
        'potential-vulnerability': { class: 'potential-bug', minConfidence: 60 },
        'false-positive': { class: 'false-positive', minConfidence: 0 },
        'by-design': { class: 'by-design', minConfidence: 0 },
        'informational': { class: 'proven-property', minConfidence: 30 },
        'cannot-determine': { class: 'insufficient-evidence', minConfidence: 0 }
    };
    
    // Calculate score based on available evidence
    let score = 50;  // Base uncertainty
    
    if (finding.trackatorEvidence?.matrixEntry) score += 15;
    if (finding.prerequisiteChain?.length >= 4) score += 10;
    if (finding.estimatedDifficulty === 'easy') score += 10;
    if (finding.trackatorEvidence?.source === 'criticalFindings[]') score += 15;
    
    // Determine class based on score and disproof result
    if (finding.disproofResult === 'DISPROVED') {
        return { class: 'false-positive', confidence: 10 };
    } else if (score >= 85) {
        return { class: 'reachable-bug', confidence: score };
    } else if (score >= 60) {
        return { class: 'potential-bug', confidence: score };
    } else if (score >= 30) {
        return { class: 'insufficient-evidence', confidence: score };
    } else {
        return { class: 'cannot-determine', confidence: score };
    }
}

// v2.1: Derive verdict when Trackator doesn't provide one
function deriveVerdict(calibration) {
    if (calibration.disproofResult === 'false-positive' || calibration.disproofResult === 'by-design') {
        return calibration.disproofResult;
    }
    
    if (calibration.classification === 'reachable-bug' && calibration.reachability === 'reachable') {
        if (calibration.proofRequirements.met >= 7) return 'confirmed-vulnerability';
        return 'potential-vulnerability';
    }
    
    if (calibration.classification === 'potential-bug' && calibration.confidenceBreakdown.overall >= 70) {
        return 'potential-vulnerability';
    }
    
    if (calibration.remainingUnknowns?.length > 3) {
        return 'cannot-determine';
    }
    
    return 'deferred';
}

// v2.1: Derive recommended action from verdict
function deriveRecommendedAction(calibration) {
    const actionMap = {
        'confirmed-vulnerability': 'immediate-fix',
        'potential-vulnerability': 'short-term-investigation',
        'false-positive': 'dismiss',
        'by-design': 'accept-risk',
        'cannot-determine': 'escalate-to-auditor',
        'deferred': 'defer'
    };
    
    return actionMap[calibration.finalVerdict] || 'defer';
}
```

