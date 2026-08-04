"use strict";
// ============================================================
// TRACKATOR Tier 3 - State Diff Engine
// Computes state differences from trace data
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeStateDiffs = computeStateDiffs;
exports.compareTraces = compareTraces;
exports.generateStateDiffSummary = generateStateDiffSummary;
/**
 * Compute state diffs from trace execution
 */
function computeStateDiffs(trace, options = {}) {
    const { inventories, alertRules, verbose = false } = options;
    if (verbose)
        console.log('Computing state differences...');
    const diffs = [];
    const processedAddresses = new Set();
    // Process each trace step to collect storage changes
    for (const step of trace.trace) {
        if (processedAddresses.has(step.address))
            continue;
        processedAddresses.add(step.address);
        const diff = computeSingleContractDiff(step, trace, inventories?.get(step.contractName || ''));
        if (diff) {
            diffs.push(diff);
        }
    }
    // Check for anomalies based on alert rules
    if (alertRules && alertRules.length > 0) {
        checkForAnomalies(diffs, alertRules);
    }
    return diffs;
}
/**
 * Compute diff for a single contract's execution
 */
function computeSingleContractDiff(step, _trace, inventory) {
    // Extract storage changes from this step and its subcalls
    const slotChanges = extractSlotChanges(step, inventory);
    // If no changes found, skip
    if (slotChanges.length === 0)
        return null;
    // Compute balance changes
    const balanceChange = computeBalanceChange(step);
    return {
        address: step.address,
        contract: step.contractName || 'Unknown',
        contractName: step.contractName || 'Unknown',
        slotChanges,
        balanceChange,
        codeChanged: false, // Would need pre/post code comparison
        nonceChanged: false // Would need nonce tracking
    };
}
/**
 * Extract storage slot changes from a trace step
 */
function extractSlotChanges(step, inventory) {
    const changes = [];
    // Direct storage changes in this step
    if (step.storageAfter) {
        for (const [slotHex, value] of Object.entries(step.storageAfter.slots)) {
            const beforeValue = step.storageBefore?.slots[slotHex] || '0x0';
            const change = {
                slot: slotHex,
                afterValue: value,
                beforeValue,
                changeType: determineChangeType(beforeValue, value),
                deviation: calculateDeviation(beforeValue, value)
            };
            // Try to label the slot using inventory
            if (inventory) {
                const slotNum = parseInt(slotHex, 16);
                const varInfo = findVariableBySlot(inventory, slotNum);
                if (varInfo) {
                    change.slotLabel = `${varInfo.variable.name}: ${varInfo.variable.type}`;
                    // Decode values if we have type info
                    try {
                        change.decodedBefore = decodeStorageValue(beforeValue, varInfo.typeInfo, varInfo.offset);
                        change.decodedAfter = decodeStorageValue(value, varInfo.typeInfo, varInfo.offset);
                    }
                    catch (e) {
                        // Keep hex values if decoding fails
                    }
                }
            }
            changes.push(change);
        }
    }
    // Recurse into subcalls
    if (step.subcalls) {
        for (const subcall of step.subcalls) {
            const subChanges = extractSlotChanges(subcall, inventory);
            changes.push(...subChanges);
        }
    }
    return changes;
}
/**
 * Determine type of change between two values
 */
function determineChangeType(before, after) {
    const beforeClean = normalizeHex(before);
    const afterClean = normalizeHex(after);
    if (afterClean === '0x' + '0'.repeat(64) || afterClean === '0x0') {
        return 'cleared';
    }
    if (beforeClean === afterClean) {
        return 'unchanged';
    }
    if (beforeClean === '0x' + '0'.repeat(64) || beforeClean === '0x0') {
        return 'set';
    }
    return 'modified';
}
/**
 * Calculate percentage deviation for numeric values
 */
function calculateDeviation(before, after) {
    try {
        const beforeBig = BigInt(normalizeHex(before) || '0x0');
        const afterBig = BigInt(normalizeHex(after) || '0x0');
        if (beforeBig === 0n) {
            return afterBig > 0n ? Infinity : 0;
        }
        const deviation = Number((afterBig - beforeBig) * 100n / beforeBig);
        return Math.abs(deviation);
    }
    catch {
        return undefined;
    }
}
/**
 * Compute balance changes (ETH and tokens)
 */
function computeBalanceChange(step) {
    // ETH balance would need external tracking - simplified here
    const ethChange = {
        before: '0',
        after: '0',
        delta: '0'
    };
    // Extract token transfers from logs/events
    const tokenChanges = extractTokenTransfers(step);
    return {
        eth: ethChange,
        tokens: tokenChanges
    };
}
/**
 * Extract token transfer information from trace
 */
function extractTokenTransfers(step) {
    const transfers = [];
    // This would need log analysis or event decoding
    // For now, look for known patterns in subcalls
    if (step.subcalls) {
        for (const subcall of step.subcalls) {
            // Check for ERC20 transfer patterns
            const input = subcall.input.toLowerCase();
            if (input.startsWith('0xa9059cbb')) { // transfer(address,uint256)
                const toAddress = `0x${input.slice(34, 74)}`;
                const amount = `0x${input.slice(74, 138)}`;
                transfers.push({
                    token: subcall.address,
                    symbol: undefined, // Would need lookup
                    before: 'unknown',
                    after: 'unknown',
                    delta: amount
                });
            }
            // Recurse for nested transfers
            transfers.push(...extractTokenTransfers(subcall));
        }
    }
    return transfers;
}
/**
 * Find variable by slot number using inventory
 */
function findVariableBySlot(inventory, slot) {
    for (const item of inventory.variables) {
        if (item.computedSlot === slot) {
            return item;
        }
    }
    return null;
}
/**
 * Basic storage value decoder
 */
function decodeStorageValue(hexValue, typeInfo, offset) {
    const cleanHex = normalizeHex(hexValue || '0x0');
    const padded = cleanHex.padStart(64, '0').slice(2); // Remove 0x, pad to 64 chars
    try {
        const bigint = BigInt('0x' + padded);
        // Handle different type categories
        switch (typeInfo?.category) {
            case 'value':
                if (typeInfo.staticSize <= 32) {
                    // Signed interpretation for smaller types
                    const maxVal = BigInt(2) ** BigInt(typeInfo.staticSize * 8);
                    const halfPoint = BigInt(2) ** BigInt(typeInfo.staticSize * 8 - 1);
                    if (bigint >= halfPoint) {
                        return Number(bigint - maxVal);
                    }
                    return Number(bigint);
                }
                return bigint.toString();
            case 'mapping':
                return `<Mapping at ${cleanHex}>`;
            default:
                return cleanHex;
        }
    }
    catch {
        return cleanHex;
    }
}
function normalizeHex(value) {
    if (!value)
        return '0x0';
    let cleaned = value.startsWith('0x') ? value.slice(2) : value;
    cleaned = cleaned.padStart(64, '0');
    return `0x${cleaned}`;
}
/**
 * Check computed diffs against alert rules for anomalies
 */
function checkForAnomalies(diffs, alertRules) {
    for (const diff of diffs) {
        for (const slotChange of diff.slotChanges) {
            // Check each rule that might apply
            for (const rule of alertRules) {
                const anomaly = evaluateRule(rule, slotChange, diff);
                if (anomaly) {
                    slotChange.anomaly = anomaly;
                }
            }
        }
    }
}
/**
 * Evaluate an alert rule against a specific state change
 */
function evaluateRule(rule, slotChange, _diff) {
    // Skip disabled rules
    if (rule.enabled === false)
        return null;
    const condition = rule.condition;
    if (!condition)
        return null;
    // Get the value to check
    let checkValue;
    switch (condition.field) {
        case 'deviation':
            checkValue = slotChange.deviation;
            break;
        case 'changeType':
            checkValue = slotChange.changeType;
            break;
        default:
            // Try to match against slot label
            if (slotChange.slotLabel?.toLowerCase().includes(condition.field.toLowerCase())) {
                checkValue = slotChange.decodedAfter;
            }
            else {
                return null; // Rule doesn't apply to this field
            }
    }
    // Evaluate condition
    let triggered = false;
    switch (condition.operator) {
        case 'gt':
            triggered = typeof checkValue === 'number' && checkValue > (condition.value ?? 0);
            break;
        case 'gte':
            triggered = typeof checkValue === 'number' && checkValue >= (condition.value ?? 0);
            break;
        case 'lt':
            triggered = typeof checkValue === 'number' && checkValue < (condition.value ?? 0);
            break;
        case 'eq':
            triggered = checkValue === condition.value;
            break;
        case 'neq':
            triggered = checkValue !== condition.value;
            break;
        case 'changed':
            triggered = slotChange.changeType !== 'unchanged';
            break;
        case 'not-changed':
            triggered = slotChange.changeType === 'unchanged';
            break;
    }
    if (triggered) {
        return {
            detected: true,
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            message: generateAnomalyMessage(rule, slotChange),
            context: {
                address: _diff.address,
                contract: _diff.contractName,
                slot: slotChange.slot,
                slotLabel: slotChange.slotLabel,
                before: slotChange.decodedBefore || slotChange.beforeValue,
                after: slotChange.decodedAfter || slotChange.afterValue,
                deviation: slotChange.deviation
            },
            suggestion: rule.mitigation
        };
    }
    return null;
}
function generateAnomalyMessage(rule, slotChange) {
    const label = slotChange.slotLabel || `slot ${slotChange.slot}`;
    const before = slotChange.decodedBefore || slotChange.beforeValue;
    const after = slotChange.decodedAfter || slotChange.afterValue;
    return `[${rule.name}] Anomalous change detected in ${label}: ${before} → ${after} (deviation: ${slotChange.deviation}%)`;
}
/**
 * Compare two traces and produce differential analysis
 */
function compareTraces(baseline, current, options = {}) {
    const baselineDiffs = computeStateDiffs(baseline, options);
    const currentDiffs = computeStateDiffs(current, options);
    // Find differences between the two sets of diffs
    const differentialDiffs = [];
    for (const currentDiff of currentDiffs) {
        const baselineDiff = baselineDiffs.find(d => d.address === currentDiff.address);
        if (!baselineDiff) {
            // New contract touched
            differentialDiffs.push(currentDiff);
            continue;
        }
        // Compute what changed since baseline
        const newSlotChanges = currentDiff.slotChanges.filter(currentSlot => {
            const baselineSlot = baselineDiff.slotChanges.find(s => s.slot === currentSlot.slot);
            if (!baselineSlot)
                return true; // New slot changed
            // Value changed differently than baseline
            return currentSlot.afterValue !== baselineSlot.afterValue;
        });
        if (newSlotChanges.length > 0) {
            differentialDiffs.push({
                ...currentDiff,
                slotChanges: newSlotChanges
            });
        }
    }
    return differentialDiffs;
}
/**
 * Generate summary statistics from state diffs
 */
function generateStateDiffSummary(diffs) {
    let totalSlotsChanged = 0;
    let significantChanges = 0;
    let anomaliesFound = 0;
    const contractsByChangeCount = [];
    for (const diff of diffs) {
        totalSlotsChanged += diff.slotChanges.length;
        for (const slot of diff.slotChanges) {
            if (slot.deviation && slot.deviation > 10) { // More than 10% change
                significantChanges++;
            }
            if (slot.anomaly?.detected) {
                anomaliesFound++;
            }
        }
        contractsByChangeCount.push({
            contract: diff.contractName || diff.address,
            changes: diff.slotChanges.length
        });
    }
    // Sort by most changes
    contractsByChangeCount.sort((a, b) => b.changes - a.changes);
    return {
        totalContractsTouched: diffs.length,
        totalSlotsChanged,
        significantChanges,
        anomaliesFound,
        contractsByChangeCount
    };
}
//# sourceMappingURL=state-diff-engine.js.map