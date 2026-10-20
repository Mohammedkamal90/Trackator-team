# trackator-hunter

**Attacker-reasoning engine** for `trackator-walker` path output. Evaluates execution paths through **exploit construction thinking**, not pattern matching.

**Input:** `path-report.json` (branch-aware CFG path enumeration)
**Output:** Triage report with reasoned exploitation analysis and PoC blueprints

---

## Core Principle

> **"Don't ask 'does this match a known bug?' Ask 'how would I exploit this?'"**

This skill forces deep contextual reasoning over path data. Every conclusion must be backed by a **constructible attack narrative**, not a checkbox match.

---

## Evidence Discipline (MANDATORY)

> Never infer unseen facts. If the path report lacks direct evidence of price source, callback control, or privileged state resolution, write `INSUFFICIENT_DATA` instead of assuming an exploit.

Rules:
- Use only fields present in the path-report schema.
- If a fact is not directly present in the JSON, label it as `UNKNOWN` or `INSUFFICIENT_DATA`.
- Do not infer stale oracle provenance, callback control, or privileged state resolution unless the report explicitly shows it.
- `path_semantics` are triage hints, not proof of vulnerability.
- Do not classify a path as SAFE or HIGH without matching the conclusion to explicit evidence in the path data.

---

## The Attacker Persona

Adopt this mindset before analyzing any path:

```
I am an unprivileged EOA. I control:
  - msg.sender (my address)
  - All function parameters I can set
  - Transaction timing and sequencing
  - Any callback contracts I deploy

I cannot:
  - Modify contract code
  - Forge signatures (unless a bug lets me)
  - Access storage directly

My goal: Extract value, break invariants, or gain privileges I shouldn't have.
My method: Find paths where the code's assumptions about my capabilities are WRONG.
```

---

## Reasoning Protocol (MANDATORY for every path)

For each candidate path, execute this **exact reasoning chain** in order. Do not skip steps.

### Phase 1: Path Comprehension

Before any judgment, reconstruct the execution story:

```
STEP 1: Trace the route
  - List call_chain in order (who calls whom)
  - At each branch fork, note WHAT was decided and WHY it matters
  
STEP 2: Map the data flow  
  - What did this path READ from storage? (storage_reads)
  - What did this path WRITE to state? (delta_writes)  
  - Who did this path talk to externally? (external_calls)
  
STEP 3: Identify the trust assumptions
  - What does this path ASSUME about msg.sender?
  - What does this path ASSUME about external call return values?
  - What does this path ASSUME about state consistency?
```

**Output requirement:** Write a 2-3 sentence summary of "what this path does" before any analysis.

---

### Phase 2: Exploitation Reasoning (The 4 Lenses)

Apply each lens as a **thinking process**, not a checklist. For each lens, construct a hypothetical exploit and test if it holds together.

---

#### LENS 1: Pure Logic Flaw — "Can I get something for nothing?"

**Reasoning process:**

```
0. Check guard_kind/allow_arm/deny_reverts on every branch_fork FIRST,
   before inferring anything from condition text. guard_kind absent or
   'ordinary-if' means that branch never short-circuits anything — do
   not treat it as an authorization decision no matter what it compares.
   deny_reverts: false (only possible on 'guarded-if') means the fork's
   allow_arm BYPASSES a check rather than passing one — this is the
   reference incident's own shape and should immediately raise
   suspicion, not be re-derived from context.

1. Identify what value this path produces or modifies
   - Is it balance changes? Supply changes? Approval grants?
   
2. Trace what the path REQUIRES before producing that value
   - Does it verify payment occurred?
   - Does it check preconditions were met?
   - Does it validate the caller has right to this value?

3. Construct the "free lunch" attack:
   "If I call this path with [manipulated parameters], 
    the code will give me [value] without verifying [condition]."
    
4. Test the attack narrative for flaws:
   - Would the transaction revert? Why/why not?
   - Is there a check I'm missing that would stop me?
   - Does the state after my exploit make sense, or would it break something?

5. Historical analog:
   - Does this resemble ChannelsFinance (inflation attack)?
   - Does this resemble MahaLend (donate-to-inflate)?
   - What did those exploits teach us about this pattern?
```

**What to look for (as reasoning prompts, not matches):**

- *"The path writes to balances/supply but never reads a 'paid' or 'deposited' flag. If I call this directly, am I minting myself value?"*
- *"The path increments a reward counter but doesn't check if I actually earned it. Can I replay this?"*
- *"Two state variables are updated but only one was read. Is the other now inconsistent with reality?"*
- *"The path sets a flag (hasClaimed, isLocked) but I don't see where it would be unset. Can I only do this once, or can I loop?"*

**Classification threshold:**
- **HIGH:** You can construct a complete "I get X without doing Y" narrative that doesn't obviously fail
- **CONDITIONAL:** The narrative works but requires specific pre-existing state
- **SAFE:** Every value change is justified by a visible, verified precondition

---

#### LENS 2: Price Manipulation — "Can I lie about the price?"

**Reasoning process:**

```
1. Locate price-dependent decisions in this path
   - Which branch forks use price/oracle variables in conditions?
   - Which delta_writes compute their values from price inputs?
   
2. Analyze the price source
   - Where did the price come from? (storage variable, external call, parameter?)
   - If storage: when was it last written? (Not in this path = potentially stale)
   - If external call: can I influence that contract's return value?
   - If parameter: I control it completely — is it trusted?

3. Construct the manipulation narrative:
   "The path uses [price_source] to decide [critical_action].
    If I make [price_source] return [manipulated_value] in the same transaction,
    the path will [action that benefits me] based on false pricing."

4. Evaluate manipulation feasibility:
   - Flash loan scenario: Can I move market price in one tx via large DEX trade?
   - Sandwich scenario: Can I front-run with manipulation, back-run with profit?
   - Stale oracle: Was price set long ago and no longer accurate?
   - Single-source: Is there no twap/secondary check to catch manipulation?

5. Assess the profit extraction:
   - After manipulating price into my favor, what do I extract?
   - Is the extraction amount proportional to manipulation magnitude?
   - Would the profit cover gas + flash loan fees?

Historical context:
   - MonoX Finance: Manipulated price in own pool, drained treasury
   - Cream Finance (twice): Flash-loan-borrowed, manipulated oracle, undercollateralized withdrawal
   - Moonwell (2025): Faulty oracle accepted manipulated price
```

**Reasoning prompts:**

- *"This path reads spotPrice from storage but never updates it. If I manipulated spotPrice an hour ago and it's still there, what happens?"*
- *"The only price check is `require(spotPrice > threshold)`. There's no twap, no secondary source. If I temporarily spike spotPrice via a DEX swap, will this path let me act on the fake price?"*
- *"Between reading the price and acting on it, there's an external call. Can I use that callback to change the price?"*
- *"The path sends tokens based on a calculated exchangeRate. If I manipulate what exchangeRate reads, how much extra can I extract?"*

---

#### LENS 3: Reentrancy & Execution Order — "Is there a window where state is wrong?"

**Reasoning process:**

```
1. Map the exact operation sequence
   - Order all operations: reads → branches → writes → external calls
   - Note positions: which comes first, which comes last?

2. Identify "dangerous orderings"
   Classic pattern (THE checks-effects-interactions violation):
     a. External call happens
     b. State update happens AFTER
     → Window exists between (a) and (b) where state is stale
   
3. Construct the reentrancy narrative:
   "Step 1: I call [function], it reaches [external_call] 
    Step 2: In my callback, I call [function] AGAIN
    Step 3: The second invocation sees OLD state (hasn't updated yet)
    Step 4: I can [extract value] again because the balance/flag hasn't changed"

4. Test reentrancy feasibility:
   - Is the external call target something I control? (parameter, my contract)
   - Is there a reentrancy guard (mutex, boolean lock) checked in this path?
   - Does the second invocation actually profit me, or would it revert?
   - How deep can I recurse before gas/runout?

5. Non-classic ordering issues (beyond simple reentrancy):
   - State read → external call → state write using STALE read value
   - Two writes that should be atomic but aren't (partial update window)
   - Event emission before state commit (front-running on event data)

Historical context:
   - Visor Finance: Reentrancy in stake/unstake
   - Cream Finance (Aug 2021): Flash loan + reentrancy combo
   - Grim Finance: Flash loan + reentrancy across multiple functions
```

**Reasoning prompts:**

- *"I see an external call at [position] and a balance update at [later position]. If my callback re-calls this function, what does it see?"*
- *"The path reads balances[msg.sender], then calls an external address, then writes to balances[msg.sender]. What if the external call invokes this same path?"*
- *"There's no 'locked' variable in storage_reads. Nothing prevents me from entering again while inside."*
- *"Even if I can't reenter, the state between [operation A] and [operation B] is inconsistent. Can anyone else observe and act on that inconsistency?"*

---

#### LENS 4: Arbitrary External Calls — "Who am I really talking to?"

**Reasoning process:**

```
1. For each external_call in the path, determine target origin
   - Fixed address? (protocol contract, DEX router — lower risk)
   - Storage-derived? (read from state — can I influence what's stored?)
   - Parameter? (caller controls — HIGH risk)
   - msg.sender? (I AM the caller — I control this)

2. Analyze execution context implications
   - Regular call: Target can call back into this contract
   - Delegatecall: Target runs IN THIS CONTRACT's context (CRITICAL)
   - Staticcall: Target can't modify state but return value might be trusted
   
3. Construct the hijacking narrative:
   "The path calls [target] with [data/value/context].
    Because I control [how target is determined],
    I can make it [malicious action]."

4. Evaluate hijack impact:
   - Delegatecall to my contract: I can write YOUR storage = I become the contract
   - Call with value: I can drain ETH sent to my address
   - Callback during execution: I can reenter or manipulate mid-transaction
   - Return value influence: If return value gates logic, I control the gate

Historical context:
   - Rubic: Arbitrary external call vulnerability
   - UniBotRouter / MaestroRouter: Router callback exploitation
   - Gnosis Safe (your example): Module called attacker-controlled executor
```

**Reasoning prompts:**

- *"The external call target is a function parameter. I can point this at MY contract. What happens when my contract gets called with the contract's context/msg.value?"*
- *"This is a delegatecall to a user-supplied address. That address's code runs AS IF it's inside this contract. Can I write to owner/admin/storage variables?"*
- *"The path trusts the return value of this external call. What if I always return true? What if I return a manipulated number?"*
- *"Between setting up this call and processing the result, what state has been committed? What hasn't?"*

---

### Phase 3: Synthesis & Classification

After applying all 4 lenses, synthesize into one classification:

```
FOR EACH PATH, produce this EXACT structure:

## PATH-{ID}: {Entrypoint}

### Execution Story (2-3 sentences)
[What the path does, in plain language]

### Attacker Reasoning (per lens)

**Logic Flaw Analysis:**
[Narrative: "If I were attacking this, I would try..."]
[Verdict: Feasible / Not feasible / Uncertain, with why]

**Price Manipulation Analysis:**
[Narrative: "The price dependency here is..."]
[Verdict: Exploitable / Not exploitable / N/A]

**Reentrancy / Ordering Analysis:**
[Narrative: "The operation sequence creates a window where..."]
[Verdict: Vulnerable / Safe / Needs deeper review]

**External Call Analysis:**
[Narrative: "When this path calls out to..."]
[Verdict: Controllable / Safe / Context-dependent]

### Final Classification
🔴 HIGH / 🟡 CONDITIONAL / 🟢 SAFE / `INSUFFICIENT_DATA`

**Decision rule:**
- `HIGH`: path data directly supports a concrete exploit narrative
- `CONDITIONAL`: exploit is plausible but depends on missing or external preconditions
- `SAFE`: explicit invariant + explicit blocked transition proven by the path data
- `INSUFFICIENT_DATA`: required fact is absent from the path report, so an exploit cannot be validated from the evidence supplied

### Safe classification hard guard
A path may be marked `SAFE` only if:
1. the invariant is explicitly stated,
2. the attacker’s required state transition is explicitly described,
3. the path data shows why that transition is blocked,
4. no missing fact is required to complete the exploit story.

If any required fact is missing, classify as `INSUFFICIENT_DATA` or `CONDITIONAL`, not SAFE.

### Historical analogy gate
Historical analogies are allowed only when the causal mechanism in the path data directly matches the historical attack mechanism.
- If the path does not show the same state transition, value flow, or callback pattern, do not draw the analogy.
- If mechanism is not present, say: `Historical analogy not applicable: mechanism mismatch.`

### Exploit Construction (if `HIGH`, `CONDITIONAL`, or `INSUFFICIENT_DATA`)
[Step-by-step: what attacker does, in what order, with what parameters]
[What prevents this exploit from working? (if anything)]
[What would a PoC need to demonstrate?]
```

---

## Anti-Patterns (FORBIDDEN)

❌ **DO NOT** output these:
- "Pattern matched: [regex-like description]"
- "Flagged because [checkbox item] triggered"
- "Similar to [CVE]" without explaining the reasoning connection
- Binary yes/no without narrative justification
- Classification without an explicit exploit construction attempt
- Historical analogy used without mechanism match

✅ **DO** output these:
- "I attempted to construct an exploit by..." (show your work)
- "The assumption that breaks here is..." (identify fragile assumptions)
- "An attacker would need to... which is feasible because..." (narrative chain)
- "Historical analogy not applicable: mechanism mismatch." (grounded refusal)
- "I classified as SAFE because I tried to exploit it and here's why it failed" (proof of analysis)

---

## Insufficient Evidence Block (MANDATORY for `INSUFFICIENT_DATA`)

If the report does not supply the required facts, produce this exact structure:

```markdown
## Path {ID}: {Entrypoint}

**Verdict:** `INSUFFICIENT_DATA`

**Missing Evidence:**
- Missing fact 1: what is absent from the path report
- Missing fact 2: what is absent from the path report
- Missing fact 3: what is absent from the path report

**Why this matters:**
The current path report does not provide enough evidence to prove or disprove the exploit narrative. Without [missing fact], the transition cannot be validated from the data supplied.

**What would resolve the uncertainty:**
- additional call trace / branch trace / state write sequence
- explicit storage provenance for the relevant values
- direct evidence of callback or privilege source
- full execution ordering across the relevant transaction sequence
```

---

## Output Report Structure

```markdown
# trackator-hunter Analysis Report

**Target:** {protocol}
**Analyzed:** {timestamp}
**Path Data:** {N} entrypoints, {M} paths, {K} flagged for deep review

## Executive Summary

| Classification | Count | Paths | Primary Vector |
|---------------|-------|-------|----------------|
| 🔴 High Confidence | {n} | {ids} | {which lens caught it} |
| 🟡 Conditional | {n} | {ids} | {what precondition needed} |
| 🟢 Safe / Benign | {n} | {ids} | {why it looked suspicious} |
| `INSUFFICIENT_DATA` | {n} | {ids} | {what fact is missing} |

## Detailed Analysis

{Per-path reasoning following Phase 1-3 template above}

## Cross-Cutting Concerns

(If multiple paths share the same weakness, summarize once here)

## Recommended Verification

For each 🔴 finding:
1. Foundry PoC priority: {High/Medium/Low}
2. Mainnet fork feasibility: {Which network, what block}
3. Manual review focus: {What human auditor should check}

---
*Generated by trackator-hunter v2.0 — Reasoning-first path analysis*
```

---

## Integration Notes

### Pipeline Position

```
trackator-walker (mechanical enumeration)
       ↓
   path-report.json (structured path data)
       ↓
trackator-hunter (THIS SKILL - attacker reasoning)
       ↓
   Triaged shortlist with exploit narratives
       ↓
Manual audit / x-ray / Foundry PoC (confirmation)
```

### When to Invoke

Run when `path-report.json` exists AND any of:
- `bypasses_state_check == true` found
- `is_zero_storage_read_auth == true` found
- External calls to non-fixed addresses found
- Price/oracle variables in branch conditions
- External calls before state writes (reentrancy-prone ordering)

### Known Limitations of Reasoning Approach

- **Cannot prove impossibility** — reasoning finds plausible exploits, not proofs of safety
- **Assumes attacker capability** — may overestimate risk if certain actions are infeasible on-chain
- **Static blind spots** — cannot observe runtime values, only reason about them
- **Historical bias** — may miss novel attack classes not in training data

**Mitigation:** Classify as CONDITIONAL when uncertain. Never classify as SAFE without attempting to construct an exploit and documenting why it fails. If the report does not contain the facts needed to prove a transition is blocked, default to `INSUFFICIENT_DATA` rather than assuming safety.

---

## Quick Reference Card

```
INPUT:  Full path context (branch_forks, storage_reads, 
        delta_writes, external_calls, call_chain)
OUTPUT: Reasoned exploitation analysis per path

4 REASONING LENSES (think, don't match):

1. LOGIC FLAW:     "Can I get value without paying cost?"
2. PRICE MANIP:   "Can I lie about what things are worth?"
3. REENTRANCY:    "Is there a moment where state is wrong?"
4. EXT CALLS:     "Who am I really talking to?"

FOR EACH LENS:
  → Construct exploit narrative
  → Test narrative for flaws
  → Compare to historical attacks
  → Conclude: Feasible / Not feasible / Uncertain

CLASSIFICATION RULE:
  `HIGH` = concrete exploit data + direct causal path
  `CONDITIONAL` = exploit plausible but needs extra state/trace facts
  `SAFE` = invariant + blocked transition proven by the path data
  `INSUFFICIENT_DATA` = required fact absent from the report
  Nothing else is valid
```

---
*v2.1 | Reasoning-first paradigm | Compatible: trackator-walker v0.1+ (guard_kind/allow_arm/deny_reverts require the version with serialized guard-shape fields in branch_forks)*
