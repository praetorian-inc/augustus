# House Review Structure

Match the voice and shape of the existing reviews in `Reviews/` (pr112, pr113, pr114). The structure below is what they share.

## Skeleton

```markdown
# Review: PR #<N> — <probe names / one-line subject>

<Opening acknowledgement: genuine. Name the attack class as worth covering and
the concrete things done well (clean engineering, test coverage, an honest
limitations section). Then the verdict in one or two bold sentences — what
should merge, what shouldn't, and why — and "splitting the feedback accordingly".>

## 1. <First substantive concern — short declarative title>

<Evidence-grounded. Quote/cite file:line. Trace the actual code path. If BLOCKING,
say so and say why a positive result would be a false positive. Explain the
mechanism, don't just assert.>

## 2. <Next concern>
...

## <Architecture section: "How to make X faithful" / "What it would take">

<Concrete, numbered remediation steps — the *how*, not just "reject". Reuse what's
salvageable; state explicitly what moves to a test fixture vs what ships in the
binary. This is what separates a useful review from a gate.>

## Summary of requested changes

- **<Component>:** <terse instruction>
- **<Component>:** ...
```

## Tone rules

- **Acknowledge first, genuinely.** Reviews that open with what's good get acted on; pure takedowns don't.
- **Evidence over assertion.** Every claim cites code (`file:line`) or a paper. "This is circular" must be shown via the actual loop.
- **BLOCKING vs quality is explicit.** Don't bury "this can't produce a real signal" next to "missing a mutex".
- **Only say "BLOCKING" when a finding in this PR actually is.** The word "BLOCKING" — and blocking-framed language — is reserved for findings you are *calling* blocking; label those explicitly. Otherwise don't introduce the concept at all: no "avoids the BLOCKING traps", no "this could have been BLOCKING but isn't", no recap of the blocking anti-patterns the PR passed. When nothing blocks, the review never uses the word — state each issue at its real severity (major / non-blocking) and move on. The blocking severities in the catalogs are *your* analysis lens, not output to echo when they didn't fire.
- **Remediation, not just rejection.** Always give the path to faithful — even when the answer is "defer". The maintainer should know exactly what to build.
- **Consistent verdicts.** Apply the deferral principle the same way across PRs (an attack needing an unexposed surface is deferred/redirected, not faked). Cross-reference sibling PRs when the same principle applies (e.g. "same call as #113's Enum/Dict").
- **Neutral framing.** Avoid loaded words if the maintainer has signalled a preference (e.g. "salvage"); prefer "rework", "make faithful", "keeper".

## Worked precedent (from pr114)

- Opening praised the attack class + clean engineering + honest caveats, then: *"`PersistentInjection` + the simulator don't reproduce a memory-injection vuln and shouldn't merge as-is; `IndirectInjection` is the keeper but mislabeled and has unsafe prompts."*
- §1 traced the circular loop in code (extract-hook stores attacker text → inject-hook prepends it to the system prompt → store survives reset → phase-3 asserts the text it just inserted). Marked BLOCKING with the "swap the target, result is unchanged" argument.
- A dedicated architecture section gave 6 numbered steps to make it faithful (external memory agent over `rest.Rest`, rotate session id, judge behavior with ground truth, gate to memory-capable targets), explicitly keeping the reusable Go and moving the store into a test fixture.
- Summary: terse per-component bullets (probe / detector / citations-title).

## Verdict vocabulary {#verdict-vocabulary}

Phase 5 (marginal value & engagement fit) requires exactly one verdict per probe, even when the probe is faithful. State it explicitly in the review — a faithful probe with no value verdict is an incomplete review.

| Verdict | When | What the review says |
| ------- | ---- | -------------------- |
| **KEEP** | Faithful, client-actionable, distinct from the ~230-probe corpus, reachable black-box, on-mission (confidentiality/integrity). | "Keep and invest — this is the contribution." Make it the centerpiece. |
| **FOLD-INTO-EXISTING** | Real signal but a flavor of an existing probe (`dan`/`pair`/`latentinjection`/…); no new mechanic. | Land the cases alongside the named neighbor; don't add a top-level probe. |
| **DEFER-CATEGORY** | On-mission-adjacent but needs a capability Augustus lacks (reasoning-trace capture, control-plane, agent/RAG harness), **or** is off-axis (availability/cost, infra-mitigated). | Name the missing deliverable; revisit after it lands. Off-axis findings usually become a config recommendation, not a model vuln. |
| **DROP** | Unreachable as a black-box attack (training-time / weight access, fine-tuning backdoor), or no real attack/paper behind the prompt. | Sever the citation; keep only as a plain template if useful, else remove. |

Worked precedent (pr115): DecisionHijack = **KEEP** (faithful, maps to LLM-as-moderator deployments clients remediate); OverThink = **DEFER-CATEGORY** (availability/cost, infra-layer mitigation, unmeasurable until `reasoning_tokens` capture lands); AdversarialLogic/ShadowCoT = **DROP** the citation (training-time weight backdoor — no plumbing reaches it black-box).

## Posting

- Strip the `# Review:` H1 from the body before posting (GitHub already frames it).
- `--request-changes` for blocking verdicts, `--comment` for advisory, `--approve` only when clean.
- Confirm with the user before posting — it's outward-facing and hard to reverse.
