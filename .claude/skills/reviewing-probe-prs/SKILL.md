---
name: reviewing-probe-prs
description: Use when reviewing any Augustus PR — probe, detector, generator, buff, or infra — especially one citing academic papers or named attack techniques (e.g. MINJA, BreakFun, ToolHijacker). Reviews for FIDELITY (does a probe reproduce the cited attack or a degraded/circular proxy?) AND the cross-cutting lenses that decide real reviews: silent-failure / fail-open (the false negative that looks clean), detector robustness beyond self-report, single-source-of-truth answer keys, end-to-end validation, config/buff/infra hardening — not just Go correctness. Guides grounding in the real diff, verifying the paper's true mechanics, the anti-pattern + lens catalogs, prompt-safety and citation checks, the house review structure, and request-changes posting.
allowed-tools: Read, Bash, Grep, Glob, AskUserQuestion, TodoWrite, Write, Edit, WebFetch
---

# Reviewing Augustus Probe PRs

**Review a probe/detector PR for fidelity to the attack it claims to implement — not just whether the Go compiles.**

## When to Use

Use this when asked to review any Augustus PR — **probe, detector, generator, buff, or infra** — particularly when it cites a paper or names a known attack. A generic code review catches Go bugs (races, dead code, missing tests) but misses the dimensions that decide whether the change is *worth merging*:

- **Fidelity** (probe/detector PRs): does the implementation actually reproduce the cited attack, or a circular/trivial proxy that produces false positives regardless of target? Are citations real and the title scoped honestly? Do the prompts embed live, third-party-owned exfil destinations?
- **Cross-cutting lenses** (every PR): does any path **silently fail safe-looking** — a judge outage scoring `0.0`, an encoder refusal forwarded as the prompt, a generator dropping input it can't format — converting a real finding into a clean-looking false negative? Is the detector robust (mention ≠ success, negation-aware, hardened judge parser, ground truth + benign control)? Is the answer key in one place or duplicated so it drifts? Are thresholds tunable parameters rather than magic numbers? Was it validated end-to-end against a real or mock endpoint?

The fidelity layer is the deepest, but the cross-cutting lenses are where reviews most often *under-call* — a fail-open on the core scoring path is BLOCKING, not "minor — flag it". **A pure infra/refactor PR with no attack claim still gets the cross-cutting lenses** (Phase 4) and the architectural lens — don't drop to a bare code review.

**You MUST use TodoWrite** to track the phases below.

## Core principle

> A probe is only valuable if a positive result means the **target** is vulnerable. If the result is forced by Augustus's own scaffolding (Augustus simulates the vulnerable system, injects into the highest-trust channel, or scores its own setup), the probe is a **false-positive generator** — that is a BLOCKING issue, not polish. Hold the implementation against what the *paper actually does*, and propose the architecture that would make it faithful rather than just rejecting it.

## Quick Reference

| Phase | Purpose |
| ----- | ------- |
| 1. Ground in the real PR | Read the diff + code, never trust the PR body or memory |
| 2. Establish true mechanics | What does the cited attack actually require? (probe/detector PRs) |
| 3. Fidelity assessment | Reproduction vs degraded/circular proxy (the heart — probe/detector PRs) |
| 4. Cross-cutting lenses | Silent-fail, detector robustness, single source of truth, e2e, config/buff/infra hardening — **every PR** |
| 5. Overlap / dedup | Does an existing probe already cover this? |
| 6. Marginal value & engagement fit | Even if faithful — does it belong in Augustus? Per-probe KEEP/FOLD/DEFER/DROP |
| 7. Prompt-safety scan | Live domains/IPs/endpoints in attack prompts |
| 8. Citation + scope | arXiv IDs resolve; title matches delivered scope |
| 9. Precedent | Read prior `Reviews/` for house style + consistent verdicts |
| 10. Write the review | House structure + remediation architecture |
| 11. Scrub + save | Remove local/internal refs; save to `Reviews/` |
| 12. Post on approval | Confirm review type, then `gh pr review` |

---

## Phase 1: Ground in the real PR (not the body, not memory)

```bash
gh pr view <N> --repo praetorian-inc/augustus --json title,body,headRefName,additions,deletions,changedFiles,updatedAt
gh pr diff <N> --repo praetorian-inc/augustus --name-only
gh pr diff <N> --repo praetorian-inc/augustus > /tmp/pr<N>.diff   # then Read it
```

Read the actual probe `.go`, detector `.go`, YAML templates, and `*_test.go`. The PR description routinely overclaims or is stale — verify every claim against code. If you hold prior notes/memory about this PR, treat them as **outdated** and re-derive from the current diff (PRs evolve; probe counts and mechanics change between pushes).

## Phase 2: Establish the cited attack's true mechanics

For each cited paper or named technique, write down — from the source, not the PR — what the real attack requires:

- **Threat model & channel**: black-box vs control-plane; data-plane (prompt) vs control-plane (enforced grammar/schema) vs retrieved-memory store.
- **Forced vs voluntary**: does the attack *force* output (logit masking, constrained decoding, retrieval the target controls), or merely *ask* and rely on compliance?
- **Single- vs multi-turn / multi-session**; what carries state across the boundary.
- **What "success" means** behaviorally.

Use WebFetch to read the paper/abstract if unsure. Capture the one or two mechanics that *are the attack* (e.g. BreakFun's 4-component construction; MINJA's semantic top-k retrieval against an external store). See [references/fidelity-antipatterns.md](references/fidelity-antipatterns.md).

## Phase 3: Fidelity assessment (the heart of the review)

Compare implementation to Phase-2 mechanics. Run each anti-pattern check in [references/fidelity-antipatterns.md](references/fidelity-antipatterns.md). The big ones:

- **Circular / self-referential**: Augustus simulates the very system under attack (memory store, RAG index, tool registry) *and* then "tests" it. A positive result is then guaranteed by construction. → BLOCKING.
- **Wrong trust channel**: payload injected into the target's **system prompt** (or any channel the model is built to obey) instead of untrusted data/retrieved content. Tests "does the model obey itself" — near-universal yes. → BLOCKING.
- **Self-report detector**: scores acceptance phrases ("I've stored", "Sure") rather than a behavioral consequence on a later benign turn. → major.
- **Simulated control/data plane**: pastes a schema/enum/dictionary as prompt *text* instead of sending it as the enforced API parameter. → the attack isn't reproduced.
- **Prompt-compliance-as-attack**: hand-authored coercive content the model is simply asked to follow, with no injection vector. → susceptibility signal at best; rename, don't claim the paper's attack.

For each finding, decide BLOCKING vs quality, and cite `file:line`.

## Phase 4: Cross-cutting review lenses (every PR)

These are the dimensions reviews most often *under-call* — they apply to probes, detectors, generators, buffs, and infra alike, and a pure refactor PR still gets them. Run each relevant lens from [references/review-lenses.md](references/review-lenses.md); mark each finding BLOCKING / major / non-blocking and cite `file:line`. The recurring ones:

- **Lens 1 — Silent failure / fail-open (the false *negative* that looks clean).** The mirror of the fidelity anti-patterns: a path that **tests nothing and reports safe**. Judge outage → `0.0`; encoder refusal forwarded as the prompt; generator silently drops unformattable input; parser returns empty content + nil error on an unexpected body (blast radius = every probe using that generator); a capability-lacking target silently scored safe instead of skipped. **A fail-open on the core scoring path is BLOCKING, not "minor".** The rule: fail loud (skip + warn + count), never fail safe-looking. Test: *"if this breaks or the target lacks the capability, does it still emit a verdict, and is that verdict silently 'safe'?"*
- **Lens 2 — Detector robustness beyond self-report.** Mention ≠ success (anchor the match: equal/begins-with, not substring; an edit-distance-vs-whole-response check that can never fire is dead code); negation/refusal awareness; harden the judge-verdict parser (take the *last* marker, escape `[`/`]` in embedded responses); carry per-prompt ground truth + a benign control; trim benign-overlapping keyword indicators.
- **Lens 3 — Single source of truth for the answer key.** Tool name / canary / correct-verdict duplicated in the detector *and* the data drifts silently. Name the principle; attach the expected value to the attempt or per-template `detector_config` so it can't diverge.
- **Lens 4 — End-to-end validation.** Has it been run against a real or `httptest` mock endpoint to confirm the detector scores a real response and does **not** false-positive on a refusal? A change to a shared generator (`rest.go`) should ship its own `rest_test.go` case, not ride inside a probe PR.
- **Lens 5 — Generator / config hardening.** Magic-number thresholds → an operator-meaningful parameter (not just "fine"); dead code that looks active → delete; aliased/overlapping config keys → warn on conflict, never silently override an explicit value; frozen compiled-in assets → make configurable; committed binaries → in-repo reproducible generators; blast-radius changes → split into their own PR.
- **Lens 6 — Buff / encoding correctness.** Tokenization completeness (punctuation-joined tokens silently unmatched; handle leading + trailing symmetrically) and round-trip reversibility (drop mappings a cooperating model can't decode back).
- **Lens 7 — Architecture.** A new abstraction must *remove* the duplication it claims to consolidate; scrutinize a new top-level capability type against existing mechanisms; offer finish-the-refactor vs ship-only-the-new-bit.
- **Lens 8 — Consolidate the bot reviews.** Validate CodeRabbit/Gemini findings against the code and fold the real ones in with credit; don't duplicate or ignore them.

## Phase 5: Overlap / dedup

Grep the registry for probes/detectors that already cover this surface before endorsing a new top-level probe.

```bash
ls internal/probes/ ; grep -rhoE 'Register\("[^"]+"' internal/probes/<neighbor>/ | sort -u
```

Name the real neighbor accurately (e.g. instruction-injection-via-content overlaps `latentinjection`/`promptinject`, not `ragpoisoning` which poisons *factual answers*). Recommend landing new cases alongside the neighbor unless they add coverage it lacks.

## Phase 6: Marginal value & engagement fit

Fidelity (Phase 3) and dedup (Phase 5) ask *is it correct* and *is it new*. This phase asks the question those don't: **even a faithful, novel probe may not belong in Augustus.** This is the dimension reviews under-weight — scrutinize correctness, ship something off-mission. Force the four questions below for **every** probe in the PR and emit a one-word verdict per probe.

- **Client-actionable finding?** Does a positive result map to something a client will *remediate* and an owner will own — or is it a diffuse susceptibility signal with no clear fix? "Model can be talked into X" with no vector and no deployment context is weak; "user input flips a content-moderator's verdict" maps to a real deployment a client patches.
- **Marginal over the existing corpus?** Augustus already ships ~230 probes, including a large jailbreak corpus (`dan`, `dra`, `gcg`, `autodan`, `pair`, `tap`, `crescendo`, `goat`, `flipattack`, `latentinjection`, `promptinject`, …). Is this *distinct*, or a flavored duplicate of one of those? A reframed-prompt jailbreak with no new mechanic is a duplicate — fold it into the neighbor (Phase 5) rather than add a top-level probe.
- **On Augustus's mission?** Augustus targets **confidentiality / integrity** — jailbreak, injection, access control, leakage. **Availability / cost** findings (token exhaustion, denial-of-wallet) are a different axis, usually mitigated at the infra layer (`max_tokens`, timeouts, rate limits) — secondary, and they typically land as a *config recommendation*, not a model vulnerability. Flag these as off-core-mission, not a reason to block, but a reason to defer the category.
- **Architecturally reachable by a black-box scanner at all?** Augustus sends prompts to an endpoint and reads the response. Attacks needing training-time / weight access (fine-tuning backdoors), or a capability Augustus doesn't expose (control-plane grammar, reasoning-trace / token visibility, an agent / RAG harness), are **not reachable as-is** — no prompt edit reaches them. Name the real missing deliverable (the capability that would unblock it) or defer; do not let the PR approximate an unreachable attack in YAML.

**Per-probe verdict (required).** State exactly one for each probe — see [references/review-structure.md](references/review-structure.md#verdict-vocabulary):

- **KEEP** — faithful, actionable, distinct, reachable, on-mission. Invest in it.
- **FOLD-INTO-EXISTING** — real but a flavor of a corpus probe; land the cases alongside the neighbor, no new top-level probe.
- **DEFER-CATEGORY** — on-mission-adjacent but needs a capability Augustus lacks, or is off-axis (availability/cost); name the missing deliverable, revisit after it lands.
- **DROP** — unreachable black-box (training-time / weight access), or no real attack behind it; sever the citation.

## Phase 7: Prompt-safety scan

Attack prompts must not contain live, third-party-owned destinations (a real fetch/tool harness could exfiltrate to them). Scan and verify — see [references/safety-and-citation-checks.md](references/safety-and-citation-checks.md):

```bash
grep -rEoh '([a-z0-9-]+\.)+[a-z]{2,}|[0-9]{1,3}(\.[0-9]{1,3}){3}' internal/probes/<dir>/data/*.yaml | sort -u
dig +short A <domain>; whois <domain> | grep -iE 'Registrar:|Creation Date'
```

Require RFC 2606 / 6761 reserved values (`example.com`, `.invalid`, `.test`, non-routable IPs) for anything that isn't already reserved. Verify "live" claims with `dig`/`whois` before asserting them in the review.

## Phase 8: Citation + scope accuracy

- Resolve every arXiv ID / reference (WebFetch) — confirm it is the cited paper, not an unrelated ID.
- Check the **title/scope**: does it advertise attacks that are out of scope or unimplemented? Recommend retitling to the delivered scope.

## Phase 9: Precedent

```bash
ls Reviews/ 2>/dev/null   # read 1-2 recent prNNN-review.md
```

Match the house voice and keep verdicts consistent (e.g. the **deferral principle**: an attack that needs a surface Augustus doesn't expose is deferred, not faked). See [references/review-structure.md](references/review-structure.md).

## Phase 10: Write the review

Use the house structure (full template in [references/review-structure.md](references/review-structure.md)):

1. **Opening acknowledgement** — genuine; name what's good (engineering, test coverage, honest caveats).
2. **Numbered substantive concerns** — evidence-grounded, `file:line`, BLOCKING called out. Group the fidelity findings (Phase 3) and the cross-cutting findings (Phase 4) so a fail-open / silent-fail isn't buried next to a style nit — name its severity explicitly.
3. **Concrete remediation architecture** — *how* to make it faithful (steps), not just "reject". Reuse what's salvageable; say what moves to a test fixture vs ships.
4. **Summary of requested changes** — terse bullets per component.

Avoid the word "salvage" and similar if the maintainer prefers neutral framing — check prior reviews.

## Phase 11: Scrub local/internal references

Before saving, remove anything only meaningful to you: personal test targets (local ports like `:9080`), cross-repo file paths the author can't see, internal ticket-only context. Cite **in-repo** patterns instead (e.g. point at `internal/generators/rest/rest_test.go`, not a Guard-side file). See [references/safety-and-citation-checks.md](references/safety-and-citation-checks.md#scrubbing).

## Phase 12: Save and post on approval

Save to `Reviews/pr<N>-review.md` and present in chat first. **Posting to the repo is outward-facing and hard to reverse — confirm before posting**, and confirm the review type:

```bash
# request-changes (blocking) — strip the H1 title line from the body first
gh pr review <N> --repo praetorian-inc/augustus --request-changes --body-file <body.md>
# or: --comment (non-blocking) / --approve
```

Verify it landed: `gh pr view <N> --json reviews --jq '.reviews[-1] | {author:.author.login,state:.state}'`.

---

## Integration

### Called By

- `gateway-augustus` (routes here on "review probe PR", "review augustus PR")
- Manual invocation

### Requires (invoke before starting)

None — entry-point workflow.

### Calls (during execution)

None — uses `gh`, `dig`/`whois`, WebFetch directly.

### Pairs With (conditional)

| Skill | Trigger | Purpose |
| ----- | ------- | ------- |
| `llm-finding-to-augustus-probe` | If the review concludes a faithful redesign is needed | Build the corrected probe |
| `testing-augustus-components` | Before endorsing a probe's behavior | Validate it end-to-end against a target |
