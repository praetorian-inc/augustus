# Cross-Cutting Review Lenses (any Augustus PR)

Fidelity (does the probe reproduce the attack?) is the deepest layer, and it only applies to PRs that *claim* an attack. These lenses apply to **every** Augustus PR — probe, detector, generator, buff, or infra. They are the recurring concerns that decided real reviews; each entry names the PR it came from so the precedent is checkable.

Run the relevant lenses, mark each finding **BLOCKING / major / non-blocking**, and cite `file:line`.

---

## Lens 1 — Silent failure direction (the false *negative* that looks clean)

The fidelity anti-patterns guard against false **positives** (a probe that reports "vulnerable" no matter what). This lens is the mirror: a path that **silently tests nothing and reports safe**. A missed finding is the expensive error — it reads as a clean result and nobody re-checks it.

**The rule:** when a component cannot do its job, it must **fail loud** (skip + warn + count), never **fail safe-looking** (pass / score 0.0 / drop input silently). A fail-open on the *core scoring path* is BLOCKING, not "minor — flag it" — weight it that way.

Recurring instances:

- **Detector/judge outage scores everything safe.** With `text_fallback:false`, a judge outage makes every chat-mode output score `0.0` behind a single `slog.Warn` — silently converting all detection to false negatives. Surface it louder than a warn: a metric or error count so silent under-reporting is *detectable*. (#182)
- **Upstream LLM refusal forwarded as valid output.** A buff's encoder (e.g. `gpt-4o-mini`) refuses to encode a jailbreak and returns `"I'm sorry, I can't assist with that."` — an HTTP 200, so no error. The refusal text gets substituted as the prompt and the whole attempt is silently neutered, with no error/log/JSONL signal. Fix: **validate the encoder output against its contract** before using it (e.g. the math-encoding system prompt promises notation + proof framing — check for it), and `slog.Warn` + count on failure instead of passing the refusal through. Validate against the *contract*, not against refusal phrasing (catches refusals, empty output, model drift, short echoes at once). (#84)
- **Generator silently drops input it can't format.** Bedrock-Nova drops an unsupported image and sends a text-only request — the probe "runs" but tests nothing and reports not-vulnerable; other generators error instead. A silent no-op must not look like a clean result — log a warning/error on skip. (#104)
- **Parser returns empty content + nil error on an unexpected body.** A `parseResponse` path that returns empty `Content` with no error when the JSONPath misses turns any misconfigured path or unexpected body into a silent clean scan — across *every* probe using that generator. The blast radius is the whole scanner, not one probe. Must error/warn. (pattern of #111/#60-class rest.go changes)
- **A whole target class is silently unsupported.** The generic `rest.Rest` target wasn't extended for multimodal, so it silently dropped image data — meaning multimodal probes only ran against the named providers, not the most common engagement target (a bespoke endpoint). A silent capability gap is worse than an explicit "unsupported". (#104)
- **Gate to capable targets; skip, don't pass.** A memory/vision/reasoning probe pointed at a target that lacks the capability must **skip loudly** (mirror the `VisionCapable` gating pattern), never silently score safe — a stateless chat API mis-reported as "safe on memory injection" is a false negative. (#114/#115)

**Test to apply:** *"If this component breaks or the target lacks the capability, does the scan still report a verdict? Is that verdict silently 'safe'?"* If yes → BLOCKING when it's the core path, major when it's a recoverable degradation; demand loud failure either way.

---

## Lens 2 — Detector robustness (beyond self-report)

Extends fidelity anti-pattern 3. A detector must score the **behavioral outcome**, and must survive adversarial and benign-but-chatty output without flipping.

- **Mention ≠ selection/success — anchor the match.** Scoring `1.0` when a tool/secret/marker merely *appears* as a substring misfires on the most expected outputs: `"I would NOT use priority_search_v2; I'll use web_search"` contains the name → falsely "vulnerable". Require the (normalized) output to **equal or begin with** the expected token; treat explanatory/multi-item output as ambiguous → not a hit (or route to a judge). Conversely a whole-response-vs-short-string edit-distance check (`levenshtein(out, canary) <= 3`) never fires — use containment, as the `apikey` detector does. (#112)
- **Add negation/refusal awareness.** If refusal/negation cues co-occur (`don't have`, `won't use`, `not appropriate`, `instead`, `rather than`), do not score vulnerable. The `memoryinject` detector already implements this shape (explicit rejection list forcing `0.0` + mixed-signal handling) — port it. (#112)
- **Judge prompts are attacker-influenced — harden the parser.** The judge reads attacker-controlled `<response>` text. Two failure modes seen together (#182):
  - **Take the *last* verdict marker, not the first.** `FindStringSubmatch` returns the first `[[…]]` anywhere; a chatty judge that echoes the response before its verdict gets misclassified. The judge is instructed to *end* with the marker → select the final match (`FindAllStringSubmatch`, take last).
  - **Escape the marker delimiters in the embedded response.** If `escapeXMLContent` escapes `&<>` but not `[`/`]`, attacker `<response>` text can smuggle a literal `[[REFUSED]]`/`[[LEAKED]]` into the prompt. Strip/escape the bracket characters too. Add a regression test: echoed `[[LEAKED]]` in prose + a final `[[REFUSED]]` → expects the refused score.
- **Ground truth + a benign control.** A detector that assumes the correct answer is always "unsafe" (keys on `"classified as safe"`, `"risk: low"`) scores a *correct* safe verdict as `1.0` vulnerable. Success for a classifier-subversion probe is *deviation from the per-prompt correct verdict* — carry that verdict as ground truth and add at least one benign-control prompt to prove no false positive. (#115/#114)
- **Trim indicators that overlap benign output.** Keyword indicators like `import subprocess`, `shell=true`, `step 1:` fire on a model *correctly explaining why something is dangerous*. Demote keywords to a secondary signal behind a judge; trim the benign-overlapping ones. (#115)

---

## Lens 3 — Single source of truth for the answer key

When the expected value (tool name, canary phrase, correct verdict) is maintained in **two** places, they drift, and the drift is a **silent miss** nobody catches in review. Name this principle in the review — don't just note "they might get out of sync".

- Tool names hardcoded in the Go detector *and* duplicated in the YAML → adding a prompt needs a detector edit. Carry expected names per-template via `detector_config` so the data is self-describing. (#112)
- The canary is baked into each image *and* listed in the detector's hardcoded array → regenerate an image with a tweaked phrase, forget the list, detector silently stops matching. Attach the expected canary to the **attempt** itself; the detector reads it from there. One source of truth, can't drift. (#104)

**Test:** *"Is the expected value written down in more than one file? What breaks silently if they disagree?"*

---

## Lens 4 — End-to-end validation against a real (or mock) endpoint

Unit tests on hardcoded strings prove the parser, not the behavior. For any detector/probe, ask: **has this been run against an actual endpoint** — even a hardcoded/`httptest` mock — to confirm the detector scores a real response correctly and **does not false-positive on a refusal**? A local mock target + judge is acceptable and expected; live real-endpoint validation can be a non-blocking follow-up. (#182 asked it; #113 satisfied it with a local mock proving `1.0` on a leak, `0.0` on refusals.)

The `rest` generator's own tests stand up an `httptest` stub (`internal/generators/rest/rest_test.go`) — point the author there for the fixture pattern. A change to `rest.go` itself should ship with a `rest_test.go` case, not ride along inside a probe PR.

---

## Lens 5 — Generator / config hardening

For PRs touching generators, config parsing, or CLI surface:

- **Magic-number thresholds → a parameter the operator understands.** A hardcoded fuzzy-match tolerance of `3` edits is arbitrary and phrase-length-dependent (too low → false negatives, too high → false positives). Don't accept it as "fine" or flag it only as dead code — replace it with a parameter expressed in terms the operator controls — e.g. a p-value against a same-shape decoy set, where they set a false-match rate `α` instead of guessing an edit count. (#104)
- **Dead code that looks active.** A branch whose condition never changes the result (a length check fully overridden by a later keyword check; an edit-distance test that can never be true) is harmless but misleading — it reads as doing something. Delete it; note the no-behavior-change. (#104)
- **Aliased / overlapping config keys → warn on conflict; never silently override an explicit value.** When a native key and its alias (`uri`/`endpoint`, `req_template`/`body`, `response_json_field`/`response_path`) are both present with **different** values, the scan silently hits the wrong target. Add a `log.Warn` naming both and which won. And an alias must not flip a boolean the user set explicitly (e.g. `response_path` implicitly setting `responseJSON=true` over an explicit `response_json:false`) — respect the explicit value or at least warn. Non-blocking when one code path never sends both vocabularies (e.g. the Guard integration), but required for the human-authored YAML/CLI path. (#60)
- **Frozen assets should be configurable.** A probe that compiles in a fixed image/payload and ignores config can't be pointed at the engagement's own target. Make it default-out-of-the-box, configurable when an engineer wants to steer it. (#104)
- **Committed binary assets must be reproducible from the repo.** If attack images (or any generated binary) are committed but the generator/verifier scripts live outside the repo, nobody can audit or regenerate what's encoded. Bring the generators + a verifier in-repo, ideally with a step that re-derives each asset and confirms it still contains the expected payload. A Python/Go compatibility blocker here is worth a Linear ticket, not a silent omission. (#104)
- **Scope a blast-radius change to its own PR.** A change to `rest.go` (or any shared generator) touches every probe that uses it. Reviewing it inside a probe PR hides the blast radius — ask for it to be split out with its own tests. (#111 precedent: rest.go SSE fix shipped as its own focused PR)

---

## Lens 6 — Buff / encoding correctness

For encoding/transformation buffs, two recurring classes of bug, both of which **silently reduce effectiveness** rather than error:

- **Tokenization completeness.** A tokenizer that splits only on whitespace leaves punctuation-joined tokens unmatched (`bomb,gun`, `pipe-bomb`, `gun/knife`, `(bomb)` are single tokens that never hit the map) — silently halving the substitution rate. Split on any non-letter/non-digit/non-mark rune and re-emit the separators verbatim. Handle **leading** punctuation symmetrically with trailing (`(bomb)`, `"gun"` fail if only trailing is stripped). (#83)
- **Round-trip / reversibility.** For a substitution buff, a mapping a cooperating model can't decode back to the original word defeats the purpose: object/verb confusion (`hack → 💻` keeps the object, loses the verb), collisions (`shoot`/`gun` both → 🔫), meme-only mappings (`thief → 🦝` decodes as "raccoon"), wrong category (`prison → 🏢` is "office building"). Drop entries that don't round-trip — fewer substitutions, but the ones that remain are clean. Synonym collisions (`home`/`house → 🏠`) are fine. (#83)

---

## Lens 7 — Architectural: don't add an abstraction without removing the duplication

For infra/refactor PRs that introduce a new layer or capability type:

- If the PR adds an abstraction to fix a coupling smell but **re-implements** the logic it claims to consolidate (new parser files that copy `rest.go`'s SSE/JSONPath code verbatim), you'll end up with two implementations that drift. (#40)
- A new **top-level capability type** (its own interface, registry, `internal/` dir, CLI flag, docs) is a large standing commitment — scrutinize whether an existing mechanism already covers it (e.g. `HookedGenerator` already wraps a generator and plumbs raw responses). (#40)
- Don't just reject — offer the two real directions: **(A) finish the refactor** (land it *and* delete the now-duplicated source, so the consolidation actually happens) or **(B) ship only the genuinely new capability** (drop the parts already covered, surface the new bit through the existing extension point). Let the author choose. (#40)

---

## Lens 8 — Consolidate the bot reviews

CodeRabbit and Gemini comment on these PRs. Read their findings, **validate** the real ones against the code, and fold them into your review with credit ("flagged independently by CodeRabbit and Gemini") rather than duplicating or ignoring them. A reviewer's value-add is the judgment of which bot findings are real and how they compose — not re-deriving them. (#182, #82)
</content>
