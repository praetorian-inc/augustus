# Fidelity Anti-Patterns

The job of a probe is to produce an **honest signal about the target**: a positive result must mean the *target* is vulnerable, not that Augustus's own scaffolding forced the outcome. These are the recurring ways a probe PR fails that test. Each is BLOCKING unless noted — it isn't polish.

## The paper-mechanics worksheet (do this first)

Before judging the code, write down — from the paper, not the PR — what the attack actually requires:

| Question | Why it matters |
| -------- | -------------- |
| Black-box prompt, or **control-plane** (enforced grammar/schema/decoding)? | Pasting a schema as *prompt text* ≠ sending it as an enforced API parameter. |
| **Data plane** (prompt) vs **control plane** (response_format/guided decoding) vs **retrieved store** (RAG/memory)? | The payload's channel is usually the whole attack. |
| Does it **force** output (logit masking, constrained decoding, retrieval the target owns) or merely **ask** and rely on compliance? | "Ask and hope" is a susceptibility signal, not the paper's attack. |
| Single-turn / multi-turn / **multi-session**? What carries state across the boundary? | Determines whether persistence is real or simulated. |
| What does **success** look like behaviorally? | The detector must measure *that*, not a proxy. |

Hold the diff against these answers. Most fidelity failures are a mismatch on one row.

## Anti-pattern 1 — Circular / self-referential (BLOCKING)

Augustus simulates the system under attack (memory store, RAG index, tool registry, retrieval) **and then "tests" it**. The positive result is guaranteed by construction, independent of the target model.

**Detection cues:**
- An in-process store/registry/index that the probe both writes to and reads from.
- A test that asserts the payload is present after the probe itself inserted it (a tautology).
- "Persistence" that is a property of a Go object surviving a `clear()`, not of the target's own retrieval.

**The test to apply:** *"If I swap the target for any other model, does the result change?"* If no → the probe measures Augustus, not the target.

## Anti-pattern 2 — Wrong trust channel (BLOCKING)

The payload is injected into the target's **system prompt** (or any channel the model is designed to obey) instead of untrusted data / retrieved content / tool output. This tests "will the model obey its own system prompt" — a near-universal yes.

**Detection cues:** `conv.System`, `WithSystem(...)`, prepending to a system message. Real injection attacks land in user/tool/retrieved-context messages.

## Anti-pattern 3 — Self-report detector (major)

The detector scores acceptance phrases ("I've stored", "I'll remember", "Sure, here's…") rather than a **behavioral consequence** on a later benign turn.

**Why it's wrong:** "I'll remember that" ≠ the model actually acting on the planted rule. Worse, if the *same phrase list* gates both the simulator's storage and the detector's score, a silently-compliant (dangerous) model scores safe and a chatty-harmless one scores vulnerable — backwards and correlated.

**Faithful detector:** judge whether a later, benign trigger produced behavior that reflects the injected content, with ground truth (the planted rule + the benign trigger), same shape as the BOLA `judge` + `AccessControlContext`.

Even a behavioral detector mis-scores if it isn't robust to benign-but-chatty or adversarial output — anchor the match (mention ≠ success), add negation/refusal awareness, harden the judge-verdict parser, and carry per-prompt ground truth + a benign control. See [review-lenses.md → Lens 2](review-lenses.md#lens-2--detector-robustness-beyond-self-report).

## Anti-pattern 4 — Simulated control/data plane (attack not reproduced)

The attack lives in the control plane (OpenAI Structured Outputs `response_format`, Gemini `responseSchema`, vLLM/SGLang guided decoding — the grammar that *masks tokens at every step*), but the PR pastes the schema/enum/dictionary as **prompt text**. Prompt text is voluntary; the model can refuse. Nothing is forced.

**Detection cues:** a JSON schema / enum / key-dictionary inside a YAML prompt string, no wiring to a generator request parameter. Faithful reproduction needs a control-payload channel (template → `conv.ResponseFormat` → provider API param), gated to schema-enforcing providers.

## Anti-pattern 5 — Prompt-compliance-as-attack (rename, don't claim the paper)

Hand-authored, overtly coercive content (`[SYSTEM PRIORITY]`, `[MANDATORY]`) pasted into a single prompt the model is simply asked to follow, with the malicious item guaranteed present and no injection vector. The paper's contribution was usually an *optimization* or *injection vector* that beats this manual baseline.

**Verdict:** valid as a **susceptibility signal**; rename to what it measures (e.g. `ToolCoercion`, not `ToolHijacker`) and drop the claim that it reproduces the paper. Note the missing vector (poisoned MCP/registry, IPI) as the real attack.

## Anti-pattern 6 — Silent pass / fail-safe-looking (the false *negative*, BLOCKING-to-major)

The mirror of anti-pattern 1. Where circular probes report "vulnerable" no matter what, this one reports **"safe" when it actually tested nothing**: the judge errored and scored `0.0`, the encoder's refusal was forwarded as the prompt, the generator dropped the image it couldn't format, or the probe ran against a target lacking the capability and silently passed. A missed finding reads as a clean result, so nobody re-checks it — that's why it's not mere polish, and why a fail-open on the core scoring path is BLOCKING rather than a "minor — flag it".

**The rule:** a component that cannot do its job must **fail loud** (skip + warn + count), never **fail safe-looking**. **Detection cue:** any path where a break/outage/unsupported-input yields a verdict instead of an explicit skip/error. Full catalogue + the worked instances (#182/#84/#104/#114) in [review-lenses.md → Lens 1](review-lenses.md#lens-1--silent-failure-direction-the-false-negative-that-looks-clean).

## Severity calibration

- **BLOCKING**: the probe cannot produce an honest true/false signal about the target — false positive by construction (anti-patterns 1, 2; often 4) or false negative that reports clean when a core path silently passes (6). Don't merge.
- **Major**: the signal exists but is mismeasured or mislabeled (3, 5; 6 when it's a recoverable degradation, not the core path). Merge only after fix/rename.
- **Quality**: Go bugs (races, dead code, non-determinism, missing tests). Real, but not why a probe PR lives or dies.

## The deferral principle

When the faithful attack needs a surface Augustus doesn't expose yet (control plane, real memory backend, tool-injection vector), **defer or redirect — do not fake it in YAML/simulation**. Either (a) point the probe at a real external system over the wire (`rest.Rest`), or (b) defer until the wire layer exists. A simulated surface that tests Augustus itself is worse than no probe.
