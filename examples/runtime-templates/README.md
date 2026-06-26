# Runtime probe templates

Load new probes from a directory of YAML files at scan time — **no rebuild
required** — with `--templates-dir`:

```bash
augustus scan openai.OpenAI --templates-dir ./examples/runtime-templates \
  --probe runtime.RoleplayBypass
```

Templates are registered into the probe registry before probe selection, so they
also work with `--probes-glob "runtime.*"` and `--all`. If a runtime template ID
collides with an existing probe ID, loading **fails with an error** — a runtime
template may not shadow a built-in (or another template); give it a distinct
`id:` instead.

## Two kinds of template

| `type:`            | What it is                          | Engine                         |
| ------------------ | ----------------------------------- | ------------------------------ |
| `static` (default) | A fixed list of single-turn prompts | `probes.RunPrompts`            |
| `multiturn`        | A YAML-defined multi-turn strategy  | `internal/multiturn` (unified) |

- `static-example.yaml` — a single-turn prompt probe.
- `multiturn-example.yaml` — a brand-new multi-turn strategy defined purely in
  YAML, run by the same engine that powers Crescendo/GOAT/Hydra.

## What you can and cannot do without a rebuild

- ✅ New static prompt probes.
- ✅ New multi-turn **strategies** (the attack flow is prompt + config).
- ✅ Re-aim any template at scan time — `--config-file` keys (e.g. `goal`,
  `max_turns`, generator types/models) override the template's defaults.
- ✅ Pick any **registered** detector via `info.detector`.
- ❌ New detector or generator *implementations*, or a fundamentally new engine
  control-flow — those are Go and still require a rebuild.

## Detector vs. judge (multi-turn)

A multi-turn template has two judge-shaped knobs:

- `engine.judge_generator_type` — the in-loop **steering** judge that scores each
  turn (drives early-exit and attacker feedback).
- `info.detector` (+ `info.secondary_detectors`) — **post-hoc** detector(s) run
  on the recorded attempt.

The unified engine always records its in-loop judge score under the detector key
`judge.Judge`. The post-hoc detector pipeline then **skips any detector whose
results are already present** on the attempt (it deliberately reuses the in-loop
judge's verdict, which had full conversation context — see
`pkg/harnesses/detection.go`). This produces two distinct cases:

- **`info.detector: judge.Judge`** (as in `multiturn-example.yaml`): the name
  matches the engine's key, so the post-hoc pass is a **no-op** — the in-loop
  steering judge *is* the verdict. There is effectively one judge.
- **`info.detector: <a different detector>`**: the in-loop score lands under
  `judge.Judge`, your detector runs post-hoc under its own name, and the
  attempt's verdict is the **maximum across all detectors** — i.e. a genuinely
  independent second opinion that can flag the attempt even if the in-loop judge
  did not.

Tune the in-loop judge with `engine.success_threshold`. (Static templates have
no in-loop judge, so for them `info.detector` is always the sole verdict and
always runs.)

## Validation

Templates are validated on load:

- Multi-turn strategy prompts are dry-run rendered against **populated** data, so
  a typo fails immediately with a clear error instead of silently degrading
  prompts mid-scan — including a bad field reference inside `{{range .History}}`
  or `{{if .History}}` (those bodies are exercised because the dry-run supplies a
  history record).
- `info.detector` and every `info.secondary_detectors` name are resolved against
  the detector registry, so an unknown detector fails at load rather than partway
  through a scan.
