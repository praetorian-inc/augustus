# Runtime probe templates

Load new probes from a directory of YAML files at scan time — **no rebuild
required** — with `--templates-dir`:

```bash
augustus scan openai.OpenAI --templates-dir ./examples/runtime-templates \
  --probe runtime.RoleplayBypass
```

Templates are registered into the probe registry before probe selection, so they
also work with `--probes-glob "runtime.*"` and `--all`.

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

Important: the unified engine always records its in-loop judge score under
`judge.Judge`, and an attempt's verdict is the **maximum score across all
detectors** (the in-loop judge *plus* your configured detector(s)). So
`info.detector` **adds** a verdict signal rather than replacing the in-loop
judge — either can flag the attempt vulnerable. Tune the in-loop judge with
`engine.success_threshold`. (Static templates have no in-loop judge, so for them
`info.detector` is the sole verdict.)

## Validation

Templates are validated on load. Multi-turn strategy prompts are dry-run
rendered against their data, so a typo like `{{.Tpyo}}` fails immediately with a
clear error instead of silently degrading prompts mid-scan.
