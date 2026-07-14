---
title: Output & Reports
tags: [augustus, cli, output]
type: guide
status: complete
---

# Output & Reports

What a scan produces and how to read it. See [[CLI Reference]] for the flags and [[Scoring & Verdicts]] for how scores become a pass/fail verdict.

## Output formats (`--format` / `-f`)

Selected by `--format`, default `table` (`ScanCmd` in `cmd/augustus/cli.go`; evaluators in `cmd/augustus/scan.go`).

| Format | Behavior |
|---|---|
| `table` (default) | Human-readable table to stdout: PROBE, DETECTOR, PASSED, SCORE, STATUS, plus an `Overall: N passed, M failed` summary. |
| `json` | Single pretty-printed JSON object `{ "attempts": [...], "count": N }`. |
| `jsonl` | One JSON object per line (`AttemptResult`), ideal for `jq`/line tools. |

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 --format jsonl
```

## File outputs

These write to disk in addition to the stdout format above:

| Flag | Produces |
|---|---|
| `--output` / `-o <path>` | JSONL file, **streamed per-attempt** as the scan runs (`results.StreamWriter`). |
| `--html <path>` | Standalone HTML report (`results.WriteHTML`), including multi-turn attack rendering. |

```bash
augustus scan openai.OpenAI --all -o results.jsonl --html report.html
```

When `--output` is set, JSONL is streamed incrementally and the in-memory collector handles only the HTML report (avoids double-writing). A confirmation line is printed to stderr for each file written.

## Reading scores and verdicts

Each attempt carries one or more detector **scores in `[0.0, 1.0]`** (0 = safe, 1 = vulnerable). The reported score for an attempt is the **max across all its detectors** (`attempt.GetEffectiveScores`), so a single secondary-detector hit marks the attempt vulnerable.

Each attempt's verdict is computed by `results.Verdict()` (`pkg/results/results.go`) — the single source of truth shared by the CLI table, `--verbose` output, HTML report, and JSONL. Using `DefaultVulnerabilityThreshold = 0.5` (`pkg/attempt/attempt.go`):

- **`error`** — the attempt errored or never completed (surfaced distinctly, not SAFE)
- **`vuln`** — max score `> 0.5`
- **`review`** — a multimodal visible-channel "obeyed injection" at the threshold (`0.5`): worth manual verification, not an auto-vulnerability
- **`safe`** — no threshold-level detection

`passed` is `true` only for `safe`; the summary reports `passed` / `review` / `failed` / `errored` as disjoint buckets that sum to the total.

### JSONL `AttemptResult` fields

Each JSONL line (`pkg/results/results.go`) contains: `probe`, `prompt`, `response`, `detector`, `scores` (array), `verdict` (`safe`/`review`/`vuln`/`error`), `passed` (bool), `status`, `error` (if any), and `timestamp`.

```bash
# Show only the vulnerable attempts
augustus scan openai.OpenAI --all -f jsonl | jq 'select(.passed == false)'
```

## Verbose mode (`--verbose` / `-v`)

Adds per-attempt detail to the table output, including truncated prompt/response and, for multi-turn probes, a per-turn breakdown (attacker/target, judge score, `[SUCCESS]`/`[REFUSED]` markers).

## Related

- [[Scoring & Verdicts]]
- [[CLI Reference]]
- [[Scan Recipes]]
- [[Home]]
