---
title: CLI Reference
tags: [augustus, cli, reference]
type: guide
status: complete
---

# CLI Reference

Canonical command and flag reference for the `augustus` binary. The CLI is built with [Kong](https://github.com/alecthomas/kong); flags below are taken directly from the Kong struct tags in `cmd/augustus/cli.go`.

> Hub note. Other CLI guides link back here: [[Provider Configuration]], [[Probe Selection & Globs]], [[Buffs in Practice]], [[Output & Reports]], [[Scan Recipes]]. See also [[Home]].

## Top-level commands

Defined on the root `CLI` struct in `cmd/augustus/cli.go`:

| Command | Purpose |
|---|---|
| `scan <generator>` | Run a vulnerability scan against an LLM. |
| `list` | List available probes, detectors, generators, harnesses, and buffs. |
| `version` | Print version information. |
| `completion <shell>` | Print a shell-completion stub (`bash`, `zsh`, `fish`). |
| `help` | Print top-level usage (default when no command is given). |

Global flag (applies to all commands):

| Flag | Short | Env | Description |
|---|---|---|---|
| `--debug` | `-d` | `AUGUSTUS_DEBUG` | Enable debug mode. |

### `list`

```bash
augustus list
```

Prints every registered capability with its registry name and a count per category (Probes, Generators, Detectors, Harnesses, Buffs). Source: `cmd/augustus/common.go` (`listCapabilities`). Registry names printed here are exactly what you pass to `scan` (e.g. `openai.OpenAI`, `dan.Dan_11_0`, `encoding.Base64`).

### `completion`

```bash
augustus completion zsh
```

Takes one positional argument constrained to `bash`, `zsh`, or `fish`.

## `scan` command

Signature: `augustus scan <generator> [flags]`

The single positional argument `<generator>` is the **required** generator registry name (e.g. `openai.OpenAI`, `anthropic.Anthropic`, `rest.Rest`). See [[Provider Configuration]].

### Probe selection (mutually exclusive)

Exactly one of these is required. They belong to the Kong `xor:"probe-selection"` group, so they cannot be combined.

| Flag | Short | Description |
|---|---|---|
| `--probe` | `-p` | Probe name; repeatable (`-p a -p b`). |
| `--probes-glob` | | Comma-separated probe glob patterns (e.g. `'dan.*,encoding.*'`). |
| `--all` | | Run all registered probes. |

See [[Probe Selection & Globs]].

### Detector selection

| Flag | Description |
|---|---|
| `--detector` | Detector name; repeatable. |
| `--detectors-glob` | Comma-separated detector glob patterns. |
| `--refusal-pattern` | Target's own refusal/guardrail phrase to treat as a mitigation; repeatable. Added to the `mitigation.*` detectors' recognized phrases (via `extra_substrings`) to avoid false positives on custom guardrails. See [[Mitigation Detector]]. |

If omitted, detectors are **auto-discovered** from each probe's primary detector metadata (`cmd/augustus/scan.go`, `createDetectors`).

### Buff selection

| Flag | Short | Description |
|---|---|---|
| `--buff` | `-b` | Buff name to apply; repeatable. |
| `--buffs-glob` | | Comma-separated buff glob patterns (e.g. `'encoding.*'`). |

See [[Buffs in Practice]].

### Configuration

| Flag | Short | Description |
|---|---|---|
| `--config` | `-c` | JSON config for the generator. |
| `--config-file` | | YAML config file path (must exist). |
| `--model` | `-m` | Model name; shorthand for `--config '{"model":"..."}'`. |
| `--profile` | | Named profile to apply from the config file (requires `--config-file`). |

Validation rules (`ScanCmd.Validate`): `--config` and `--config-file` are mutually exclusive; `--profile` requires `--config-file`. Precedence is **defaults -> YAML -> CLI**; `--model` is merged into the config JSON and wins over a `model` key in `--config`. See [[Provider Configuration]].

### Execution

| Flag | Env | Default | Description |
|---|---|---|---|
| `--harness` | | `probewise.Probewise` | Harness name. |
| `--timeout` | | `0` (none) | Overall scan timeout (Go duration, e.g. `5m`). |
| `--concurrency` | `AUGUSTUS_CONCURRENCY` | `10` | Max concurrent probes. |
| `--probe-timeout` | | `0` (none) | Per-probe timeout (Go duration). |

The scanner default concurrency is 10 (`pkg/scanner` `DefaultOptions`). Note: when any runtime hook is set, concurrency is forced to 1 (see below).

### Output

| Flag | Short | Default | Description |
|---|---|---|---|
| `--format` | `-f` | `table` | Output format: `table`, `json`, or `jsonl`. |
| `--output` | `-o` | | JSONL output file path (streamed per-attempt). |
| `--html` | | | HTML report file path. |
| `--verbose` | `-v` | | Verbose output (per-attempt detail, multi-turn turns). |

See [[Output & Reports]].

### Runtime hooks

| Flag | Description |
|---|---|
| `--setup` | Shell command run once before all probes. Stdout `KEY=VALUE` lines are injected into the generator request template as `$KEY` (prefixed `HOOK_` on config collision). |
| `--prepare` | Shell command run before each probe. Receives `AUGUSTUS_LAST_RESPONSE` env var. |
| `--cleanup` | Shell command run once after all probes complete. |

Setting any hook forces sequential execution (`--concurrency` is reduced to 1). Source: `cmd/augustus/scan.go` (`runScanResolved`).

## Minimal example

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 --detector dan.DAN
```

## Related

- [[Provider Configuration]]
- [[Probe Selection & Globs]]
- [[Buffs in Practice]]
- [[Output & Reports]]
- [[Scan Recipes]]
- [[Home]]
