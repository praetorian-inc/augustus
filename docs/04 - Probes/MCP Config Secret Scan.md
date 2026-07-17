---
title: MCP Config Secret Scan
tags: [augustus, probe, data-leak, mcp]
type: reference
component: probe
registry-name: ["mcpconfig.CredentialExposure"]
source: internal/probes/mcpconfig/credentialexposure.go
status: complete
---

# MCP Config Secret Scan

> Scores MCP (Model Context Protocol) server configuration for exposed credentials. Covers the static half of credential-exposure testing (OWASP **MCP01** / **MCP04**) without needing a live MCP server.

## Purpose

`mcpconfig.CredentialExposure` is a **context-aware scorer**, not a collector: it does no file I/O itself. Config collection lives in the `recon.MCPConfig` reconnaissance module, which reads inline content, a file, or a directory and emits one `mcp.config` observation per source into the shared recon store. The probe opts into that store (via `recon.ContextAwareProbe`) and emits one attempt per collected config source so the [[MCP Config Leak Detector]] can flag hard-coded secrets. This is the "scan once, reuse everywhere" model — recon populates the workspace, the probe scores it — and answers "are my MCP credentials sitting in the clear in a config or `.env` file?" with no target model required.

## Registry name(s)

- `mcpconfig.CredentialExposure` — context-aware credential scorer over config observations.

## The `recon.MCPConfig` module

Config collection is a first-class reconnaissance module (`recon.MCPConfig`, `internal/recon/mcpconfig`). It measures local configuration at rest — independent of the scan target (the recon contract sanctions target-less modules) — and emits observations; it renders no verdict. Recognized config keys:

- **`content`** — inline configuration text.
- **`path`** — a file, or a directory that is walked for config files (`.json`, `.env*`, `.yaml`/`.yml`, `.toml`, `.ini`, `.cfg`, `.conf`; extension/`.env` checks are case-insensitive).

It emits one `mcp.config` observation per source (`Target` = the path or `inline`, `Data` = the JSON-encoded file content). Unreadable and oversize (> 5 MiB) files are skipped rather than failing the run; a cancelled context aborts.

## How the probe works

The probe reads the config observations back from the recon store and emits one attempt per source (output = the file/inline content, `source` metadata = its label). The primary detector is `mcpsecrets.Credential`.

When the recon store holds no config (`recon.MCPConfig` was not run, or found nothing), the probe emits a single **informational, non-vulnerable** attempt explaining that `recon.MCPConfig` must be run to supply config content — so an operator can tell "recon not run" apart from a genuinely clean pass.

## Usage

`recon.MCPConfig` is configured from the `recon.settings` block of a YAML config
file (recon modules are not configured by `--config`, which carries generator
config only). Point `path` at a file or a directory of config files (or set
`content` for inline text):

```yaml
# mcpconfig.yaml
recon:
  settings:
    recon.MCPConfig:
      path: "/path/to/mcp-configs"
```

```bash
# Collect config with recon.MCPConfig, then score it with the probe in one scan.
# The generator is unused by both, so any no-network generator such as test.Blank
# works as the placeholder target.
augustus scan test.Blank \
  --recon recon.MCPConfig \
  --probe mcpconfig.CredentialExposure \
  --config-file mcpconfig.yaml
```

A leaky config (e.g. a `GITHUB_TOKEN` set to a real `ghp_…` value) scores `1.0` (VULN); configs that only reference env vars (`${FS_API_KEY}`) or use placeholders score `0.0` (SAFE).

> [!warning] Scan outputs are secret-bearing
> Attempt outputs (and the `mcp.config` observations) embed the scanned content verbatim, including any real credential found, so JSONL report artifacts should be treated as sensitive and handled accordingly.

## Pairs with

- [[MCP Config Leak Detector]] (`mcpsecrets.Credential`)

## Source

`internal/probes/mcpconfig/credentialexposure.go` (probe) · `internal/recon/mcpconfig/mcpconfig.go` (recon module)

## Related

- [[Probes]]
- [[Core Interfaces]]
- [[API Key]]
- [[Adding a Probe]]
