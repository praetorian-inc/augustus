---
title: MCP Config Secret Scan
tags: [augustus, probe, data-leak, mcp]
type: reference
component: probe
registry-name: ["mcpconfig.SecretScan"]
source: internal/probes/mcpconfig/secretscan.go
status: complete
---

# MCP Config Secret Scan

> Statically scans MCP (Model Context Protocol) server configuration for exposed credentials. Covers the static half of credential-exposure testing (OWASP **MCP01** / **MCP04**) without needing a live MCP server.

## Purpose

Unlike prompt-based probes, `mcpconfig.SecretScan` is a **static-analysis probe**: it does not call the generator. It sources MCP configuration content and emits it as attempt outputs so the [[MCP Config Leak Detector]] can flag hard-coded secrets. This answers the question "are my MCP credentials sitting in the clear in a config or `.env` file?" — a standalone recon capability that runs before any adversarial testing and requires no target model.

## Registry name(s)

- `mcpconfig.SecretScan` — static credential scan over config content.

## How it works

The probe collects one or more sources, then emits one attempt per source (output = the file/inline content, `source` metadata = its label):

- **`content`** (config key) — inline configuration text to scan.
- **`path`** (config key) — a file, or a directory that is walked for config files (`.json`, `.env*`, `.yaml`/`.yml`, `.toml`, `.ini`, `.cfg`, `.conf`).

With no source configured, or an unreadable path, it emits a single attempt in `error` status. The primary detector is `mcpsecrets.ConfigLeak`.

## Configuration

Provide probe settings via a config file:

```yaml
probes:
  settings:
    mcpconfig.SecretScan:
      path: "/path/to/mcp-configs"   # file or directory
      # or: content: '{"mcpServers":{...}}'
```

## Usage

```bash
# Scan a directory of MCP configs. The generator is unused (static probe),
# so any no-network generator such as test.Blank works as the placeholder target.
augustus scan test.Blank --probe mcpconfig.SecretScan --config-file scan.yaml
```

A leaky config (e.g. a `GITHUB_TOKEN` set to a real `ghp_…` value) scores `1.0` (VULN); configs that only reference env vars (`${FS_API_KEY}`) or use placeholders score `0.0` (SAFE).

## Pairs with

- [[MCP Config Leak Detector]] (`mcpsecrets.ConfigLeak`)

## Source

`internal/probes/mcpconfig/secretscan.go`

## Related

- [[Probes]]
- [[Core Interfaces]]
- [[API Key]]
- [[Adding a Probe]]
