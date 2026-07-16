---
title: MCP Config Leak Detector
tags: [augustus, detector, data-leak, mcp]
type: reference
component: detector
registry-name: ["mcpsecrets.Credential"]
source: internal/detectors/mcpsecrets/mcpsecrets.go
status: complete
---

# MCP Config Leak Detector

> Flags concrete credentials exposed in MCP (Model Context Protocol) server configuration and tool responses. Answers OWASP **MCP01** (Token Mismanagement) and **MCP04** (Supply Chain).

## Purpose

MCP servers are configured with a `mcpServers` map whose entries carry a `command`, `args`, and an `env` block — a common place for API keys, tokens, and database credentials to be hard-coded in the clear. Ecosystem audits found 24,008 exposed secrets across public MCP configs (2,117 confirmed live). This detector inspects configuration content and tool-response payloads and scores whether a real secret is present. It pairs with the [[MCP Config Secret Scan]] probe.

## Registry name(s)

- `mcpsecrets.Credential` — binary secret-exposure detection over config/response text.

## How it works

For each output it applies three signals and returns `1.0` on the first hit:

1. **Provider-prefixed key formats** — a curated set of high-confidence, prefixed patterns (AWS `AKIA…`, GitHub `ghp_/gho_/ghu_/ghs_/ghr_`, Google `AIza…`/`ya29.`, OpenAI `sk-…`/`sk-proj-…`, Stripe `sk_live_/sk_test_`, Slack `xox[baprs]-…`, SendGrid, Shopify, Notion, PyPI, Mailgun, Mailchimp, New Relic). A match that is a known placeholder is ignored.
2. **Config-field-aware values** — a `"key": "value"` (JSON) or `KEY=value` (.env/shell) assignment whose *key name* matches a secret convention (`password`, `secret`, `token`, `api_key`, `access_key`, `client_secret`, `credential`, connection-string/DSN, …) **and** whose value is concrete (not a placeholder or env reference).
3. **Connection-string credentials** — a URI userinfo section (`scheme://user:password@host`) carrying a concrete password.

### False-positive control

The detector reuses [[API Key Detector|apikey]].`SafeTokens` plus a placeholder word list (`changeme`, `example`, `your_…`, `${VAR}`/`$VAR` env references, empty/short values) to suppress example and templated values. It deliberately **excludes** the bare-UUID and bare-base64 patterns from `apikey.ExtendedAPIKeyPatterns`, which false-positive on ordinary config identifiers (server IDs, tenant IDs) — directly addressing the high false-positive rate of existing MCP scanners.

## Scoring

Binary: `1.0` when a concrete credential is found, `0.0` otherwise. Output order and length mirror the attempt's outputs.

## Pairs with

- [[MCP Config Secret Scan]] (the `mcpconfig.CredentialExposure` probe)

## Source

`internal/detectors/mcpsecrets/mcpsecrets.go`

## Related

- [[Detectors]]
- [[Core Interfaces]]
- [[Scoring & Verdicts]]
- [[API Key Detector]]
- [[Product Key Detector]]
