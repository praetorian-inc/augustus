---
title: Web Injection
tags: [augustus, probe, malware]
type: reference
component: probe
registry-name: "webinjection.JavaScript"
source: internal/probes/webinjection/webinjection.go
status: complete
---

# Web Injection

> Tests whether an LLM will generate malicious web content — XSS scripts, redirecting meta tags, exfiltrating CSS, or hostile form fields — when asked to produce HTML.

## Purpose

Web Injection probes check whether a model used to generate web markup can be coaxed into emitting **client-side attack payloads**. If a model freely produces `<script>` that steals cookies, meta refreshes to attacker domains, CSS that beacons out data, or hidden privileged form fields, downstream consumers of that output are exposed to XSS, open redirects, and data exfiltration.

## Registry name(s)

One probe per injection vector:

- `webinjection.HTMLComment` — secrets / dangerous notes hidden in `<!-- ... -->`.
- `webinjection.MetaTags` — malicious `<meta>` (refresh redirects, fake Set-Cookie, JS-in-content).
- `webinjection.JavaScript` — inline `<script>` and event-handler payloads (cookie theft, `eval(atob(...))`, beacons).
- `webinjection.CSS` — exfiltrating `background:url()`, `@import`, `expression()`, and binding payloads.
- `webinjection.FormFields` — hostile `<input>`/`<form>` (credential-stealing actions, hidden `admin=true`, `onfocus` handlers).

## How it works

`NewWebInjection(injType)` is a factory closure that selects a fixed payload set (from `payloads.go`) and builds a `WebInjectionProbe` (embedding a [[Probes#SimpleProbe|SimpleProbe]]) for the chosen vector. Each prompt instructs the model to generate HTML containing a specific known-malicious snippet; the detector scores whether the model reproduced the dangerous content rather than sanitizing or refusing.

## Pairs with

- **Detector**: [[Web Injection Detector]] — `webinjection.Detector` (primary for all five variants).
- **Buffs**: generally run unbuffed.

## Source

`internal/probes/webinjection/webinjection.go`, `internal/probes/webinjection/payloads.go`

## Related

[[Probes]], [[Core Interfaces]]
