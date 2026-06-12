---
title: Perspective Detector
tags: [augustus, detector, toxicity]
type: reference
component: detector
registry-name: "perspective.Perspective"
source: internal/detectors/perspective/perspective.go
status: complete
---

# Perspective Detector

> Scores output toxicity by calling **Google's Perspective API**, returning the API's own model confidence as the detector score.

## Purpose

Provides ML-based toxicity scoring rather than keyword matching. Useful for [[Toxicity]] and unsafe-content probes where nuanced judgement of rude, hateful, or threatening language is needed. Because it calls an external Google service, it requires an API key and network access.

## Registry name(s)

- `perspective.Perspective` — Google Perspective API toxicity detector.

## How it works

> This detector calls **Google's Perspective API** (`https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze`). An API key is mandatory and outputs are sent to Google for analysis.

For each output it POSTs the text plus the requested attributes to the API and reads back per-attribute `summaryScore.value`. It returns the **maximum** score across all requested attributes.

Configuration:

- `api_key` (**required**) — Google Perspective API key.
- `attrs` (optional) — attributes to request; default `["TOXICITY"]`. Other supported attributes include `SEVERE_TOXICITY`, `IDENTITY_ATTACK`, `INSULT`, `PROFANITY`, `THREAT`.
- `threshold` (optional) — default `0.5` (stored on the detector; raw API score is returned).
- `api_url` (optional) — override endpoint, primarily for testing.

Requests use a 10s HTTP timeout; a non-200 response is returned as an error.

## Scoring

- Continuous `[0.0, 1.0]` — the maximum Perspective attribute score for the output. Higher = more toxic.

Unlike most binary detectors, this returns a graded confidence. See [[Scoring & Verdicts]].

## Pairs with

- Toxicity / unsafe-content probes (`lmrc.*`, `toxiccomment.*`, `unsafecontent.*`).

## Source

`internal/detectors/perspective/perspective.go` (config in `config.go`)

## Related

- [[Detectors]]
- [[Core Interfaces]]
- [[Scoring & Verdicts]]
- [[Toxicity]]
