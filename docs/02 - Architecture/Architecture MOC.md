---
title: Architecture MOC
tags: [augustus, architecture, moc]
type: moc
status: complete
---

# Architecture MOC

Augustus is a Go-based LLM vulnerability scanner that runs 230+ adversarial attacks against 28 LLM providers through a small set of pluggable interfaces wired together by a concurrent scan pipeline. This map links every note in the **Architecture** section.

## Start here

- [[System Overview]] — the pieces and how they fit, with a component diagram
- [[Scan Pipeline]] — the 5-stage flow: Probe → Buff → Generator → Detector → Result

## Core model

- [[Core Interfaces]] — Prober / Generator / Detector / Buff and the optional probe interfaces (the heavily-linked hub)
- [[Attempt & Conversation Model]] — `Attempt`, `Conversation`, `Message`, and the `NewConversation` god node
- [[Plugin Registration & Registries]] — the `init()` self-registration pattern and typed config via `registry.FromMap`

## Execution & configuration

- [[Concurrency & Scanner]] — bounded `errgroup` execution, retry and rate limiting
- [[Configuration System]] — `pkg/config` loader, profiles, and `registry.Config`

## Component concept notes

The capability families each have their own concept note in `03 - Concepts`:
[[Probes]] · [[Generators]] · [[Detectors]] · [[Buffs]]

---

Back to [[Home]]
