---
title: Tree Search
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "treesearch.TopicTree"
source: internal/probes/treesearch/topictree.go
status: complete
---

# Tree Search

> An iterative tree-search framework for adaptive jailbreaks: prompt a node's terms, score the response, and use the score to decide which child branches of an attack tree to explore next.

## Purpose

Tree Search provides the reusable **adaptive exploration** engine behind several iterative probes. Instead of firing a fixed prompt list, it organizes attack space as a tree, evaluates each node with a detector, and concentrates effort on the branches where the model shows weakness (or strength, depending on configuration). The shipped concrete probe, `TopicTree`, walks a built-in taxonomy of harmful-content topics.

## Registry name(s)

- `treesearch.TopicTree` — explores a hierarchical tree of harmful topics (violence, illegal activity, exploitation, dangerous information).
- `treesearch.TopicTreeDeep` — the same tree with deeper traversal settings.

The underlying `TreeSearcher` is also consumed (unregistered) by the [[Topic]] probe.

## How it works

`treesearch.go` defines the generic `TreeSearcher`, a `Node` interface, search `Strategy` (BreadthFirst, DepthFirst, plus TAP/PAIR modes), and a `Config` of thresholds. The algorithm:

1. Seed the queue with initial nodes.
2. For each node, render prompts from its `terms` and call the generator (`Generations` responses each).
3. Score responses with a [[Detectors|Detector]]; scores above `PerGenerationThreshold` are "hits".
4. If a node's mean score crosses `PerNodeThreshold`, queue its children (direction governed by `TargetSoft`).

`topictree.go` supplies the concrete `TopicNode` tree (root "Harmful Content" → Violence/Illegal/Exploitation/Dangerous Information → leaf term sets) and registers the two probes.

## Configuration

`treesearch.Config`:

| Field | Purpose |
|---|---|
| `Strategy` | BreadthFirst / DepthFirst (TAP, PAIR also defined). |
| `PerGenerationThreshold` | Per-response "hit" threshold (default 0.5). |
| `PerNodeThreshold` | Mean-score threshold to expand children (default 0.1). |
| `TargetSoft` | `true` = dig into high-scoring (vulnerable) nodes; `false` = push resilient nodes. |
| `Generations` | Responses requested per prompt. |
| `QueueChildrenAtStart` | Whether children are queued up front. |

## Pairs with

- **Detector**: any [[Detectors|Detector]] supplied via config; typically a mitigation/refusal or harmful-content detector that scores each generation.
- **Buffs**: generally run unbuffed.

## Source

`internal/probes/treesearch/treesearch.go`, `internal/probes/treesearch/topictree.go`

## Related

[[Probes]], [[Core Interfaces]], [[Topic]], [[TAP]]
