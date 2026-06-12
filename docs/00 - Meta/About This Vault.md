---
title: About This Vault
tags: [augustus, meta]
type: guide
status: complete
---

# About This Vault

This is the documentation vault for **Augustus**, a Go-based LLM vulnerability scanner that tests large language models against 230+ adversarial attacks across 28+ providers. The vault is written for **both users and contributors**, with a contributor lean — it explains not just *how to run* Augustus but *how it is built* and *how to extend it*.

Open **[[Home]]** to start.

## How the vault is organized

Folders are numbered to give a natural reading order, from orientation to deep reference:

| Folder | Purpose |
| --- | --- |
| `00 - Meta` | How this vault works (this note, the tag index). |
| `01 - Overview` | What Augustus is, install, quickstart, threat model, glossary. |
| `02 - Architecture` | The system design: interfaces, registries, scan pipeline, concurrency. |
| `03 - Concepts` | Cross-cutting domain concepts (probes, detectors, attack engine, scoring). |
| `04 - Probes` | One reference note per probe category (the attacks). |
| `05 - Generators` | One reference note per provider integration. |
| `06 - Detectors` | One reference note per detector. |
| `07 - Buffs` | One reference note per prompt transformation. |
| `08 - CLI & Usage` | Running scans: CLI, provider config, output. |
| `09 - Contributing` | Extending Augustus: adding probes, generators, detectors, buffs. |
| `10 - Reference` | Package map and lower-level reference. |

Each folder (except Overview/Meta) has a **MOC** (Map of Content) — a hub note that links to everything in that area. The top-level **[[Home]]** links to every MOC.

## Note conventions

Every note in this vault follows these conventions. **Contributors writing new notes should match them exactly.**

### Frontmatter

Every note opens with YAML frontmatter:

```yaml
---
title: <Human Readable Title>
tags: [augustus, <section>, <topic tags>]
type: <moc | overview | concept | reference | guide>
status: complete
---
```

Component reference notes (probes, generators, detectors, buffs) add three fields:

```yaml
component: <probe | generator | detector | buff>
registry-name: "<category.Name>"   # or a list if the file registers several
source: <relative/path/from/repo/root>
```

### Tags

A small, consistent tag taxonomy (see **[[Tag Index]]**):

- Section: `#probe`, `#generator`, `#detector`, `#buff`, `#architecture`, `#concept`, `#cli`, `#contributing`
- Attack family (probes/detectors): `#jailbreak`, `#prompt-injection`, `#data-leak`, `#toxicity`, `#agent`, `#multimodal`, `#encoding`, `#malware`
- Provider class (generators): `#cloud-api`, `#local`, `#framework`, `#aggregator`

### Links

- Use `[[Note Title]]` wikilinks generously. Backlinks and the graph view are the point.
- A component note **must** link to: the interface it implements (e.g. [[Core Interfaces]]), the concept note for its kind (e.g. [[Probes]]), and any components it pairs with (a probe links to its detector(s) and useful buffs).
- Prefer linking the canonical note over repeating its content.

### Component note template

```markdown
---
title: ...
tags: [augustus, <kind>, ...]
type: reference
component: probe
registry-name: "category.Name"
source: internal/probes/category/file.go
---

# <Title>

> One-sentence summary of what this does.

## Purpose
What attack / behavior / capability this targets and why it matters for LLM security.

## Registry name(s)
- `category.Name` — what this variant does

## How it works
The mechanism: prompts/templates used, key logic, what gets sent to the model.

## Configuration
Config keys and defaults (omit the section if there are none).

## Pairs with
- **Detector:** [[...]]
- **Buffs:** [[...]]

## Source
`internal/.../file.go` — the key types and functions.

## Related
[[...]] · [[...]]
```

### Diagrams

Use Mermaid fenced code blocks (` ```mermaid `) for architecture, pipeline, and relationship diagrams. The architecture and concept notes lean on these.

## Provenance

These notes were generated from the Augustus source tree using its own knowledge graph (`graphify-out/`) for orientation, then verified against the code. When the code changes, regenerate or update the affected notes and keep the conventions above.
