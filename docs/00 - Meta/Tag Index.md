---
title: Tag Index
tags: [augustus, meta]
type: reference
status: complete
---

# Tag Index

The vault uses a small, consistent tag taxonomy so notes can be filtered (and queried with Dataview if you install it). Every note carries `#augustus` plus its section tag and any applicable topic tags.

## Section tags

| Tag | Meaning |
| --- | --- |
| `#augustus` | Every note in this vault. |
| `#meta` | Vault meta (this note, [[About This Vault]]). |
| `#overview` | Newcomer orientation notes. |
| `#architecture` | System-design notes. |
| `#concept` | Cross-cutting domain concepts. |
| `#probe` | A probe (attack) reference note. |
| `#generator` | A provider-integration reference note. |
| `#detector` | An output-scorer reference note. |
| `#buff` | A prompt-transformation reference note. |
| `#cli` | CLI / usage guides. |
| `#contributing` | Extending the codebase. |
| `#reference` | Lower-level code-structure reference. |
| `#moc` | A Map of Content (hub) note. |

## Attack-family tags (probes & detectors)

| Tag | Meaning |
| --- | --- |
| `#jailbreak` | Refusal-bypass / unrestricted-behavior attacks. |
| `#prompt-injection` | Instruction-override and indirect-injection attacks. |
| `#data-leak` | Training-data extraction, memorization, credential leakage. |
| `#toxicity` | Toxic / harmful / unsafe content elicitation. |
| `#malware` | Malicious code, malware, exploit artefacts. |
| `#agent` | Tool-use / function-calling / multi-agent attacks. |
| `#multimodal` | Image/audio-involving attacks. |
| `#encoding` | Encoding / obfuscation-based evasion. |
| `#keyword` | Keyword/pattern/meta detectors. |
| `#test` | Internal testing capabilities. |

## Provider-class tags (generators)

| Tag | Meaning |
| --- | --- |
| `#cloud-api` | Hosted commercial / cloud LLM APIs. |
| `#local` | Local / self-hosted inference (Ollama, GGML, mocks). |
| `#aggregator` | Multi-provider proxies / aggregators (LiteLLM, OpenAI-compatible). |
| `#framework` | Wrappers around LLM frameworks (LangChain, Rasa, NeMo Guardrails). |

## Buff-class tags

| Tag | Meaning |
| --- | --- |
| `#encoding` | Reversible encodings (Base64, ROT13, …). |
| `#translation` | Language / conlang translation buffs. |
| `#obfuscation` | Character-flip, case, Unicode-smuggling buffs. |
| `#rephrasing` | Paraphrase / poetry rewrites. |

---
[[Home]] · [[About This Vault]]
