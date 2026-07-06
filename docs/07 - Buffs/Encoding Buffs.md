---
title: Encoding Buffs
aliases: ["Encoding Buff", "Base64 Encoding"]
tags: [augustus, buff, encoding]
type: reference
component: buff
registry-name:
  - "encoding.Base64"
  - "encoding.Base16"
  - "encoding.Base32"
  - "encoding.Base2048"
  - "encoding.Ascii85"
  - "encoding.Hex"
  - "encoding.ROT13"
  - "encoding.Atbash"
  - "encoding.Morse"
  - "encoding.NATO"
  - "encoding.Braille"
  - "encoding.Leet"
  - "encoding.PigLatin"
  - "encoding.Emoji"
  - "encoding.Ecoji"
  - "encoding.Zalgo"
  - "encoding.CharCode"
  - "encoding.CamelCase"
  - "encoding.QuotedPrintable"
  - "encoding.UUencode"
  - "encoding.UnicodeTags"
  - "encoding.SneakyBits"
  - "encoding.MathPrompt"
source: internal/buffs/encoding/
status: complete
---

# Encoding Buffs

> A family of 23 buffs that encode or obfuscate the prompt text — Base64, Hex, ROT13, Morse, emoji, Zalgo, leetspeak, and more — to test whether a model decodes and complies with harmful instructions that its safety training never saw in plain form.

## Purpose

Safety alignment is mostly trained against natural-language surface forms. If a harmful instruction is encoded (Base64, hex, Morse, leetspeak, etc.), a capable model may decode and execute it while its guardrails fail to recognize the intent. The encoding family probes this decode-then-comply gap across a broad set of representations. Most variants wrap the encoded payload in an instruction prefix naming the scheme (e.g. `The following instruction is base64 encoded: ...`) so the model knows to decode.

## Registry name(s)

The `encoding` package registers 23 variants:

| Registry name | Scheme |
| --- | --- |
| `encoding.Base64` | Standard Base64 |
| `encoding.Base16` | Base16 |
| `encoding.Base32` | Base32 |
| `encoding.Base2048` | Base2048 (token-dense) |
| `encoding.Ascii85` | Ascii85 |
| `encoding.Hex` | Hexadecimal bytes |
| `encoding.ROT13` | ROT13 letter rotation |
| `encoding.Atbash` | Atbash substitution cipher |
| `encoding.Morse` | Morse code |
| `encoding.NATO` | NATO phonetic alphabet |
| `encoding.Braille` | Braille Unicode |
| `encoding.Leet` | Leetspeak (1337) |
| `encoding.PigLatin` | Pig Latin |
| `encoding.Emoji` | Emoji substitution |
| `encoding.Ecoji` | Ecoji (Base1024 emoji) |
| `encoding.Zalgo` | Zalgo combining-mark text |
| `encoding.CharCode` | Character code points |
| `encoding.CamelCase` | CamelCase word joining |
| `encoding.QuotedPrintable` | Quoted-printable |
| `encoding.UUencode` | UUencode |
| `encoding.UnicodeTags` | Invisible Unicode tag characters |
| `encoding.SneakyBits` | Bit-level steganographic encoding |
| `encoding.MathPrompt` | LLM-encoded formal mathematics (see below) |

## How it works

Most variants are pure string rewrites. `Transform` encodes `a.Prompt`, wraps it in a scheme-naming instruction prefix, and yields a single copied attempt with the new prompt (e.g. `encoding.Base64`, `encoding.Zalgo`). The shared `buffs.DefaultBuff` helper drives batch processing — see [[Core Interfaces]]. Unicode-smuggling-flavored variants (`encoding.UnicodeTags`, `encoding.SneakyBits`) hide the payload in invisible code points rather than visibly garbled text, overlapping conceptually with [[Unicode Smuggling]].

`encoding.MathPrompt` is the outlier: it is **LLM-backed**, not a string rewrite. It requires an `encoder_generator_type` (e.g. `openai.OpenAI`) and uses a system prompt to recast the request as a formal set-theory / abstract-algebra problem (arXiv:2409.11445), deliberately discarding the original surface words. On encoder error it passes the prompt through unchanged so a transient API failure doesn't sink the scan.

## Use in scans

```bash
# Simple encoding rewrite
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff encoding.Base64

# ROT13
augustus scan anthropic.Anthropic --all --buff encoding.ROT13

# MathPrompt requires an encoder generator (YAML/JSON config)
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff encoding.MathPrompt \
  --config '{"buffs":{"encoding.MathPrompt":{"encoder_generator_type":"openai.OpenAI","encoder_config":{"model":"gpt-4o-mini"}}}}'
```

## Source

`internal/buffs/encoding/` (one file per variant; `base64.go`, `zalgo.go`, `mathprompt.go`, etc.)

## Related

- [[Buffs]]
- [[Core Interfaces]]
- [[Buffs in Practice]]
- [[Unicode Smuggling]]
- [[Flip]]
