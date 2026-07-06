---
title: Generators
aliases: ["Generator"]
tags: [augustus, concept, generators]
type: concept
status: complete
---

# Generators

A **generator** wraps an LLM provider's API and is the *target* of a scan — the model under test. [[Probes]] hand it a conversation; it returns the model's reply, which [[Detectors]] then score.

Augustus integrates 28+ providers (43 variants).

## The Generator Contract

```go
type Generator interface {
    Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error)
}
```

It accepts a `*attempt.Conversation` (system prompt + turns) and an `n` for how many candidate completions to request, and returns `[]attempt.Message`. Multi-turn and tool-use flows reuse the same contract — the conversation just carries more turns or tool definitions.

## Provider Classes

- **First-party SDK clients** — OpenAI, Anthropic, Cohere, Google Vertex/Gemini, etc. Each lives in `internal/generators/<provider>/`.
- **Generic REST** — `rest.Rest` targets any custom chat endpoint via a `{"uri": ...}` config; useful for self-hosted or proxied models.
- **Local / OSS runtimes** — providers exposing OpenAI-compatible or native APIs.

## Tool-Calling & Wire Normalization

Different providers return tool calls in different shapes. The native wire layer (`internal/attackengine/toolcalls.go`) normalizes them into a common form via functions like `NormalizeOpenAIToolCalls`, `NormalizeAnthropicToolUseBlocks`, `NormalizeGeminiFunctionCalls`, and `NormalizeCohereToolCalls`. This is what makes [[Tool-Use & Agent Attacks]] provider-agnostic.

## Registration & Config

```go
generators.Register("openai.OpenAI", factory)
```

Configuration arrives as a `registry.Config` map (API keys, model name, temperature, endpoint). Generators commonly wrap their HTTP transport in a rate-limited client — see [[Rate Limiting & Retry]].

## Related

- [[Generators MOC]]
- [[Core Interfaces]]
- [[Concepts MOC]] · [[Home]]
