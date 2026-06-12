---
title: Generators MOC
tags: [augustus, generator, moc]
type: moc
status: complete
---

# Generators MOC

A **generator** wraps an LLM API and turns a [[Attempt & Conversation Model|conversation]] into model responses. See the [[Generators]] concept note and the `Generator` interface in [[Core Interfaces]]. Augustus ships **29 provider integrations** (43 registered variants), grouped below by class. Configure them via [[Provider Configuration]].

> Select a generator by registry name, e.g. `augustus scan openai.OpenAI ...`. Many hosted providers share the [[OpenAI-Compatible]] base.

### Cloud / Hosted APIs

| Note | Registry name | What it does |
| --- | --- | --- |
| [[AWS Bedrock]] | `bedrock.Bedrock` | Generator for AWS Bedrock's InvokeModel runtime, fronting multiple model families (Claude/Anthropic, Titan/Amazon, Llama/Meta) through a single AWS-authenticated interface. |
| [[Anthropic]] | `anthropic.Anthropic` | Native generator for Anthropic's Claude Messages API (Claude 3 / Claude 3.5 — Opus, Sonnet, Haiku), with first-class function-calling (tool-use) support. |
| [[Anyscale]] | `anyscale.Anyscale` | Generator for Anyscale Endpoints, an OpenAI-compatible hosted API serving Llama-2, Mistral, and other open-source models. Built on the shared OpenAI-Compatible Base. |
| [[Azure OpenAI]] | `azure.AzureOpenAI` | Generator for Azure OpenAI Service — GPT models hosted on a customer's Azure resource, supporting both chat and legacy completion APIs. |
| [[Cohere]] | `cohere.Cohere` | Generator for Cohere's Chat (v2) and legacy Generate (v1) APIs, defaulting to the recommended v2 chat endpoint. |
| [[DeepInfra]] | `deepinfra.DeepInfra` | Generator for DeepInfra's OpenAI-compatible inference API (Llama, Falcon, and other open-source models). Built on the shared OpenAI-Compatible Base. |
| [[Fireworks AI]] | `fireworks.Fireworks` | Generator for Fireworks AI's fast OpenAI-compatible inference API serving various open-source models. Built on the shared OpenAI-Compatible Base. |
| [[Google Vertex AI]] | `vertex.Vertex` | Generator for Google Cloud's Vertex AI generateContent API, supporting Gemini models (gemini-pro, gemini-pro-vision) and PaLM 2 (text-bison, chat-bison). One of the few generators with full tool-use / function-calling support, using Gemini's native functionDeclarations and functionCall/functionResponse content parts. |
| [[Groq]] | `groq.Groq` | Generator for Groq's fast LPU inference API, exposed through an OpenAI-compatible interface. Built on the shared OpenAI-Compatible Base with retry support. |
| [[Hugging Face]] | `huggingface.InferenceAPI` | Four generators wrapping Hugging Face inference surfaces: the hosted Inference API, custom Inference Endpoints, local Text Generation Inference (TGI) pipelines, and LLaVA vision-language models. |
| [[IBM watsonx]] | `watsonx.WatsonX` | Generator for IBM watsonx.ai text-generation API. Supports both project-based models (development/training) and deployment-based models (production), and authenticates with IBM Cloud IAM by exchanging an API key for a bearer token. |
| [[Mistral]] | `mistral.Mistral` | Generator for the [Mistral AI](https://mistral.ai/) chat completions API, built on the shared OpenAI-compatible generator. |
| [[NVIDIA Cloud Functions]] | `nvcf.NvcfChat` | Generators for NVIDIA Cloud Functions (NVCF), invoking a deployed function by ID in either chat or text-completion mode. |
| [[NVIDIA NIM]] | `nim.NIM` | Generators for NVIDIA NIM (Inference Microservices), the OpenAI-compatible serving layer for models such as LLaMA-2 and Mixtral. Four variants cover chat, text completion, and multimodal/vision inputs. |
| [[NVIDIA NeMo]] | `nemo.NeMo` | Generator for NVIDIA NeMo models hosted on NGC, exposed through an OpenAI-compatible API. |
| [[OpenAI]] | `openai.OpenAI` | Wraps the OpenAI API for both modern chat-completion models (GPT-4, GPT-4o, GPT-3.5-turbo) and legacy text-completion models (gpt-3.5-turbo-instruct, davinci-002). The most widely reused generator in Augustus — its message conversion, error handling, and model tables are shared with the OpenAI-Compatible infrastructure and many other providers. |
| [[REST]] | `rest.Rest` | Generic HTTP generator for any LLM endpoint that does not have a dedicated provider integration. Highly configurable: arbitrary URL/method/headers, a request-body template with variable substitution, flexible JSON/JSONPath response extraction, and Server-Sent Events (SSE) streaming support. A central building block — many custom and self-hosted endpoints are tested through it. |
| [[Replicate]] | `replicate.Replicate` | Generator for [Replicate](https://replicate.com/), the model-hosting platform for running open-source models (Llama, Mistral, etc.). Models are addressed as owner/model-name or owner/model-name:version, and both public models and private deployments are supported. |

### Aggregators & Proxies

| Note | Registry name | What it does |
| --- | --- | --- |
| [[LiteLLM]] | `litellm.LiteLLM` | Generator that connects to a [LiteLLM](https://github.com/BerriAI/litellm) proxy server, giving Augustus OpenAI-compatible access to 100+ underlying LLM providers (OpenAI, Anthropic, Azure, Bedrock, Cohere, Replicate, …) through one endpoint. |
| [[OpenAI-Compatible]] | `(shared infrastructure — not directly registered)` | Shared infrastructure package that lets many providers (Groq, Mistral, Together, DeepInfra, Fireworks, Anyscale, NIM, NeMo, LiteLLM, and others) implement the Generator interface with almost no code. It extracts the common OpenAI wire format — message conversion, request building, model tables, and error wrapping — into one place. |
| [[Together AI]] | `together.Together` | Generator for [Together.ai](https://www.together.ai/), an inference aggregator hosting many open-source models behind an OpenAI-compatible chat-completions API. Implemented in ~10 lines by delegating entirely to the OpenAI-Compatible infrastructure. |

### Local & Self-Hosted

| Note | Registry name | What it does |
| --- | --- | --- |
| [[GGML / llama.cpp]] | `ggml.Ggml` | Local generator that runs inference by shelling out to a llama.cpp / GGML executable against a local GGUF model file — no network, no API key. |
| [[Ollama]] | `ollama.Ollama` | Generators for a local [Ollama](https://ollama.com/) instance, exposing both the text-completion (/api/generate) and multi-turn chat (/api/chat) endpoints. |
| [[Test Generator]] | `test.*` | A family of mock generators that produce deterministic or canned output without contacting any LLM. Used to verify harness wiring, probe/detector logic, and edge-case handling (empty responses, single-generation constraints, multimodal input) offline and in CI. |

### Frameworks & Wrappers

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Function]] | `—` | Programmatic generator that wraps a user-supplied Go function as the "model" — for testing, mocking, and embedding Augustus in larger Go programs. Not intended for CLI use. |
| [[LangChain]] | `langchain.LangChain` | Generator that wraps a LangChain runnable exposed over HTTP, calling its invoke()-style REST endpoint. |
| [[LangChain Serve]] | `langchain_serve.LangChainServe` | Generator that wraps a [LangServe](https://github.com/langchain-ai/langserve) application, POSTing to its /invoke endpoint with the LangServe request envelope. |
| [[NeMo Guardrails]] | `guardrails.NeMoGuardrails` | Generator that wraps an [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) server, letting Augustus probe an LLM application *through* its programmable guardrails (input/output rails, dialog rails, fact-checking) rather than the raw model. |
| [[Rasa]] | `rasa.RasaRest` | Generator for chatbots built on the [Rasa](https://rasa.com/) open-source conversational-AI framework. Talks to Rasa's REST channel at /webhooks/rest/webhook using its simple {sender, message} request and [{text}] response format. |

---
[[Home]] · [[Generators]] · [[Provider Configuration]] · [[Probes MOC]] · [[Detectors MOC]]
