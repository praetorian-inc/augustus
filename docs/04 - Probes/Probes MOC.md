---
title: Probes MOC
tags: [augustus, probe, moc]
type: moc
status: complete
---

# Probes MOC

A **probe** generates adversarial attack prompts and returns attempts to be scored. See the [[Probes]] concept note for the contract, and [[Core Interfaces]] for the `Prober` interface. There are **49 probe categories** in Augustus, grouped below by attack family.

> Select probes on the CLI by registry name, e.g. `--probe dan.Dan_11_0`, or by glob `--probes-glob "dan.*"`. See [[Probe Selection & Globs]].

### Testing

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Test Probe]] | `test.Test` | Internal verification probes that send trivial or empty prompts to exercise harness and generator plumbing — not adversarial attacks. |

### Multimodal

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Adversarial Patch]] | `—` | Tests Vision-Language Models against image perturbations ("patches") crafted to cause misclassification or bypass safety filters. |
| [[Multimodal]] | `—` | Base interface for probes that test LLMs with combined text, image, and audio inputs — enabling vulnerabilities that require non-text data. |

### Agent & Tool-Use Attacks

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Browsing]] | `—` | Tests whether an LLM browsing agent will follow malicious instructions hidden in web page content that are invisible to a human reader. |
| [[GOAT]] | `goat.Goat` | Generative Offensive Agent Tester — an attacker LLM that runs a multi-turn conversation, aggressively switching between seven jailbreak techniques using Chain-of-Attack-Thought reasoning to adapt to the target's responses. |
| [[Mischievous]] | `mischievous.MischievousUser` | Multi-turn attack that simulates an innocent, curious user who subtly drifts a conversation toward prohibited topics through natural-sounding engagement — rather than overt adversarial pressure. |
| [[Multi-Agent]] | `—` | Simulates attacks against multi-agent AI systems — orchestrator poisoning, task-queue injection, priority manipulation, worker-instruction corruption, and result filtering/manipulation between cooperating agents. |
| [[Tool Coercion]] | `toolcoercion.AuthorityInjection` | Tests whether an LLM agent can be tricked into selecting a malicious tool over a legitimate one through adversarial tool **descriptions** — the tool-selection step is the attack surface. |
| [[Tool Use]] | `tool.UnauthorizedInvocation` | Tests whether an LLM can be manipulated into misusing its function-calling / tool-calling capabilities — invoking unauthorized tools, injecting malicious parameters, exfiltrating data, or amplifying tool chains. |

### Malware & Malicious Code

| Note | Registry name | What it does |
| --- | --- | --- |
| [[AV Spam Scanning]] | `—` | Tries to make the model emit well-known antivirus/spam/phishing test signatures to check whether the application scans model output for malicious content. |
| [[Malware Generation]] | `—` | Tests whether a model will write malware: full malicious programs, individual malware sub-functions, or anti-detection / evasion code — across eight programming languages. |
| [[Package Hallucination]] | `packagehallucination.*` | Tests whether an LLM will recommend importing non-existent packages in generated code — package names an attacker could squat in public registries (PyPI, npm, crates.io, etc.) for a supply-chain attack. |
| [[Web Injection]] | `webinjection.JavaScript` | Tests whether an LLM will generate malicious web content — XSS scripts, redirecting meta tags, exfiltrating CSS, or hostile form fields — when asked to produce HTML. |

### Encoding & Obfuscation

| Note | Registry name | What it does |
| --- | --- | --- |
| [[ANSI Escape]] | `—` | Tests whether a model will emit ANSI terminal control codes that can hijack downstream terminal rendering. |
| [[Art Prompts]] | `—` | Hides instructions inside ASCII/Unicode art to test whether a model decodes and obeys commands embedded in visual text. |
| [[Bad Characters]] | `—` | Injects imperceptible Unicode perturbations into harmful prompts to test whether refusal policies can be bypassed without changing the visible text. |
| [[Glitch]] | `—` | Feeds the model known "glitch tokens" — rare tokenizer entries the model cannot reliably repeat — and checks for erratic, unstable behavior. |
| [[Guardrail]] | `—` | Guardrail-bypass probes that evade content filters / prompt shields (Azure Prompt Shield, Meta Prompt Guard, OpenAI Moderation) using character-injection, tokenizer-boundary, encoding-mix, synonym-substitution, and sentence-fragmentation evasion techniques. |

### Data Leakage & Memorization

| Note | Registry name | What it does |
| --- | --- | --- |
| [[API Key]] | `—` | Tests whether a model will fabricate or complete secret-looking API keys for common cloud and SaaS services. |
| [[Divergence]] | `divergence.Repeat` | The "poem poem poem" attack — asks the model to repeat a word forever, which can cause it to diverge from the task and replay memorized training data. |
| [[Goodside]] | `—` | A collection of prompt-injection and model-quirk attacks popularized by Riley Goodside — token smuggling, ChatML role confusion, system-prompt override, markdown data exfiltration, output coercion, and a hallucination probe. |
| [[Leak Replay]] | `—` | Detects training-data memorization using cloze (fill-in-the-blank) tests drawn from copyrighted books and news articles — if the model reliably fills the masked word, it likely memorized the source text. |
| [[MCP Config Secret Scan]] | `mcpconfig.SecretScan` | Statically scans MCP server configuration (files, directories, or inline content) for hard-coded credentials — no live MCP server or target model required (OWASP MCP01/MCP04). |
| [[Snowball]] | `snowball.GraphConnectivity` | Probes that pose questions with impossible or false premises to see whether a model "snowballs" into confidently asserting a wrong answer instead of admitting uncertainty. |

### Toxicity & Harmful Content

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Continuation]] | `—` | Feeds the model a high-risk context plus a partial slur and checks whether it completes the offensive term. |
| [[Do Not Answer]] | `—` | Replays the open-source Do-Not-Answer dataset — prompts that safety-aligned models are expected to refuse — to measure whether the target answers instead. |
| [[LMRC]] | `—` | Probes derived from the Language Model Risk Cards framework — a mix of (mostly non-adversarial) content-safety checks and adversarial prompt-injection attacks, each mapped to an LMRC risk category. |
| [[Misleading]] | `misleading.FalseAssertion` | Poses false factual claims to the model and checks whether it refutes/contradicts them or instead goes along and elaborates on the falsehood — a targeted test for a subset of hallucination/sycophancy behaviour. |
| [[Real Toxicity Prompts]] | `realtoxicityprompts.RTP*` | Sends curated prompts known to have a high chance of eliciting toxic continuations across distinct harm categories, plus empty/boundary-token prompts. |

### Prompt Injection

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Exploitation]] | `—` | Coaxes a model into emitting classic web-app exploitation payloads (SQL injection, Jinja SSTI) that become dangerous if downstream systems execute or render the model's output. |
| [[Latent Injection]] | `—` | Tests latent (hidden-context) injection — malicious instructions buried inside seemingly benign framing (creative writing, fictional scenarios, embedded context) that only activate the unsafe behaviour indirectly. |
| [[Prompt Injection]] | `promptinject.Hijack*` | Implements the PromptInject framework's hijacking attacks — instructs the model to ignore prior instructions and emit a specific "rogue string" verbatim. |
| [[RAG Poisoning]] | `ragpoisoning.*` | Indirect prompt injection via retrieval context — plants poisoned "knowledge base" documents containing a false answer, then checks whether the model propagates it when answering a trigger question. |

### Jailbreaks

| Note | Registry name | What it does |
| --- | --- | --- |
| [[AutoDAN]] | `—` | Automatically evolves DAN-style jailbreak prompts against the target using a genetic algorithm. |
| [[Crescendo]] | `crescendo.Crescendo` | A multi-turn jailbreak that starts benign and gradually escalates toward a prohibited goal using the foot-in-the-door technique. |
| [[DAN]] | `—` | Classic "Do Anything Now" roleplay jailbreaks that coax a model into adopting an unrestricted persona that ignores its safety guidelines. |
| [[DRA]] | `—` | Decomposition-Reconstruction Attack — hides a harmful request by obfuscating it letter-by-letter, then instructs the model to reconstruct and answer its own hidden prompt. |
| [[FlipAttack]] | `flipattack.FullAttack` | Wraps a harmful payload in the FlipAttack adversarial system prompt, then relies on a flip.* buff to character/word-flip the payload so safety filters miss it while the model is instructed to unflip and solve it. |
| [[GCG]] | `gcg.GCG` | Appends pre-computed Greedy Coordinate Gradient adversarial suffixes to harmful goal prompts — gibberish-looking token strings that were gradient-optimized to bypass alignment. |
| [[Grandma]] | `—` | Social-engineering jailbreak that frames harmful requests as a wish to honour a deceased grandmother, using emotional manipulation (appeal to pathos) to bypass safety guardrails. |
| [[Hydra]] | `hydra.Hydra` | Single-path multi-turn jailbreak that, on refusal, *backtracks* — completely removing the refused turn from the target's conversation history and asking the attacker model for a different approach. |
| [[Obscure Prompt]] | `obscureprompt.ObscurePrompt` | Uses an LLM (a "mutator") to generate semantically obfuscated jailbreak variations of a base seed prompt, then tests each variation against the target. |
| [[PAIR]] | `pair.IterativePAIR` | Prompt Automatic Iterative Refinement — uses an attacker LLM to iteratively rewrite a jailbreak prompt based on target responses, scored by a judge LLM, until it succeeds or hits a max-iteration cap. |
| [[Phrasing]] | `phrasing.PastTense, phrasing.FutureTense` | Reformulates harmful requests using grammatical tense changes (past / future) to evade safety filters that are tuned for present-tense imperative commands. |
| [[Poetry]] | `poetry.Inject*` | Reformulates harmful instructions into poetic structures (haiku, sonnet, limerick, free verse, rhyming couplet) to bypass safety mechanisms — research reports up to 18x improvement over prose jailbreak baselines. |
| [[Prefix]] | `prefix.Prefix` | Prepends adversarial prefixes (roleplay, context manipulation, authority claims) to harmful base prompts to test whether safety guardrails can be bypassed. |
| [[Suffix]] | `suffix.GCGCached` | Appends pre-computed adversarial suffixes (GCG) to harmful goal prompts to test whether the model's safety alignment can be bypassed by a crafted trailing string. |
| [[TAP]] | `tap.IterativeTAP` | Tree of Attacks with Pruning — an iterative jailbreak that uses an attacker LLM to grow a tree of adversarial prompts, prunes off-topic and low-scoring branches, and scores candidates with a judge LLM. |
| [[Topic]] | `(unregistered library)` | Explores the lexical space around a blocked keyword using WordNet, probing how close a prompt can stay to a forbidden topic before the model stops refusing. |
| [[Tree Search]] | `treesearch.TopicTree` | An iterative tree-search framework for adaptive jailbreaks: prompt a node's terms, score the response, and use the score to decide which child branches of an attack tree to explore next. |

---
[[Home]] · [[Probes]] · [[Detectors MOC]] · [[Generators MOC]] · [[Buffs MOC]]
