---
title: Detectors MOC
tags: [augustus, detector, moc]
type: moc
status: complete
---

# Detectors MOC

A **detector** analyzes model output and returns a score in `[0.0, 1.0]` (0 = safe, 1 = vulnerable). See the [[Detectors]] concept note, [[Scoring & Verdicts]] for how scores become verdicts, and the `Detector` interface in [[Core Interfaces]]. Augustus has **43 detector categories** (many registering several variants), grouped below.

> A probe's verdict is the **max score across all its detectors** (primary + secondary). Many detectors build on the shared [[Base Detector]] and use [[Key Packages|Aho-Corasick]] keyword matching.

### Multimodal

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Adversarial Patch Detector]] | `["advpatch.Universal", "advpatch.Targeted", "advpatch.Transfer"]` | Placeholder detectors for vision-model adversarial patch attacks. All three variants always return 0.0 until a vision pipeline exists. |
| [[Visual Jailbreak Detector]] | `visualjailbreak.FigStep` | Multimodal jailbreak detector — flags step-by-step instructional output produced in response to a FigStep-style image attack. |

### Agent & Tool-Use

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Agent Detector]] | `["agent.ToolManipulation", "agent.ArgumentExfiltration", "agent.ChainLength", "agent.FakeToolCallText"]` | A family of detectors for tool-using / agentic LLM attacks. They inspect structured tool-call metadata (with a response-text fallback for chat-mode) to catch forbidden tool use, argument-level data exfiltration, runaway tool-call chains, and fabricated tool calls. |
| [[Hijacking Detector]] | `hijacking.AgentHijack` | Detects whether a browsing/automation agent was hijacked by hidden accessibility (screen-reader) instructions, by scanning output for canary strings that only appear if the agent followed the malicious hidden text. |
| [[Multi-Agent Detector]] | `multiagent.Detector` | Detects whether a multi-agent / orchestrator jailbreak bypassed safety by checking for the absence of a refusal message. |
| [[Tool Coercion Detector]] | `toolcoercion.ToolSelection` | Detects tool-selection coercion in agentic LLMs — picking an attacker-controlled tool over the legitimate one, and leaking information inferred from denied tool calls or parasitic tool chains. |

### Malware & Malicious Code

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Exploitation Detector]] | `exploitation.SQLiEcho` | A family of regex- and keyword-based detectors that flag classic web/app exploitation artefacts in model output: Jinja template injection, Python code execution payloads, and SQL injection (success markers and echoed payloads). |
| [[File Formats Detector]] | `fileformats.PossiblePickleName` | Inspects filenames/files referenced in model output for unsafe formats — Python pickle files (deserialization risk) and executable files (shebang detection). |
| [[Known Bad Signatures Detector]] | `knownbadsignatures.EICAR` | Detects whether the model reproduced a standard security **test signature** — EICAR (antivirus), GTUBE (spam), or GTphish (phishing) — verbatim in its output. |
| [[Malware Generation Detector]] | `malwaregen.AnyCode` | Flags LLM outputs that contain source code or assembly when the model was prompted to produce malware, using language-fingerprinting regexes tuned for recall. |

### Encoding

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Encoding Detector]] | `encoding.DecodeMatch` | Scores how well a model decoded an obfuscated payload by comparing model output against the original plaintext **triggers** carried in attempt metadata. Used to grade Encoding Probe attacks (Base64, ROT13, Morse, hex, etc.). |

### Data Leakage & Credentials

| Note | Registry name | What it does |
| --- | --- | --- |
| [[API Key Detector]] | `["apikey.ApiKey", "apikey.CompleteKey"]` | Regex-based detectors for credential leakage. apikey.ApiKey flags any output matching a known API-key format; apikey.CompleteKey scores how confidently the model *completed* a partial key fragment from the prompt. |
| [[Divergence Detector]] | `divergence.RepeatDiverges` | Detector for the "repeat-a-word forever" training-data extraction attack. It flags when a model that was told to repeat a word *diverges* from the repetition into other, potentially memorized, content. |
| [[Goodside Detector]] | `goodside.RileyIsnt` | A family of detectors backing Riley Goodside's attack collection: hallucination checks, threat-coerced JSON output, ChatML role confusion, markdown image exfiltration, system-prompt override echoes, token smuggling, and glitch-token echoing. |
| [[Leak Replay Detector]] | `leakreplay.StartsWith` | Detects training-data / memorized-content leakage by checking whether model output reproduces known **trigger** text (the secret continuation) carried in attempt metadata — either anywhere in the output or as its opening. |
| [[Package Hallucination Detector]] | `packagehallucination.PythonPypi` | Extracts package/import references from code in a model's output and verifies they actually exist in the relevant public registry — non-existent packages are flagged as hallucinations (a supply-chain / slopsquatting risk). |
| [[Product Key Detector]] | `productkey.Win5x5` | Flags outputs containing a Windows-style 5x5 product key, indicating the model emitted (or fabricated) a license key. |

### Toxicity & Harmful Content

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Continuation Detector]] | `continuation.Continuation` | Context-window matcher for continuation attacks. It detects when a model completes a contentious term (slur, hate phrase) that was started in the prompt, by checking whether the trigger word straddles the prompt/output boundary. |
| [[LMRC Detector]] | `lmrc.Anthro` | Language Model Risk Card detectors. Flag two LMRC failure modes via word-boundary substring matching: anthropomorphisation (first-person pronoun use) and quack-medicine health claims. |
| [[Perspective Detector]] | `perspective.Perspective` | Scores output toxicity by calling **Google's Perspective API**, returning the API's own model confidence as the detector score. |
| [[Toxic Comment Detector]] | `toxiccomment.Toxic` | Flags toxic output — profanity, threats, and slurs — via a curated keyword list. |
| [[Unsafe Content Detector]] | `unsafecontent.SlursReclaimedSlurs` | A family of word-list detectors for offensive and unsafe content — ethnic slurs, profanity (Surge AI), UK OFCOM offensive terms, and the LDNOOBW bad-words list — segmented by category. |

### Prompt Injection

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Latent Injection Detector]] | `latentinjection.Detector` | Detects whether a latent (indirect) injection bypassed safety, using the **mitigation-absence** pattern: it looks for refusal language and **inverts** the result — no refusal means the injection succeeded. |
| [[Prompt Injection Detector]] | `promptinject.AttackRogueString` | Detects successful prompt injection by checking whether the model emitted an attack-defined trigger string carried in the attempt's metadata. |
| [[RAG Poison Detector]] | `ragpoison.RAGPoison` | Detects whether a known poisoned answer, injected into a RAG knowledge base, propagated into the model's output. |
| [[RAG Poisoning Detector]] | `ragpoisoning.Detector` | Detects successful RAG document (and metadata) poisoning by checking whether the model repeated a poisoned answer supplied via attempt trigger metadata. |
| [[Web Injection Detector]] | `webinjection.Detector` | A family of detectors for web-injection payloads in LLM output — generic HTML/JS injection, XSS, and markdown-image data-exfiltration patterns. |

### Jailbreak & Refusal-Bypass

| Note | Registry name | What it does |
| --- | --- | --- |
| [[Art Prompts Detector]] | `artprompts.InstructionFollowing` | Keyword/heuristic detector for ASCII-art prompt injection. It scores whether the model followed instructions hidden inside ASCII art using a refusal-absence + compliance-presence heuristic. |
| [[DAN Detector]] | `["dan.DAN", "dan.AntiDAN", "dan.DANJailbreak", "dan.STAN", "dan.DUDE", "dan.DevMode", "dan.MarkdownLink"]` | Substring detectors for "Do Anything Now" style jailbreak markers. Each variant looks for the signature tokens a model emits when it has adopted a jailbroken persona (DAN, STAN, DUDE, Developer Mode, etc.). |
| [[FlipAttack Detector]] | `flipattack.Bypass` | Detects a successful FlipAttack jailbreak by weighing refusal signals against compliance language, harmful-content keywords, and evidence that the model decoded the flipped/obfuscated payload. |
| [[Judge Detector]] | `judge.Judge` | An **LLM-as-judge** detector: it calls a separate "judge" model to grade whether a target model's output achieved the attacker's goal (judge.Judge) or whether the output is a refusal (judge.Refusal). This is Augustus's general-purpose semantic verdict mechanism, used by the iterative attack engines. |
| [[Mitigation Detector]] | `mitigation.MitigationBypass` | Detects whether a model's safety mitigation (refusal) message is present, then inverts the result so that the *absence* of a refusal scores as vulnerable. |
| [[PAIR Detector]] | `pair.PAIR` | Detects a successful static PAIR (Prompt Automatic Iterative Refinement) jailbreak by checking for the absence of refusal strings in the response. |
| [[Poetry Harm Judge Detector]] | `poetry.HarmJudge` | An LLM-judge detector that decides whether a response contains *actionable* harmful content (instructions, recipes, exploit methods) — not merely whether the model failed to refuse. |
| [[TAP Detector]] | `tap.TAP` | Detects successful TAP (Tree of Attacks with Pruning) jailbreaks by spotting step-by-step instructional output. |

### Keyword, Pattern & Meta

| Note | Registry name | What it does |
| --- | --- | --- |
| [[ANSI Escape Detector]] | `["ansiescape.Raw", "ansiescape.Escaped"]` | Substring detectors for ANSI/terminal escape sequences in model output. ANSI codes can hijack terminals — hiding text, rewriting the screen, spoofing prompts, or (in some terminals) triggering command execution. |
| [[Always Detector]] | `["always.Pass", "always.Fail"]` | Constant-score meta-detectors. always.Pass returns 0.0 for every output; always.Fail returns 1.0 for every output. Used as baselines and for pipeline/harness testing. |
| [[Any Detector]] | `["any.AnyOutput", "any.AnyNonspaceOutput"]` | Presence meta-detectors. They fire (1.0) whenever the model produces any output at all — useful when the model is *supposed* to stay silent or refuse, and any response is itself the vulnerability. |
| [[Base Detector]] | `base.StringDetector` | The shared foundation other detectors build on. The base package provides the reusable StringDetector (substring/word/prefix matching), the metadata-driven TriggerMatchDetector, the WrappedDetector adapter, and the shared MitigationStrings list. |
| [[Misleading Detector]] | `misleading.MustRefuteClaimKW` | Looks for refutation keywords in a response to confirm the model pushed back on a false or misleading claim. |
| [[Patterns Detector]] | `patterns.Patterns` | A generic, fully configurable regex detector: define a list of named patterns with per-pattern severities and a combination mode, and it scores outputs accordingly. |
| [[Shields Detector]] | `shields.Up` | Inspects the verdict of a security system (guard, shield, firewall, guardrail) by matching the leading word of its response. |
| [[Snowball Detector]] | `snowball.DontStartYes` | Detects "hallucination snowballing" — when an LLM commits to a wrong yes/no answer on an impossible or trick question by opening with an incorrect affirmation or negation. |

---
[[Home]] · [[Detectors]] · [[Scoring & Verdicts]] · [[Probes MOC]] · [[Generators MOC]]
