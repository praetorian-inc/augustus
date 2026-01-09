# Augustus vs Garak - Complete Gap Analysis

**Analysis Date**: 2026-01-06
**Last Updated**: 2026-01-08 (Session 17 completions)
**Analyst**: capability-lead
**Purpose**: Document every missing Garak capability and research enhancement

---

## Executive Summary

| Category    | Augustus | Garak | Gap  | Completion |
|-------------|----------|-------|------|------------|
| Probes      | 99       | 176   | 77   | 56%        |
| Generators  | 21       | 43    | 22   | 49%        |
| Detectors   | 75       | 89    | 14   | 84%        |
| Buffs       | 7        | 6     | 0    | 117%       |
| Harnesses   | 1        | 2     | 1    | 50%        |
| **Total**   | **203**  | **316** | **114** | **64%** |

**Research Enhancements**: 12 tasks remaining (FlipAttack ✅, Commercial Guardrails ✅, Neural Steg, etc.)

**Total Remaining Work**: ~280-320 tasks for 100% parity + research enhancements

> **Session 17 Progress (2026-01-08)**: +54 implementations added, +17% completion

---

## Part 1: Missing Garak Probes (77 remaining, was 98)

### 1.1 Tier 1: Simple Probes (No External Dependencies)

| Garak Probe | Module | Prompts | Priority | Est. Tasks | Status |
|-------------|--------|---------|----------|------------|--------|
| `test.Single` | test.py | 1 | Low | 1 | |
| `test.Nones` | test.py | 1 | Low | 1 | |
| `test.Lipsum` | test.py | 1 | Low | 1 | |
| `topic.WordnetBlockedWords` | topic.py | Dynamic | Medium | 2 | |
| `topic.WordnetAllowedWords` | topic.py | Dynamic | Medium | 2 | |
| `topic.WordnetControversial` | topic.py | Dynamic | Medium | 2 | |
| `apikey.CompleteKey` | apikey.py | 290 | High | 1 | ✅ Session 17 |

**Tier 1 Subtotal**: 6 probes remaining, ~9 tasks (was 7 probes, 10 tasks)

### 1.2 Tier 2: Template-Based Probes (Static Prompts)

| Garak Probe | Module | Prompts | Priority | Est. Tasks |
|-------------|--------|---------|----------|------------|
| `dan.AutoDANCached` | dan.py | Cached | Medium | 2 |
| `dan.AutoDAN` | dan.py | Generated | High | 3 |
| `dan.DanInTheWildFull` | dan.py | 1000+ | Low | 2 |
| `dan.DanInTheWild` | dan.py | 100 | Medium | 1 |
| `dan.Ablation_Dan_11_0` | dan.py | Variable | Low | 2 |
| `dra.DRA` | dra.py | Complex | High | 3 |
| `dra.DRAAdvanced` | dra.py | Complex | High | 3 |
| `leakreplay.LiteratureClozeFull` | leakreplay.py | 1000+ | Low | 2 |
| `leakreplay.LiteratureCloze` | leakreplay.py | 100 | Medium | 1 |
| `leakreplay.LiteratureCompleteFull` | leakreplay.py | 1000+ | Low | 2 |
| `leakreplay.LiteratureComplete` | leakreplay.py | 100 | Medium | 1 |
| `leakreplay.NYTClozeFull` | leakreplay.py | 1000+ | Low | 2 |
| `leakreplay.NYTCloze` | leakreplay.py | 100 | Medium | 1 |
| `leakreplay.NYTCompleteFull` | leakreplay.py | 1000+ | Low | 2 |
| `leakreplay.NYTComplete` | leakreplay.py | 100 | Medium | 1 |
| `leakreplay.GuardianClozeFull` | leakreplay.py | 1000+ | Low | 2 |
| `leakreplay.GuardianCloze` | leakreplay.py | 100 | Medium | 1 |
| `leakreplay.GuardianCompleteFull` | leakreplay.py | 1000+ | Low | 2 |
| `leakreplay.GuardianComplete` | leakreplay.py | 100 | Medium | 1 |
| `leakreplay.PotterClozeFull` | leakreplay.py | 1000+ | Low | 2 |
| `leakreplay.PotterCloze` | leakreplay.py | 100 | Medium | 1 |
| `leakreplay.PotterCompleteFull` | leakreplay.py | 1000+ | Low | 2 |
| `leakreplay.PotterComplete` | leakreplay.py | 100 | Medium | 1 |

**Tier 2 Subtotal**: 23 probes, ~36 tasks

### 1.3 Tier 3: API-Integrated Probes

| Garak Probe | Module | External API | Priority | Est. Tasks | Status |
|-------------|--------|--------------|----------|------------|--------|
| `atkgen.Tox` | atkgen.py | Perspective | High | 3 | |
| `doctor.Puppetry` | doctor.py | None | Medium | 2 | |
| `doctor.Bypass` | doctor.py | None | Medium | 2 | |
| `doctor.BypassLeet` | doctor.py | None | Medium | 2 | |
| `audio.AudioAchillesHeel` | audio.py | Audio model | Low | 3 | |
| `fileformats.HF_Files` | fileformats.py | HuggingFace | Low | 3 | |
| `visual_jailbreak.FigStepFull` | visual_jailbreak.py | Vision model | Medium | 3 | |
| `visual_jailbreak.FigStep` | visual_jailbreak.py | Vision model | Medium | 2 | |
| `sata.MLM` | sata.py | MLM model | Medium | 3 | |
| `fitd.FITD` | fitd.py | Iterative | High | 3 | |
| `exploitation.JinjaTemplatePythonInjection` | exploitation.py | None | High | 2 | ✅ Session 17 |
| `exploitation.SQLInjectionSystem` | exploitation.py | None | High | 2 | ✅ Session 17 |
| `exploitation.SQLInjectionEcho` | exploitation.py | None | High | 2 | ✅ Session 17 |

**Tier 3 Subtotal**: 10 probes remaining, ~26 tasks (was 13 probes, 32 tasks)

### 1.4 Tier 4: Complex/Iterative Probes

| Garak Probe | Module | Complexity | Priority | Est. Tasks |
|-------------|--------|------------|----------|------------|
| `suffix.BEAST` | suffix.py | High | High | 4 |
| `divergence.RepeatExtended` | divergence.py | Medium | Medium | 2 |
| `divergence.RepeatedToken` | divergence.py | Medium | Medium | 2 |
| `web_injection.MarkdownURINonImageExfilExtended` | web_injection.py | High | High | 3 |
| `web_injection.MarkdownURIImageExfilExtended` | web_injection.py | High | High | 3 |
| `latentinjection.LatentInjectionTranslationEnFrFull` | latentinjection.py | High | Medium | 3 |
| `latentinjection.LatentInjectionTranslationEnZhFull` | latentinjection.py | High | Medium | 3 |
| `latentinjection.LatentInjectionReportFull` | latentinjection.py | High | High | 3 |
| `latentinjection.LatentInjectionResumeFull` | latentinjection.py | High | High | 3 |
| `latentinjection.LatentInjectionFactSnippetEiffelFull` | latentinjection.py | High | Medium | 3 |
| `latentinjection.LatentInjectionFactSnippetLegalFull` | latentinjection.py | High | Medium | 3 |
| `latentinjection.LatentWhois` | latentinjection.py | Medium | Medium | 2 |
| `latentinjection.LatentWhoisSnippetFull` | latentinjection.py | High | Medium | 3 |
| `latentinjection.LatentWhoisSnippet` | latentinjection.py | Medium | Medium | 2 |
| Various Non-Full variants | latentinjection.py | Medium | Medium | 8 |

**Tier 4 Subtotal**: 15 probes, ~43 tasks

### 1.5 Encoding Probes (Missing Variants)

| Garak Probe | Module | Encoding Type | Priority | Est. Tasks | Status |
|-------------|--------|---------------|----------|------------|--------|
| `encoding.InjectQP` | encoding.py | Quoted-Printable | Medium | 1 | ✅ Session 17 |
| `encoding.InjectMime` | encoding.py | MIME | Medium | 1 | ✅ Session 17 |
| `encoding.InjectUnicodeVariantSelectors` | encoding.py | Unicode | High | 2 | |

**Encoding Subtotal**: 1 probe remaining, ~2 tasks (was 3 probes, 4 tasks)

### 1.6 Remaining Probe Categories

Based on Garak source analysis, approximately **40 additional probes** exist across:
- `grandma.*` variants not yet implemented
- `lmrc.*` variants (Bullying, Deadnaming)
- `badchars.*` advanced variants
- `web_injection.*` XSS/CSRF variants
- `phrasing.*` full variants

**Remaining Subtotal**: ~40 probes, ~60 tasks

### Probe Summary

| Category | Probes | Tasks | Completed |
|----------|--------|-------|-----------|
| Tier 1 (Simple) | 6 | 9 | 1 (apikey.CompleteKey) |
| Tier 2 (Template) | 23 | 36 | 0 |
| Tier 3 (API) | 10 | 26 | 3 (exploitation.*) |
| Tier 4 (Complex) | 15 | 43 | 0 |
| Encoding | 1 | 2 | 2 (InjectQP, InjectMime) |
| Remaining | 40 | 60 | 0 |
| **Total** | **~77** | **~176** | **6 probes** |

> Note: FlipAttack (16 variants) was added as research enhancement, now complete.

---

## Part 2: Missing Garak Generators (22 remaining, was 33)

> Note: Augustus has 21 generators implemented (9 more than originally documented).
> Several generators were previously undocumented: groq, deepinfra, rest, mistral, together, nim, test.Repeat, test.Blank, ollama.OllamaChat

### 2.1 Cloud/Enterprise Providers

| Generator | Module | API Type | Priority | Est. Tasks | Status |
|-----------|--------|----------|----------|------------|--------|
| `azure.AzureOpenAI` | azure.py | OpenAI-compatible | High | 3 | |
| `watsonx.WatsonX` | watsonx.py | IBM API | Medium | 3 | |
| `nemo.NeMo` | nemo.py | NVIDIA NeMo | Medium | 3 | |
| `nvcf.NvcfChat` | nvcf.py | NVIDIA Cloud | Medium | 3 | |

**Cloud Subtotal**: 4 generators, 12 tasks

### 2.2 Framework Integrations

| Generator | Module | Framework | Priority | Est. Tasks | Status |
|-----------|--------|-----------|----------|------------|--------|
| `litellm.LiteLLM` | litellm.py | LiteLLM | High | 3 | ✅ Session 17 |
| `langchain.LangChain` | langchain.py | LangChain | Medium | 3 | |
| `langchain_serve.LangChainServe` | langchain_serve.py | LangChain | Low | 2 | |
| `guardrails.NeMoGuardrails` | guardrails.py | NeMo Guardrails | Medium | 3 | |

**Framework Subtotal**: 3 generators remaining, 8 tasks (was 4 generators, 11 tasks)

### 2.3 Local/Edge Providers

| Generator | Module | Type | Priority | Est. Tasks | Status |
|-----------|--------|------|----------|------------|--------|
| `ggml.Ggml` | ggml.py | GGML/GGUF | High | 3 | |
| `huggingface.Pipeline` | huggingface.py | Local HF | High | 3 | ✅ Session 17 |
| `huggingface.LLaVA` | huggingface.py | VLM | Medium | 4 | |
| `rasa.RasaRest` | rasa.py | Rasa NLU | Low | 2 | |

**Local Subtotal**: 3 generators remaining, 9 tasks (was 4 generators, 12 tasks)

### 2.4 OpenAI Variants

| Generator | Module | Type | Priority | Est. Tasks |
|-----------|--------|------|----------|------------|
| `openai.OpenAIReasoning` | openai.py | o1/o3 models | High | 2 |
| `replicate.InferenceEndpoint` | replicate.py | Custom endpoints | Medium | 2 |

**OpenAI Subtotal**: 2 generators, 4 tasks

### 2.5 Test Generators

| Generator | Module | Purpose | Priority | Est. Tasks |
|-----------|--------|---------|----------|------------|
| `test.Single` | test.py | Returns single value | Low | 1 |
| `test.Nones` | test.py | Returns None | Low | 1 |
| `test.Lipsum` | test.py | Lorem ipsum | Low | 1 |
| `test.BlankVision` | test.py | Vision testing | Low | 1 |

**Test Subtotal**: 4 generators, 4 tasks

### 2.6 Additional Generators

Based on parity-manifest (43 total), approximately **15 additional generators** exist:
- Various model-specific variants
- API compatibility layers
- Streaming variants

**Additional Subtotal**: ~15 generators, ~25 tasks

### Generator Summary

| Category | Generators | Tasks | Completed |
|----------|------------|-------|-----------|
| Cloud/Enterprise | 4 | 12 | 0 |
| Framework | 3 | 8 | 1 (litellm.LiteLLM) |
| Local/Edge | 3 | 9 | 1 (huggingface.Pipeline) |
| OpenAI Variants | 2 | 4 | 0 |
| Test | 4 | 4 | 0 |
| Additional | 15 | 25 | 0 |
| **Total** | **~22** | **~62** | **2 generators** |

> Note: Gap reduced from 33 to 22 due to 9 previously undocumented generators + 2 Session 17 additions.

---

## Part 3: Missing Garak Detectors (14 remaining, was 35)

> Note: Augustus has 75 detectors implemented (21 more than originally documented).
> Includes comprehensive unsafe content (surge_profanity: 10, ofcom_offensive: 6), guardrail bypass (20), apikey (2), flipattack bypass (1), judge (2).

### 3.1 Content Safety Detectors

| Detector | Module | Detection Type | Priority | Est. Tasks | Status |
|----------|--------|----------------|----------|------------|--------|
| `unsafe_content.*` (multiple) | unsafe_content.py | Various categories | High | 8 | Mostly ✅ |
| `shields.Shields` | shields.py | Multiple shields | Medium | 3 | |

**Content Safety Subtotal**: ~5 detectors remaining, 6 tasks (was ~10 detectors, 11 tasks)

### 3.2 Specialized Detectors

| Detector | Module | Detection Type | Priority | Est. Tasks | Status |
|----------|--------|----------------|----------|------------|--------|
| `judge.Judge` | judge.py | LLM-as-judge | High | 3 | ✅ Session 17 |
| `fileformats.FileFormats` | fileformats.py | File detection | Low | 2 | |
| `visual_jailbreak.VisualJailbreak` | visual_jailbreak.py | VLM detection | Medium | 3 | |
| `misleading.Misleading` | misleading.py | False claims | Medium | 2 | |
| `exploitation.Exploitation` | exploitation.py | Exploit detection | High | 3 | ✅ Session 17 |

**Specialized Subtotal**: 3 detectors remaining, 7 tasks (was 5 detectors, 13 tasks)

### 3.3 Package Hallucination Detectors

| Detector | Module | Package Manager | Priority | Est. Tasks |
|----------|--------|-----------------|----------|------------|
| `packagehallucination.NPM` | packagehallucination.py | NPM | High | 2 |
| `packagehallucination.Go` | packagehallucination.py | Go modules | High | 2 |
| `packagehallucination.Rust` | packagehallucination.py | Crates.io | Medium | 2 |
| `packagehallucination.Dart` | packagehallucination.py | Pub.dev | Low | 2 |
| `packagehallucination.Perl` | packagehallucination.py | CPAN | Low | 2 |
| `packagehallucination.RakuLand` | packagehallucination.py | Raku | Low | 2 |

**Package Subtotal**: 6 detectors, 12 tasks

### 3.4 Web/Injection Detectors

| Detector | Module | Detection Type | Priority | Est. Tasks |
|----------|--------|----------------|----------|------------|
| `web_injection.XSS` | web_injection.py | XSS patterns | High | 2 |
| `web_injection.CSRF` | web_injection.py | CSRF patterns | High | 2 |
| `web_injection.URLInjection` | web_injection.py | URL patterns | Medium | 2 |
| `web_injection.MarkdownDetector` | web_injection.py | Markdown exfil | High | 2 |

**Web Subtotal**: 4 detectors, 8 tasks

### 3.5 Remaining Detectors

Based on Garak source (89 total - 54 implemented = 35 missing), approximately **10 additional detectors** exist:
- Various LMRC variants
- Snowball variants
- Always/base variants
- Leakreplay variants

**Remaining Subtotal**: ~10 detectors, ~15 tasks

### Detector Summary

| Category | Detectors | Tasks | Completed |
|----------|-----------|-------|-----------|
| Content Safety | 5 | 6 | ~5 (unsafe_content.*) |
| Specialized | 3 | 7 | 2 (judge.Judge, exploitation.*) |
| Package Hallucination | 6 | 12 | 0 |
| Web/Injection | 4 | 8 | 0 |
| Remaining | 0 | 0 | ~10 (already implemented) |
| **Total** | **~14** | **~33** | **~17 detectors** |

> Note: Gap reduced from 35 to 14 due to 21 previously undocumented detectors.

---

## Part 4: Missing Harnesses (1 needed)

| Harness | Module | Purpose | Priority | Est. Tasks |
|---------|--------|---------|----------|------------|
| `pxd.PXD` | pxd.py | Probe-times-detector | Medium | 3 |

**Harness Total**: 1 harness, 3 tasks

---

## Part 5: Research Enhancements (12 tasks remaining, was 19)

### 5.1 CRITICAL Priority

| Enhancement | Research Source | Success Rate | Tasks | Status |
|-------------|-----------------|--------------|-------|--------|
| FlipAttack Implementation | Keysight 2025 | 98% vs GPT-4o | 3 | ✅ Session 17 (16 variants) |
| Commercial Guardrail Testing | arXiv:2504.11168 | 100% bypass | 4 | ✅ (20 variants: 5 techniques × 4 targets) |

**Critical Subtotal**: 0 tasks remaining (was 7 tasks)

### 5.2 HIGH Priority

| Enhancement | Research Source | Success Rate | Tasks | Status |
|-------------|-----------------|--------------|-------|--------|
| Neural Steganography | arXiv 2025 | 31.8% | 3 | ⚠️ Partial (classical LSB done, neural missing) |
| System Prompt Extraction | Production studies | Common vector | 2 | ✅ Already covered across multiple probe families |

**High Subtotal**: ~2 tasks remaining (neural steg only)

### 5.3 MEDIUM Priority

| Enhancement | Research Source | Justification | Tasks | Status |
|-------------|-----------------|---------------|-------|--------|
| Domain-Specific Scenarios | Nature 2024 | Medical 100% vuln | 4 | ❌ Not started |
| HarmBench Integration | DeepSeek study | Standard benchmark | 3 | ❌ Not started |

**Medium Subtotal**: 7 tasks remaining

### Research Enhancement Summary

| Priority | Tasks | Completed |
|----------|-------|-----------|
| Critical | 0 | 7 (FlipAttack, Guardrails) |
| High | 2 | 3 (System Prompt Extraction) |
| Medium | 7 | 0 |
| **Total** | **12** | **10 tasks completed** |

---

## Part 6: Task Count Summary

### Phase 1: Foundation (Garak Parity)

| Component | Tasks |
|-----------|-------|
| Probe Implementation | 185 |
| Generator Implementation | 68 |
| Detector Implementation | 59 |
| Harness Implementation | 3 |
| Core Architecture | 8 |
| **Phase 1 Total** | **323** |

### Phase 2: Research Integration

| Component | Tasks |
|-----------|-------|
| FlipAttack | 3 |
| Commercial Guardrails | 4 |
| Neural Steganography | 3 |
| System Prompt Extraction | 2 |
| Domain-Specific Scenarios | 4 |
| HarmBench Integration | 3 |
| **Phase 2 Total** | **19** |

### Phase 3: Agent Security Testing

| Component | Tasks |
|-----------|-------|
| MCP/Tool Integration | 12 |
| Browsing Agent Attacks | 10 |
| Multi-Agent Systems | 8 |
| Agent-Specific Harness | 2 |
| **Phase 3 Total** | **32** |

### Phase 4: Production Infrastructure

| Component | Tasks |
|-----------|-------|
| Plugin Cache System | 5 |
| Concurrent Execution | 10 |
| Configuration System | 10 |
| Rate Limiting & Retry | 10 |
| Observability | 15 |
| Testing Infrastructure | 23 |
| **Phase 4 Total** | **73** |

### Grand Total

| Phase | Tasks |
|-------|-------|
| Phase 1: Foundation | 323 |
| Phase 2: Research | 19 |
| Phase 3: Agent Security | 32 |
| Phase 4: Infrastructure | 73 |
| **TOTAL** | **447** |

---

## Part 7: Quick Wins (Implement First)

### Highest Impact, Lowest Effort

1. ✅ **`apikey.CompleteKey`** - DONE Session 17 (290 prompts)
2. ✅ **`encoding.InjectQP`** - DONE Session 17
3. ✅ **`encoding.InjectMime`** - DONE Session 17
4. **`test.Single/Nones/Lipsum`** - 3 tasks, testing infrastructure
5. ✅ **`exploitation.*`** - DONE Session 17 (3 probes, 4 detectors)
6. ✅ **FlipAttack** - DONE Session 17 (16 variants)

### Dependencies to Unblock

1. ✅ **`litellm.LiteLLM`** - DONE Session 17 (100+ model support)
2. ✅ **`huggingface.Pipeline`** - DONE Session 17 (local testing)
3. ✅ **`judge.Judge`** - DONE Session 17 (LLM-as-judge + Refusal)
4. **`ggml.Ggml`** - Enables GGUF model testing

> **Session 17 Impact**: 5/6 quick wins completed, 3/4 dependencies unblocked.

---

## Part 8: Mapping to Plan Tasks

### Current docs/PLAN.yaml Structure (447 tasks)

✅ **Plan structure now matches recommendations:**

```
Phase 1: 323 tasks (Foundation/Garak Parity)
  - 1A: Core Architecture (8 tasks)
  - 1B: Generators (68 tasks)
  - 1C: Probe Tier 1-2 (46 tasks)
  - 1D: Probe Tier 3-4 (75 tasks)
  - 1E: Probe Remaining (64 tasks)
  - 1F: Detectors (59 tasks)
  - 1G: Harness (3 tasks)
Phase 2: 19 tasks (Research Integration) - 7 complete
Phase 3: 32 tasks (Agent Security Testing)
Phase 4: 73 tasks (Production Infrastructure)
```

### Plan Location

- **Source of truth**: `docs/PLAN.yaml`
- **This gap analysis**: `docs/GAPS.md` (detailed item-level reference)

---

## Metadata

```json
{
  "agent": "capability-lead",
  "output_type": "gap-analysis",
  "created": "2026-01-06T00:00:00Z",
  "updated": "2026-01-08T12:00:00Z",
  "updated_by": "capability-reviewer (audit)",
  "feature_directory": "/Users/nathansportsman/chariot-development-platform2/modules/augustus/docs",
  "skills_invoked": [
    "using-skills",
    "enforcing-evidence-based-analysis",
    "adhering-to-yagni",
    "writing-plans",
    "persisting-agent-outputs",
    "verifying-before-completion"
  ],
  "source_files_verified": [
    "research/parity-manifest.yaml",
    "docs/PLAN.yaml",
    "research/garak/garak/probes/*.py",
    "research/garak/garak/generators/*.py",
    "research/garak/garak/detectors/*.py",
    "internal/probes/**/*.go",
    "internal/generators/**/*.go",
    "internal/detectors/**/*.go"
  ],
  "status": "complete",
  "session_17_updates": {
    "probes_completed": ["apikey.CompleteKey", "encoding.InjectQP", "encoding.InjectMime", "exploitation.*", "flipattack.*"],
    "generators_completed": ["litellm.LiteLLM", "huggingface.Pipeline"],
    "detectors_completed": ["judge.Judge", "judge.Refusal", "exploitation.*", "flipattack.Bypass", "apikey.CompleteKey"],
    "research_completed": ["FlipAttack", "Commercial Guardrails", "System Prompt Extraction"]
  }
}
```
