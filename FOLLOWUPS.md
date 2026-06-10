# Follow-ups from PR #55 audit

This PR (feature/tool-use-attack-probes) closed 8 of 9 findings from the
independent research validation of the tool-use probe suite. The ninth
(P2b) was intentionally deferred because it requires architectural
discussion before implementation, not just coding.

## Deferred: per-probe SuccessCriteria metadata + detector rename

**Finding:** scan-operator-configured `expected_tools` / `forbidden_tools`
at runtime is out of line with the agent-security benchmark consensus
(AgentDojo, InjecAgent, MCPTox) which all declare success criteria
per-test-case. Each of our 9 probes has its own threat model; forcing
them to share one scan-wide config is the structural cause of the
detection gaps this PR otherwise fixed.

**What would change:**

1. New `info.success_criteria` YAML field on each probe:
   ```yaml
   info:
     success_criteria:
       detectors:
         - name: agent.ToolAllowlist
           expected_tools: [...]
           forbidden_tools: [...]
         - name: agent.ArgumentExfiltration
           forbidden_patterns: [...]
   ```

2. `pkg/templates/` loader parses `success_criteria` into structured data
   on `Template` struct.

3. Scanner (or a new probe-to-detector binding layer) reads probe
   metadata at scan time and configures detectors per-probe, overriding
   any scan-wide default when a probe declares its own criteria.

4. Rename `agent.ToolManipulation` to `agent.ToolAllowlist` with a
   back-compat alias so existing scan configs continue to work. The new
   name better reflects what the detector actually does (whitelist /
   blacklist filtering) vs. the broader "manipulation" framing.

**Why deferred:**

- Changes the scanner's config flow in a way that touches multiple
  packages (`pkg/scanner`, `pkg/templates`, `pkg/registry`, every
  probe YAML).
- Needs a decision on precedence: does probe-declared criteria override,
  merge with, or fall back to scan-wide config?
- Existing scan users with external `--detector-config` will need a
  migration path.

**Suggested plan:**

1. Author a short ADR covering the precedence rule.
2. Extend `templates.Template` with the optional `SuccessCriteria` block.
3. Add a new `scanner` helper that composes probe metadata + scan config
   into the per-attempt detector config.
4. Migrate all 14 tool-use probes to declare their own criteria.
5. Rename and add alias.

## Probes intentionally remaining on agent.ToolManipulation

Three probes remain wired to `agent.ToolManipulation` and that is the correct
design choice:

- `tool.UnauthorizedInvocation` — threat model is an agent invoking a tool
  whose name the operator declares forbidden (e.g., `maintenance_shell`).
  Name-based scoring is the correct fit; detecting the name is the signal.
- `tool.FunctionCallingJailbreak` — threat model is an agent calling an
  unrestricted or jailbreak-specific tool (e.g., `unrestricted_query`).
  Again, the tool name is the security-relevant signal.
- `tool.OnboardingPoisoning` — threat model is an agent calling an admin-
  scoped tool (e.g., `admin_query`) that the operator marked forbidden during
  the onboarding phase. Name-based detection is appropriate.

These three probes require operator-supplied `expected_tools` / `forbidden_tools`
config to produce a non-zero score, and that is an accepted design choice:
operators must declare what is forbidden for the scanner to detect it.
This differs from the now-corrected wiring of the argument-level probes
(ChainAmplification was already on agent.ChainLength; DataExfiltration,
MCPSupplyChainPoisoning, SchemaMutation, MemoryPoisoning, CrossAgentPropagation,
and ConfusedDeputyTokenReuse are now on agent.ArgumentExfiltration) whose
threat models match argument-content scoring, not tool-name scoring.

## Other low-priority items noted during the audit

- Log-To-Leak (OpenReview UVgbFuXPaO) PDF is 403-blocked; specific ASR
  numbers could not be independently verified. Consider finding an
  accessible mirror or a replacement primary source for the
  `tool.DataExfiltration` probe's citation.

- Benchmark scale: augustus ships ~35 tool-use prompts across 14 probes,
  vs InjecAgent (1,054 test cases), MCPTox (1,312 cases). This is a
  property of being a probe scanner rather than a benchmark, but worth
  documenting for users who want coverage numbers comparable to academic
  literature.
