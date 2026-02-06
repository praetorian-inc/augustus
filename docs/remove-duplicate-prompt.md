# Garak Python Compatibility Analysis: Dual-Field Design Verdict

## Executive Summary

**Finding:** NO - The dual-field design (Prompt/Prompts) is NOT for garak Python compatibility.

**Recommendation:** REMOVE the redundant `Prompts []string` field from Augustus's `Attempt` struct. The remediation plan can safely consolidate to a single field design.

---

## Evidence

### 1. garak `Attempt` Class (Python)

**Source:** `modules/garak/garak/attempt.py`

**Lines 282-290 - Prompt property (SINGULAR):**
```python
@property
def prompt(self) -> Union[Conversation, None]:
    if hasattr(self, "_prompt"):
        return self._prompt
    return None
```

**Lines 260-280 - JSON serialization uses singular "prompt":**
```python
def as_dict(self) -> dict:
    return {
        "entry_type": "attempt",
        "uuid": str(self.uuid),
        "seq": self.seq,
        "status": self.status,
        "probe_classname": self.probe_classname,
        "probe_params": self.probe_params,
        "targets": self.targets,
        "prompt": asdict(self.prompt),  # <-- SINGULAR key
        "outputs": [asdict(output) if output else None for output in self.outputs],
        ...
    }
```

**Key finding:** garak's `Attempt.as_dict()` outputs `"prompt"` (singular), NOT `"prompts"` (plural). There is no `prompts` field on the Attempt class.

### 2. garak `Probe` Class (Python)

**Source:** `modules/garak/garak/probes/base.py`

**Lines 382-384 - Probe has plural prompts internally:**
```python
prompts = copy.deepcopy(
    self.prompts  # <-- PLURAL attribute on Probe class
)
```

**Key finding:** `self.prompts` (plural) exists on the **Probe** class, not the **Attempt** class. Each prompt in `Probe.prompts` becomes a separate `Attempt` with a singular `prompt`.

### 3. Augustus `Attempt` Struct (Go)

**Source:** `pkg/attempt/attempt.go`

**Lines 39-43 - Dual-field design:**
```go
// Prompt is the input prompt (single-turn).
Prompt string `json:"prompt"`

// Prompts contains multiple prompts (multi-turn or batch).
Prompts []string `json:"prompts,omitempty"`
```

**Lines 74-86 - Constructor sets BOTH fields:**
```go
func New(prompt string) *Attempt {
    return &Attempt{
        Prompt:  prompt,
        Prompts: []string{prompt},  // <-- Redundant duplication
        ...
    }
}
```

**Key finding:** Augustus's design is NOT required for garak JSON compatibility. garak's serialized Attempt only has `"prompt"` (singular).

### 4. Augustus Equivalence Tests

**Source:** `tests/equivalence/types.go`

**Lines 10-13 - AttemptInput for detector testing:**
```go
type AttemptInput struct {
    Prompt  string   `json:"prompt"`   // SINGULAR
    Outputs []string `json:"outputs"`
}
```

**Lines 32-39 - ProbeResult for probe comparison:**
```go
type ProbeResult struct {
    Success         bool     `json:"success"`
    Name            string   `json:"capability_name"`
    Prompts         []string `json:"prompts"`          // PLURAL
    PrimaryDetector string   `json:"primary_detector"`
    ...
}
```

**Key finding:**
- `AttemptInput` uses singular `Prompt` (matching garak's Attempt)
- `ProbeResult` uses plural `Prompts` (matching garak's Probe.prompts)

These are **separate concepts** - Probe outputs a list of prompts, each prompt becomes an Attempt.

---

## Data Model Relationship

```
garak Python:
  Probe.prompts (plural, list)
       |
       v (each item)
  Attempt.prompt (singular)
       |
       v (serializes as)
  JSON: { "prompt": {...} }

Augustus Go (CURRENT - redundant):
  Attempt.Prompt (singular)
  Attempt.Prompts (plural) <-- UNNECESSARY for garak compat

Augustus Go (PROPOSED - clean):
  Attempt.Prompt (singular) - matches garak Attempt
  OR
  Attempt.Prompts (plural) - for multi-turn only
```

---

## Verdict

| Question | Answer |
|----------|--------|
| Does garak Attempt have `prompts` field? | **NO** - only `prompt` (singular) |
| Does garak serialize `"prompts"` key? | **NO** - only `"prompt"` |
| Is dual-field for JSON compatibility? | **NO** |
| Is dual-field for multi-turn support? | **Possibly** - but causes inconsistency |
| Safe to remove `Prompts` field? | **YES** - no compatibility concern |

---

## Recommendation for Remediation Plan

**REMOVE the redundant fields. Options:**

### Option A: Keep Singular Only (Recommended for Single-Turn)
```go
type Attempt struct {
    Prompt string `json:"prompt"`
    // Remove: Prompts []string
}
```
- Matches garak's Attempt serialization exactly
- Simpler, no synchronization needed

### Option B: Keep Plural Only (For Multi-Turn Support)
```go
type Attempt struct {
    Prompts []string `json:"prompts"`
    // Remove: Prompt string
}
```
- Add helper: `func (a *Attempt) FirstPrompt() string`
- Better for multi-turn conversations

### Option C: Use Conversations Field (Best Long-Term)

garak has evolved to use `Conversation` with `Turn` objects for multi-turn. Augustus should follow:
```go
type Attempt struct {
    Conversations []*Conversation `json:"conversations"`
    // Both Prompt and Prompts become computed properties
}
```

**Do NOT maintain both fields** - they create synchronization bugs and confusion.

---

## Metadata

```json
{
  "agent": "capability-lead",
  "output_type": "architecture-review",
  "timestamp": "2026-01-05T00:00:00Z",
  "feature_directory": ".claude/.output/agents/2026-01-05-garak-compatibility-analysis",
  "skills_invoked": [
    "using-skills",
    "semantic-code-operations",
    "calibrating-time-estimates",
    "enforcing-evidence-based-analysis",
    "gateway-capabilities",
    "persisting-agent-outputs",
    "verifying-before-completion"
  ],
  "library_skills_read": [],
  "source_files_verified": [
    "modules/garak/garak/attempt.py:156-438",
    "modules/garak/garak/probes/base.py:1-832",
    "pkg/attempt/attempt.go:1-180",
    "tests/equivalence/types.go:1-54",
    "tests/equivalence/compare.go:1-224",
    "tests/equivalence/python_harness.go:1-287"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Apply remediation - remove redundant Prompts field from Attempt struct"
  }
}
```
