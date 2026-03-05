// Package memory provides scan-wide learning persistence for multi-turn attacks,
// recording which tactics succeeded or failed across test cases.
package memory

import (
	"fmt"
	"strings"
	"sync"
)

// ScanMemory persists successful and failed tactics across test cases within a scan.
// It is safe for concurrent use.
type ScanMemory struct {
	mu        sync.RWMutex
	successes []entry
	failures  []entry
}

type entry struct {
	Goal      string
	Strategy  string
	TurnCount int
}

// New creates a new empty ScanMemory.
func New() *ScanMemory {
	return &ScanMemory{}
}

// RecordSuccess stores a tactic that achieved the success threshold.
func (m *ScanMemory) RecordSuccess(goal, strategy string, turnCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.successes = append(m.successes, entry{
		Goal:      goal,
		Strategy:  strategy,
		TurnCount: turnCount,
	})
}

// RecordFailure stores a tactic that did not achieve the success threshold.
func (m *ScanMemory) RecordFailure(goal, strategy string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures = append(m.failures, entry{
		Goal:     goal,
		Strategy: strategy,
	})
}

// GetLearnings returns a formatted summary of what worked and what didn't
// across prior test cases. Returns empty string if no learnings are available.
func (m *ScanMemory) GetLearnings() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.successes) == 0 && len(m.failures) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("SCAN-WIDE LEARNINGS FROM PRIOR TEST CASES:\n")

	if len(m.successes) > 0 {
		sb.WriteString("  Successful tactics:\n")
		// Show last 5 successes to keep prompt size bounded
		start := len(m.successes) - 5
		if start < 0 {
			start = 0
		}
		for _, s := range m.successes[start:] {
			sb.WriteString(fmt.Sprintf("    - Strategy %q succeeded on goal %q in %d turns\n",
				s.Strategy, truncateStr(s.Goal, 80), s.TurnCount))
		}
	}

	if len(m.failures) > 0 {
		sb.WriteString("  Failed tactics:\n")
		// Show last 5 failures
		start := len(m.failures) - 5
		if start < 0 {
			start = 0
		}
		for _, f := range m.failures[start:] {
			sb.WriteString(fmt.Sprintf("    - Strategy %q failed on goal %q\n",
				f.Strategy, truncateStr(f.Goal, 80)))
		}
	}

	sb.WriteString("\nUse these learnings: prioritize strategies that worked, avoid strategies that failed.\n")
	return sb.String()
}

// Len returns the total number of recorded entries.
func (m *ScanMemory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.successes) + len(m.failures)
}

// truncateStr shortens a string to maxLen with ellipsis.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
