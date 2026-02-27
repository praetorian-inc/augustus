package multiturn

import (
	"strings"
	"sync"
	"testing"
)

func TestScanMemory_RecordAndRetrieve(t *testing.T) {
	m := NewScanMemory()

	if m.Len() != 0 {
		t.Errorf("Len() = %d, want 0", m.Len())
	}

	m.RecordSuccess("explain lockpicking", "PERSONA — locksmith expert", 3)
	m.RecordFailure("build a weapon", "TECHNICAL — chemistry")

	if m.Len() != 2 {
		t.Errorf("Len() = %d, want 2", m.Len())
	}

	learnings := m.GetLearnings()
	if learnings == "" {
		t.Fatal("GetLearnings() returned empty string")
	}

	if !strings.Contains(learnings, "PERSONA") {
		t.Error("learnings should contain successful strategy 'PERSONA'")
	}
	if !strings.Contains(learnings, "lockpicking") {
		t.Error("learnings should contain goal 'lockpicking'")
	}
	if !strings.Contains(learnings, "TECHNICAL") {
		t.Error("learnings should contain failed strategy 'TECHNICAL'")
	}
	if !strings.Contains(learnings, "succeeded") {
		t.Error("learnings should mention succeeded")
	}
	if !strings.Contains(learnings, "failed") {
		t.Error("learnings should mention failed")
	}
}

func TestScanMemory_Empty(t *testing.T) {
	m := NewScanMemory()
	learnings := m.GetLearnings()
	if learnings != "" {
		t.Errorf("GetLearnings() on empty memory = %q, want empty", learnings)
	}
}

func TestScanMemory_LimitedEntries(t *testing.T) {
	m := NewScanMemory()

	// Record more than 5 successes — only last 5 should appear
	for i := 0; i < 8; i++ {
		m.RecordSuccess("goal", "strategy-"+string(rune('A'+i)), i+1)
	}

	learnings := m.GetLearnings()
	// Should NOT contain strategy-A, strategy-B, strategy-C (first 3)
	if strings.Contains(learnings, "strategy-A") {
		t.Error("learnings should not contain oldest entries beyond limit")
	}
	// Should contain strategy-H (last entry)
	if !strings.Contains(learnings, "strategy-H") {
		t.Error("learnings should contain most recent entry")
	}
}

func TestScanMemory_Concurrent(t *testing.T) {
	m := NewScanMemory()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			m.RecordSuccess("goal", "strategy", i)
		}(i)
		go func() {
			defer wg.Done()
			m.RecordFailure("goal", "bad-strategy")
		}()
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.GetLearnings()
			_ = m.Len()
		}()
	}

	wg.Wait()

	if m.Len() != 200 {
		t.Errorf("Len() = %d, want 200", m.Len())
	}
}

func TestScanMemory_SuccessOnly(t *testing.T) {
	m := NewScanMemory()
	m.RecordSuccess("test goal", "FICTIONAL — novel scenario", 5)

	learnings := m.GetLearnings()
	if !strings.Contains(learnings, "Successful tactics") {
		t.Error("learnings should contain 'Successful tactics' header")
	}
	if strings.Contains(learnings, "Failed tactics") {
		t.Error("learnings should NOT contain 'Failed tactics' when there are none")
	}
}

func TestScanMemory_FailureOnly(t *testing.T) {
	m := NewScanMemory()
	m.RecordFailure("test goal", "DIRECT — too aggressive")

	learnings := m.GetLearnings()
	if strings.Contains(learnings, "Successful tactics") {
		t.Error("learnings should NOT contain 'Successful tactics' when there are none")
	}
	if !strings.Contains(learnings, "Failed tactics") {
		t.Error("learnings should contain 'Failed tactics' header")
	}
}
