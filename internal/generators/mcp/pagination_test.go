package mcp

import (
	"errors"
	"fmt"
	"testing"
)

// TestListAll_FollowsCursors: listAll accumulates items across every page,
// following nextCursor until it is empty.
func TestListAll_FollowsCursors(t *testing.T) {
	pages := map[string]struct {
		items []int
		next  string
	}{
		"":   {[]int{1, 2}, "c1"},
		"c1": {[]int{3}, "c2"},
		"c2": {[]int{4}, ""}, // last page
	}
	got, err := listAll(func(cursor string) ([]int, string, error) {
		p := pages[cursor]
		return p.items, p.next, nil
	})
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	if fmt.Sprint(got) != "[1 2 3 4]" {
		t.Errorf("got %v, want [1 2 3 4] (all pages followed)", got)
	}
}

// TestListAll_StopsOnCursorRepeat: a hostile/buggy server that returns the same
// non-empty cursor forever must not loop indefinitely.
func TestListAll_StopsOnCursorRepeat(t *testing.T) {
	calls := 0
	got, err := listAll(func(_ string) ([]int, string, error) {
		calls++
		return []int{calls}, "loop", nil // always the same next cursor
	})
	if err != nil {
		t.Fatalf("listAll: %v", err)
	}
	if calls > 2 {
		t.Errorf("cursor repeat not detected: %d calls (want <= 2)", calls)
	}
	if len(got) == 0 {
		t.Error("expected the first page's items to be retained")
	}
}

// TestListAll_PropagatesError: a page error is returned (with the pages gathered
// so far), not silently swallowed.
func TestListAll_PropagatesError(t *testing.T) {
	_, err := listAll(func(_ string) ([]int, string, error) {
		return nil, "", errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected the page error to propagate")
	}
}

// TestListAll_ErrorsOnPageCapExhaustion: a catalog that keeps emitting fresh
// unique cursors past the page budget must surface errListTruncated (with the
// items gathered so far) rather than silently reporting a complete enumeration.
func TestListAll_ErrorsOnPageCapExhaustion(t *testing.T) {
	n := 0
	items, err := listAll(func(_ string) ([]int, string, error) {
		n++
		return []int{n}, fmt.Sprintf("cursor-%d", n), nil // always a new unique cursor
	})
	if !errors.Is(err, errListTruncated) {
		t.Fatalf("expected errListTruncated on cap exhaustion, got %v", err)
	}
	if len(items) != maxListPages {
		t.Errorf("expected %d items gathered before the cap, got %d", maxListPages, len(items))
	}
}
