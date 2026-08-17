package observed

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func res(text string) types.ToolResult { return types.ToolResult{Text: text} }

func param(path, typ string) toolsig.Param {
	return toolsig.Param{Path: toolsig.Path(path), Type: typ}
}

// The core flow: a value returned by a listing tool fills a parameter of
// another tool that no schema could have supplied.
func TestObservedValueFillsAParameter(t *testing.T) {
	s := New()
	s.Record("identity-a", "list_records", res(`{"records":[{"record_id":"C-42","title":"x"}]}`))

	v, ok := s.Source("identity-a").Value(param("params.record_id", "string"))
	if !ok || v != "C-42" {
		t.Errorf("value = %v (ok=%v), want C-42", v, ok)
	}
}

// The safety property. An authorization probe works by replaying one identity's
// object under another's session; if ordinary calls could be auto-filled across
// identities, the scanner would manufacture cross-identity access out of its own
// plumbing and mask the real thing.
func TestIdentityIsolation(t *testing.T) {
	s := New()
	s.Record("identity-a", "list_records", res(`{"record_id":"A-1"}`))
	s.Record("identity-b", "list_records", res(`{"record_id":"B-1"}`))

	p := param("record_id", "string")

	if v, _ := s.Source("identity-a").Value(p); v != "A-1" {
		t.Errorf("identity-a saw %v, want its own A-1", v)
	}
	if v, _ := s.Source("identity-b").Value(p); v != "B-1" {
		t.Errorf("identity-b saw %v, want its own B-1", v)
	}
	if v, ok := s.Source("identity-c").Value(p); ok {
		t.Errorf("an identity that observed nothing got %v; it must get nothing", v)
	}
}

// Crossing identities has to be asked for by name.
func TestCrossIdentityIsExplicit(t *testing.T) {
	s := New()
	s.Record("victim", "list_records", res(`{"record_id":"VICTIM-1"}`))

	p := param("record_id", "string")
	if _, ok := s.Source("attacker").Value(p); ok {
		t.Fatal("the attacker's ordinary source must not see the victim's value")
	}

	v, ok := s.SourceFrom("victim").Value(p)
	if !ok || v != "VICTIM-1" {
		t.Errorf("explicit cross-identity value = %v (ok=%v), want VICTIM-1", v, ok)
	}
	if name := s.SourceFrom("victim").Name(); name != "observed:victim" {
		t.Errorf("provenance = %q; a crossed source must be distinguishable in output", name)
	}
}

// Matching runs exact, then normalised, then entity — and nothing looser.
func TestMatchingPrecedence(t *testing.T) {
	t.Run("normalised key", func(t *testing.T) {
		s := New()
		s.Record("a", "t", res(`{"recordId":"C-1"}`))
		if v, ok := s.Source("a").Value(param("record_id", "string")); !ok || v != "C-1" {
			t.Errorf("value = %v (ok=%v), want C-1 via case/separator-insensitive match", v, ok)
		}
	})

	t.Run("entity match on a bare id", func(t *testing.T) {
		s := New()
		s.Record("a", "t", res(`{"records":[{"id":"C-9"}]}`))
		if v, ok := s.Source("a").Value(param("record_id", "string")); !ok || v != "C-9" {
			t.Errorf("value = %v (ok=%v), want C-9 from records[].id", v, ok)
		}
	})

	t.Run("a bare id from an unrelated container is not used", func(t *testing.T) {
		s := New()
		s.Record("a", "t", res(`{"invoices":[{"id":"INV-1"}]}`))
		if v, ok := s.Source("a").Value(param("record_id", "string")); ok {
			t.Errorf("got %v; an id from an unrelated container is a guess, not a match", v)
		}
	})

	t.Run("no match for an unrelated name", func(t *testing.T) {
		s := New()
		s.Record("a", "t", res(`{"title":"hello"}`))
		if v, ok := s.Source("a").Value(param("record_id", "string")); ok {
			t.Errorf("got %v; matching must not fall back to any string", v)
		}
	})
}

// A value of the wrong type fails validation and tests nothing, so it is not
// offered.
func TestTypeCompatibility(t *testing.T) {
	s := New()
	s.Record("a", "t", res(`{"limit":25,"label":"x"}`))

	if v, ok := s.Source("a").Value(param("limit", "integer")); !ok || v != float64(25) {
		t.Errorf("integer param got %v (ok=%v), want 25", v, ok)
	}
	if _, ok := s.Source("a").Value(param("limit", "string")); ok {
		t.Error("a number must not be offered for a string parameter")
	}
	if _, ok := s.Source("a").Value(param("label", "integer")); ok {
		t.Error("a string must not be offered for an integer parameter")
	}
}

// The most recently seen value wins: it is the likeliest to still be valid.
func TestMostRecentWins(t *testing.T) {
	s := New()
	s.Record("a", "t", res(`{"room_id":"OLD"}`))
	s.Record("a", "t", res(`{"room_id":"NEW"}`))

	if v, _ := s.Source("a").Value(param("room_id", "string")); v != "NEW" {
		t.Errorf("value = %v, want NEW", v)
	}
}

// Bounds: a listing tool can return thousands of rows, and the store must not
// grow with them.
func TestPerKeyCap(t *testing.T) {
	s := New()
	for i := 0; i < maxPerKey*3; i++ {
		s.Record("a", "t", res(`{"record_id":"C-`+itoa(i)+`"}`))
	}
	if got := len(s.Values("record_id")); got > maxPerKey {
		t.Errorf("kept %d values for one key, cap is %d", got, maxPerKey)
	}
}

// Oversized strings are prose or blobs, not identifiers.
func TestOversizedValuesAreSkipped(t *testing.T) {
	long := make([]byte, maxStringLen+10)
	for i := range long {
		long[i] = 'a'
	}
	s := New()
	s.Record("a", "t", res(`{"note":"`+string(long)+`"}`))
	if len(s.Values("note")) != 0 {
		t.Error("a value too long to be an identifier must not be stored")
	}
}

// Non-JSON output is ignored rather than mangled.
func TestNonJSONResponseIsIgnored(t *testing.T) {
	s := New()
	s.Record("a", "t", res("plain text, not JSON"))
	if s.Len() != 0 {
		t.Errorf("store holds %d keys after a non-JSON response, want 0", s.Len())
	}
}

// --- invoker decorator ------------------------------------------------------

type fakeInvoker struct {
	result types.ToolResult
	err    error
	calls  int
}

func (f *fakeInvoker) ListTools(context.Context) ([]map[string]any, error) { return nil, nil }
func (f *fakeInvoker) CallTool(context.Context, string, map[string]any) (types.ToolResult, error) {
	f.calls++
	return f.result, f.err
}

// Recording is a decorator so that no call site has to remember to feed the
// store; forgetting would be silent.
func TestWrapRecordsEveryResponse(t *testing.T) {
	s := New()
	inner := &fakeInvoker{result: res(`{"room_id":"R-1"}`)}
	inv := Wrap(inner, s, "identity-a")

	if _, err := inv.CallTool(context.Background(), "get_rooms", nil); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if v, ok := s.Source("identity-a").Value(param("room_id", "string")); !ok || v != "R-1" {
		t.Errorf("value = %v (ok=%v), want R-1 recorded by the wrapper", v, ok)
	}
	if inner.calls != 1 {
		t.Errorf("inner invoker called %d times, want 1", inner.calls)
	}
}

// A rejection often names what the server would have accepted, which is as
// usable as anything a success returns.
func TestWrapRecordsToolErrors(t *testing.T) {
	s := New()
	inv := Wrap(&fakeInvoker{result: types.ToolResult{
		Text: `{"error":"invalid action","allowed_action":"read"}`, IsError: true,
	}}, s, "a")

	if _, err := inv.CallTool(context.Background(), "t", nil); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if v, ok := s.Source("a").Value(param("allowed_action", "string")); !ok || v != "read" {
		t.Errorf("value = %v (ok=%v); a tool-level error still carries a payload worth reading", v, ok)
	}
}

// A transport failure carries no payload, so there is nothing to record.
func TestWrapIgnoresTransportFailures(t *testing.T) {
	s := New()
	inv := Wrap(&fakeInvoker{err: errors.New("connection reset")}, s, "a")
	if _, err := inv.CallTool(context.Background(), "t", nil); err == nil {
		t.Fatal("expected the transport error to be returned")
	}
	if s.Len() != 0 {
		t.Errorf("store holds %d keys after a transport failure, want 0", s.Len())
	}
}

// Recording is opt-in; without a store the invoker is handed back untouched.
func TestWrapWithoutStoreIsAPassthrough(t *testing.T) {
	inner := &fakeInvoker{}
	if got := Wrap(inner, nil, "a"); got != types.ToolInvoker(inner) {
		t.Error("a nil store must return the invoker unchanged")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// The cap is per identity, not per key. Identities are recorded one session
// after another, so a shared cap lets the last session seen evict everything the
// first recorded under the same key — the primary identity's values vanishing
// because a victim session happened to return more of its own.
func TestPerKeyCapIsPerIdentity(t *testing.T) {
	s := New()
	s.Record("primary", "list", res(`{"record_id":"PRIMARY-1"}`))
	for i := 0; i < maxPerKey*2; i++ {
		s.Record("victim", "list", res(`{"record_id":"VICTIM-`+itoa(i)+`"}`))
	}

	v, ok := s.Source("primary").Value(param("record_id", "string"))
	if !ok || v != "PRIMARY-1" {
		t.Errorf("primary value = %v (ok=%v), want PRIMARY-1; another identity's history must not evict it", v, ok)
	}
	victim := 0
	for _, val := range s.Values("record_id") {
		if val.Identity == "victim" {
			victim++
		}
	}
	if victim > maxPerKey {
		t.Errorf("victim kept %d values, cap is %d", victim, maxPerKey)
	}
}

// The distinct-key budget is per identity. A global one lets the first identity
// fill it and then silently starve every later one, so a victim's identifiers
// never reach Source(victim) and the authorization probe emits no tests.
func TestKeyBudgetIsPerIdentity(t *testing.T) {
	s := New()
	for i := 0; i < maxKeys+50; i++ {
		s.Record("primary", "t", res(`{"k`+itoa(i)+`":"v"}`))
	}
	s.Record("victim", "t", res(`{"record_id":"VICTIM-1"}`))

	v, ok := s.Source("victim").Value(param("record_id", "string"))
	if !ok || v != "VICTIM-1" {
		t.Errorf("victim value = %v (ok=%v); one identity filling the budget must not starve another", v, ok)
	}
}
