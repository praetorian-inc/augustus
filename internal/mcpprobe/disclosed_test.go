package mcpprobe

import (
	"reflect"
	"testing"
)

// TestValuesFromResponse_EnumeratedAllowList is the case that matters most in the
// field: a helpful error message leaks the server's own allow-list. Harvesting it
// is target-derived discovery — the values come from the target at runtime — and is
// a standard technique, unlike copying a value out of a server's source.
func TestValuesFromResponse_EnumeratedAllowList(t *testing.T) {
	resp := "Error: System 'test' not found. Available systems: database, webserver, fileserver, admin-console"
	got := ValuesFromResponse(resp, []string{"test"})
	want := []string{"database", "webserver", "fileserver", "admin-console"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ValuesFromResponse() = %v, want %v", got, want)
	}
}

// TestValuesFromResponse_ExcludesSubmittedValues: a value the probe itself sent
// and the server echoed back is not a discovery. Re-trying it would waste calls
// and, worse, could make the probe compare a value against itself.
func TestValuesFromResponse_ExcludesSubmittedValues(t *testing.T) {
	resp := "Unknown mode 'admin'. Valid modes: read, write, admin"
	got := ValuesFromResponse(resp, []string{"admin"})
	if want := []string{"read", "write"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ValuesFromResponse() = %v, want %v (submitted value must be excluded)", got, want)
	}
}

// TestValuesFromResponse_QuotedAlternatives: quoted alternatives in a refusal are
// also the server declaring what it accepts.
func TestValuesFromResponse_QuotedAlternatives(t *testing.T) {
	resp := "Error: Invalid permission action. Use 'grant' or 'revoke'."
	got := ValuesFromResponse(resp, nil)
	if want := []string{"grant", "revoke"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ValuesFromResponse() = %v, want %v", got, want)
	}
}

// TestValuesFromResponse_IgnoresProse: an ordinary sentence must not be shredded
// into candidate values, or the probe would fire hundreds of meaningless calls at
// every target that returns a message.
func TestValuesFromResponse_IgnoresProse(t *testing.T) {
	for _, resp := range []string{
		"Connected to the database with standard privileges.",
		"An unexpected error occurred while processing your request, please try again later.",
		"Token 0123456789abcdef appears to be valid",
		"",
	} {
		if got := ValuesFromResponse(resp, nil); len(got) != 0 {
			t.Errorf("ValuesFromResponse(%q) = %v, want none", resp, got)
		}
	}
}

// TestValuesFromResponse_RequiresAtLeastTwoListItems: a single token after a colon
// is prose ("Status: connected"), not an enumeration of accepted values.
func TestValuesFromResponse_RequiresAtLeastTwoListItems(t *testing.T) {
	if got := ValuesFromResponse("Status: connected", nil); len(got) != 0 {
		t.Errorf("ValuesFromResponse() = %v, want none (a single item is not a list)", got)
	}
}

// TestValuesFromResponse_Bounded: a response listing a great many values must not
// turn one probe into an unbounded scan.
func TestValuesFromResponse_Bounded(t *testing.T) {
	resp := "Valid ids: a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20"
	got := ValuesFromResponse(resp, nil)
	if len(got) == 0 {
		t.Fatal("ValuesFromResponse() found nothing in a clear list")
	}
	if len(got) > maxDisclosedValues {
		t.Errorf("ValuesFromResponse() returned %d values, want at most %d", len(got), maxDisclosedValues)
	}
}

// TestValuesFromResponse_Deduplicates keeps the candidate set tidy.
func TestValuesFromResponse_Deduplicates(t *testing.T) {
	got := ValuesFromResponse("Valid: alpha, beta, alpha, beta", nil)
	if want := []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ValuesFromResponse() = %v, want %v", got, want)
	}
}
