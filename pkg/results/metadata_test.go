package results

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// TestAttemptResult_CarriesCoverageMetadata: a report has to be able to say
// which tool and which parameter an attempt actually tested. Reconstructing that
// from the target's responses is unsound — a call the server never processed
// leaves nothing to reconstruct from, so exactly the attempts whose coverage is
// in doubt are the ones that cannot be accounted for.
func TestAttemptResult_CarriesCoverageMetadata(t *testing.T) {
	a := attempt.New("payload")
	a.Probe = "mcptool.Injection"
	a.Metadata["mcptool.tool"] = "fetch_object"
	a.Metadata["mcptool.param"] = "params.object_id"
	a.Complete()

	line, err := json.Marshal(ToAttemptResult(a))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	md, ok := got["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("the JSONL line carries no metadata object: %s", line)
	}
	if md["mcptool.tool"] != "fetch_object" {
		t.Errorf("metadata[mcptool.tool] = %v, want %q", md["mcptool.tool"], "fetch_object")
	}
	if md["mcptool.param"] != "params.object_id" {
		t.Errorf("metadata[mcptool.param] = %v, want the PATH %q, which a bare leaf name cannot express", md["mcptool.param"], "params.object_id")
	}
}

// TestAttemptResult_OmitsEmptyMetadata keeps the format backward compatible: an
// attempt that recorded nothing produces exactly the line it always did, so a
// consumer written against the previous shape is unaffected.
func TestAttemptResult_OmitsEmptyMetadata(t *testing.T) {
	a := attempt.New("hello")
	a.Complete()

	line, err := json.Marshal(ToAttemptResult(a))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := got["metadata"]; present {
		t.Errorf("an attempt with no metadata emitted a metadata key: %s", line)
	}
}

// unencodable is a value the JSON encoder rejects.
type unencodable struct{ ch chan int }

// TestAttemptResult_OneBadValueDoesNotCostTheWholeLine: metadata is
// map[string]any and a probe may put anything in it. A single unencodable value
// would fail the encode for the entire attempt, so one careless probe would
// silently cost every other attempt in the run its output. The key survives as
// text instead.
func TestAttemptResult_OneBadValueDoesNotCostTheWholeLine(t *testing.T) {
	a := attempt.New("payload")
	a.Metadata["mcptool.tool"] = "get_object"
	a.Metadata["broken"] = unencodable{ch: make(chan int)}
	a.Complete()

	line, err := json.Marshal(ToAttemptResult(a))
	if err != nil {
		t.Fatalf("one unencodable metadata value failed the whole line: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	md, _ := got["metadata"].(map[string]any)
	if md["mcptool.tool"] != "get_object" {
		t.Errorf("the encodable keys did not survive: %s", line)
	}
	if _, present := md["broken"]; !present {
		t.Error("the unencodable key vanished; a lost record of what was tested must not be silent")
	}
}
