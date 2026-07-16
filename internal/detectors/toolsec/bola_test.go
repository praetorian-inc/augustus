package toolsec

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// stubJudge is an inline test double implementing generators.Generator. It records
// the last conversation it was asked to judge so tests can assert the P/N/T
// calibration reached the prompt.
type stubJudge struct {
	verdict  string
	err      error
	calls    int
	lastConv *attempt.Conversation
}

func (s *stubJudge) Generate(_ context.Context, conv *attempt.Conversation, _ int) ([]attempt.Message, error) {
	s.calls++
	s.lastConv = conv
	if s.err != nil {
		return nil, s.err
	}
	return []attempt.Message{{Content: s.verdict}}, nil
}
func (s *stubJudge) ClearHistory()       {}
func (s *stubJudge) Name() string        { return "stub.Judge" }
func (s *stubJudge) Description() string { return "stub judge" }

// newBOLADetector builds an unconfigured (no-judge) detector.
func newBOLADetector(t *testing.T) *BOLADetector {
	t.Helper()
	d, err := NewBOLADetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewBOLADetector: %v", err)
	}
	return d.(*BOLADetector)
}

// newBOLADetectorWithJudge injects a stub judge directly.
func newBOLADetectorWithJudge(j *stubJudge) *BOLADetector {
	return &BOLADetector{judgeGen: j}
}

// bolaAttempt builds an attempt carrying the probe-stamped evidence. nxID is the
// well-formed-nonexistent id used for the negative control (empty when there is
// no negative control).
func bolaAttempt(id, nxID, attack, neg, pos string) *attempt.Attempt {
	a := attempt.New("bola")
	a.Metadata["toolsec.tool"] = "get_object"
	a.Metadata[attempt.MetadataKeyBOLAID] = id
	if nxID != "" {
		a.Metadata[attempt.MetadataKeyBOLANonexistentID] = nxID
	}
	if neg != "" {
		a.Metadata[attempt.MetadataKeyBOLANegativeControl] = neg
	}
	if pos != "" {
		a.Metadata[attempt.MetadataKeyBOLAPositiveControl] = pos
	}
	a.AddOutput(attack)
	return a
}

func TestBOLADetector_Registered(t *testing.T) {
	if _, ok := detectors.Get("toolsec.BOLA"); !ok {
		t.Fatal("toolsec.BOLA not registered in the detector registry")
	}
}

// TestBOLADetector_Stage1Prune_Dialects proves the deterministic stage-1 prune is
// SERVER-AGNOSTIC: across four unrelated response dialects, when the target-id
// response equals the nonexistent-id response (after masking the id) the object
// was not served, so the attempt scores 0.0 WITHOUT any judge. Uses synthetic ids
// only; no engagement identifiers.
func TestBOLADetector_Stage1Prune_Dialects(t *testing.T) {
	cases := []struct {
		name   string
		id     string
		nxID   string // the id the probe used for the negative control
		attack string
		neg    string
	}{
		{
			name: "json not-found",
			id:   "obj_100", nxID: "obj_999",
			attack: `{"error":"not found","id":"obj_100"}`,
			neg:    `{"error":"not found","id":"obj_999"}`,
		},
		{
			name: "plain text error",
			id:   "100", nxID: "999",
			attack: "Error: order 100 not found",
			neg:    "Error: order 999 not found",
		},
		{
			name: "empty object both",
			id:   "obj_100", nxID: "obj_999",
			attack: "{}",
			neg:    "{}",
		},
		{
			name: "identical 403 forbidden",
			id:   "obj_100", nxID: "obj_999",
			attack: "403 forbidden",
			neg:    "403 forbidden",
		},
	}

	// A judge that would FLAG everything, to prove stage 1 culls before it runs.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := &stubJudge{verdict: `{"verdict":"leak"}`}
			d := newBOLADetectorWithJudge(j)
			a := bolaAttempt(tc.id, tc.nxID, tc.attack, tc.neg, "")
			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(scores) != 1 || scores[0] != 0.0 {
				t.Fatalf("stage-1 prune should score 0.0 (not served), got %v", scores)
			}
			if j.calls != 0 {
				t.Fatalf("stage-1 prune must not invoke the judge, calls=%d", j.calls)
			}
		})
	}
}

// TestBOLADetector_JudgePath_VerdictMapping: when the target-id response DIFFERS
// from the not-found baseline the survivor is escalated to the judge, and its
// verdict maps leak->1.0, denied->0.0, uncertain->0.5. The judge is invoked.
func TestBOLADetector_JudgePath_VerdictMapping(t *testing.T) {
	cases := []struct {
		name    string
		verdict string
		want    float64
	}{
		{"leak", `{"verdict":"leak"}`, 1.0},
		{"denied", `{"verdict":"denied"}`, 0.0},
		{"uncertain", `{"verdict":"uncertain"}`, 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := &stubJudge{verdict: tc.verdict}
			d := newBOLADetectorWithJudge(j)
			// Target returns a real object; negative control is a not-found — they differ.
			a := bolaAttempt("obj_100", "obj_999",
				`{"id":"obj_100","balance":4200,"holder":"someone"}`,
				`{"error":"not found","id":"obj_999"}`,
				`{"id":"obj_7","balance":10,"holder":"attacker"}`)
			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(scores) != 1 || scores[0] != tc.want {
				t.Fatalf("verdict %q -> scores %v, want %v", tc.verdict, scores, tc.want)
			}
			if j.calls != 1 {
				t.Fatalf("judge should be invoked exactly once, calls=%d", j.calls)
			}
		})
	}
}

// TestBOLADetector_JudgePromptCarriesCalibration: the survivor's judge prompt must
// contain the P, N and T responses so the judge can calibrate served vs denied on
// this server.
func TestBOLADetector_JudgePromptCarriesCalibration(t *testing.T) {
	j := &stubJudge{verdict: `{"verdict":"leak"}`}
	d := newBOLADetectorWithJudge(j)
	pos := `POS_own_object_marker`
	neg := `NEG_not_found_marker`
	attack := `ATK_target_object_marker`
	a := bolaAttempt("obj_100", "obj_999", attack, neg, pos)
	if _, err := d.Detect(context.Background(), a); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if j.lastConv == nil {
		t.Fatal("judge conversation was not captured")
	}
	var buf strings.Builder
	for _, m := range j.lastConv.ToMessages() {
		buf.WriteString(m.Content)
		buf.WriteString("\n")
	}
	prompt := buf.String()
	for _, want := range []string{pos, neg, attack, "get_object"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("judge prompt missing calibration token %q; prompt=%q", want, prompt)
		}
	}
}

// TestBOLADetector_NoJudge_SurvivorInconclusive: a stage-1 survivor with NO judge
// configured scores 0.5 — inconclusive, never a silent 0.0.
func TestBOLADetector_NoJudge_SurvivorInconclusive(t *testing.T) {
	d := newBOLADetector(t) // no judge
	a := bolaAttempt("obj_100", "obj_999",
		`{"id":"obj_100","balance":4200}`,
		`{"error":"not found","id":"obj_999"}`, "")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.5 {
		t.Fatalf("no-judge survivor should be inconclusive 0.5, got %v", scores)
	}
}

// TestBOLADetector_JudgeErrorInconclusive: a judge error fails to 0.5 (inconclusive),
// never a false negative.
func TestBOLADetector_JudgeErrorInconclusive(t *testing.T) {
	j := &stubJudge{err: context.DeadlineExceeded}
	d := newBOLADetectorWithJudge(j)
	a := bolaAttempt("obj_100", "obj_999",
		`{"id":"obj_100","balance":4200}`,
		`{"error":"not found","id":"obj_999"}`, "")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect should not propagate judge errors: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.5 {
		t.Fatalf("judge error must score inconclusive 0.5, got %v", scores)
	}
}

// TestBOLADetector_TransportErrorSafe: a transport-errored attempt scores 0.0.
func TestBOLADetector_TransportErrorSafe(t *testing.T) {
	j := &stubJudge{verdict: `{"verdict":"leak"}`}
	d := newBOLADetectorWithJudge(j)
	a := bolaAttempt("obj_100", "", "", "", "")
	a.SetError(errors.New("boom"))
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.0 {
		t.Fatalf("transport error must score 0.0, got %v", scores)
	}
	if j.calls != 0 {
		t.Fatalf("judge must not run on a transport error, calls=%d", j.calls)
	}
}

// TestBOLADetector_EmptyAttackSafe: an empty attack output scores 0.0.
func TestBOLADetector_EmptyAttackSafe(t *testing.T) {
	d := newBOLADetector(t)
	a := attempt.New("bola")
	a.Metadata[attempt.MetadataKeyBOLAID] = "obj_100"
	a.AddOutput("   ")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.0 {
		t.Fatalf("empty attack must score 0.0, got %v", scores)
	}
}

// TestBOLADetector_NumericIDPrune: stage-1 works with numeric ids too (S6).
func TestBOLADetector_NumericIDPrune(t *testing.T) {
	j := &stubJudge{verdict: `{"verdict":"leak"}`}
	d := newBOLADetectorWithJudge(j)
	a := bolaAttempt("2", "9999999999",
		`{"error":"not found","id":"2"}`,
		`{"error":"not found","id":"9999999999"}`, "")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.0 {
		t.Fatalf("numeric-id not-found should prune to 0.0, got %v", scores)
	}
}

// TestBOLADetector_NoNegativeControl: without a negative control the prune cannot
// run; a non-empty served-shaped attack goes to the judge (or 0.5 with none).
func TestBOLADetector_NoNegativeControl(t *testing.T) {
	d := newBOLADetector(t) // no judge
	a := bolaAttempt("obj_100", "", `{"id":"obj_100","balance":1}`, "", "")
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.5 {
		t.Fatalf("no negative control + no judge should be inconclusive 0.5, got %v", scores)
	}
}

func TestParseBOLAVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want float64
	}{
		{"json leak", `{"verdict":"leak"}`, 1.0},
		{"json denied", `{"verdict":"denied"}`, 0.0},
		{"json uncertain", `{"verdict":"uncertain"}`, 0.5},
		{"json in fence", "```json\n{\"verdict\":\"leak\"}\n```", 1.0},
		{"substring leak", "the verdict is leak", 1.0},
		{"substring denied", "clearly denied here", 0.0},
		{"unparseable defaults uncertain", "I am not sure what happened", 0.5},
		{"case insensitive", `{"verdict":"LEAK"}`, 1.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseBOLAVerdict(tc.in); got != tc.want {
				t.Fatalf("parseBOLAVerdict(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewBOLADetector_NoJudgeWhenUnconfigured(t *testing.T) {
	d := newBOLADetector(t)
	if d.judgeGen != nil {
		t.Fatal("unconfigured detector must have no judge")
	}
}
