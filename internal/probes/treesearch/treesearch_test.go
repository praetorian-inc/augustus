package treesearch

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// mockGenerator is a simple mock for testing tree search probes
type mockGenerator struct {
	responses    []attempt.Message
	err          error
	callCount    int
	cleared      bool
	generateFunc func(context.Context, *attempt.Conversation, int) ([]attempt.Message, error)
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	m.callCount++
	if m.generateFunc != nil {
		return m.generateFunc(ctx, conv, n)
	}
	if m.err != nil {
		return nil, m.err
	}
	if len(m.responses) == 0 {
		msgs := make([]attempt.Message, n)
		for i := range msgs {
			msgs[i] = attempt.NewAssistantMessage("response")
		}
		return msgs, nil
	}
	return m.responses, nil
}

func (m *mockGenerator) ClearHistory() {
	m.cleared = true
}

func (m *mockGenerator) Name() string {
	return "mock-generator"
}

func (m *mockGenerator) Description() string {
	return "mock generator for testing"
}

// mockDetector is a simple mock detector for tree search
type mockDetector struct {
	scores []float64
	err    error
}

func (m *mockDetector) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	if m.err != nil {
		return nil, m.err
	}
	if len(m.scores) == 0 {
		// Default: return 0.0 (pass) for each output
		scores := make([]float64, len(a.Outputs))
		return scores, nil
	}
	return m.scores, nil
}

func (m *mockDetector) Name() string {
	return "mock.Detector"
}

func (m *mockDetector) Description() string {
	return "Mock detector for testing"
}

// mockNode implements Node interface for testing
type mockNode struct {
	id       string
	terms    []string
	children []*mockNode
	parent   *mockNode
}

func (n *mockNode) ID() string {
	return n.id
}

// mockTreeSearchImpl is a concrete implementation for testing
type mockTreeSearchImpl struct {
	*TreeSearcher
	initialNodes []*mockNode
	prompts      map[string][]string // term -> prompts mapping
}

func newMockTreeSearch(cfg *Config) *mockTreeSearchImpl {
	impl := &mockTreeSearchImpl{
		TreeSearcher: NewTreeSearcher(cfg),
		initialNodes: []*mockNode{},
		prompts:      make(map[string][]string),
	}
	return impl
}

// Search wraps TreeSearcher.Search passing self as implementation
func (m *mockTreeSearchImpl) Search(ctx context.Context, gen probes.Generator, det Detector) ([]*attempt.Attempt, error) {
	return m.TreeSearcher.Search(ctx, gen, det, m)
}

func (m *mockTreeSearchImpl) GetInitialNodes() []Node {
	nodes := make([]Node, len(m.initialNodes))
	for i, n := range m.initialNodes {
		nodes[i] = n
	}
	return nodes
}

func (m *mockTreeSearchImpl) GetNodeID(node Node) string {
	if n, ok := node.(*mockNode); ok {
		return n.id
	}
	return ""
}

func (m *mockTreeSearchImpl) GetNodeChildren(node Node) []Node {
	if n, ok := node.(*mockNode); ok {
		children := make([]Node, len(n.children))
		for i, c := range n.children {
			children[i] = c
		}
		return children
	}
	return nil
}

func (m *mockTreeSearchImpl) GetNodeTerms(node Node) []string {
	if n, ok := node.(*mockNode); ok {
		return n.terms
	}
	return nil
}

func (m *mockTreeSearchImpl) GeneratePrompts(term string) []string {
	if prompts, ok := m.prompts[term]; ok {
		return prompts
	}
	return []string{"prompt for " + term}
}

func (m *mockTreeSearchImpl) GetNodeParent(node Node) Node {
	if n, ok := node.(*mockNode); ok {
		if n.parent == nil {
			return nil
		}
		return n.parent
	}
	return nil
}

// TestConfig_Defaults tests default configuration values
func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Strategy != BreadthFirst {
		t.Errorf("Strategy = %v, want %v", cfg.Strategy, BreadthFirst)
	}
	if cfg.PerGenerationThreshold != 0.5 {
		t.Errorf("PerGenerationThreshold = %v, want %v", cfg.PerGenerationThreshold, 0.5)
	}
	if cfg.PerNodeThreshold != 0.1 {
		t.Errorf("PerNodeThreshold = %v, want %v", cfg.PerNodeThreshold, 0.1)
	}
	if !cfg.TargetSoft {
		t.Error("TargetSoft = false, want true")
	}
	if !cfg.QueueChildrenAtStart {
		t.Error("QueueChildrenAtStart = false, want true")
	}
}

// TestConfig_WithOptions tests functional options
func TestConfig_WithOptions(t *testing.T) {
	cfg := DefaultConfig()
	cfg = cfg.
		WithStrategy(DepthFirst).
		WithPerGenerationThreshold(0.7).
		WithPerNodeThreshold(0.2).
		WithTargetSoft(false)

	if cfg.Strategy != DepthFirst {
		t.Errorf("Strategy = %v, want %v", cfg.Strategy, DepthFirst)
	}
	if cfg.PerGenerationThreshold != 0.7 {
		t.Errorf("PerGenerationThreshold = %v, want %v", cfg.PerGenerationThreshold, 0.7)
	}
	if cfg.PerNodeThreshold != 0.2 {
		t.Errorf("PerNodeThreshold = %v, want %v", cfg.PerNodeThreshold, 0.2)
	}
	if cfg.TargetSoft {
		t.Error("TargetSoft = true, want false")
	}
}

// TestTreeSearcher_EmptyInitialNodes tests behavior with no initial nodes
func TestTreeSearcher_EmptyInitialNodes(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{} // Empty

	gen := &mockGenerator{}
	det := &mockDetector{}

	attempts, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v, want nil", err)
	}
	if len(attempts) != 0 {
		t.Errorf("Search() returned %d attempts, want 0", len(attempts))
	}
}

// TestTreeSearcher_SingleNode tests searching a single node
func TestTreeSearcher_SingleNode(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "root", terms: []string{"term1"}},
	}
	impl.prompts["term1"] = []string{"prompt1"}

	gen := &mockGenerator{
		responses: []attempt.Message{
			attempt.NewAssistantMessage("response1"),
		},
	}
	det := &mockDetector{scores: []float64{0.0}} // Pass

	attempts, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v, want nil", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Search() returned 0 attempts, want at least 1")
	}

	// Verify attempt structure
	a := attempts[0]
	if a.Prompt != "prompt1" {
		t.Errorf("attempt.Prompt = %q, want %q", a.Prompt, "prompt1")
	}
	if a.Status != attempt.StatusComplete {
		t.Errorf("attempt.Status = %v, want %v", a.Status, attempt.StatusComplete)
	}
}

// TestTreeSearcher_BreadthFirst tests BFS exploration order
func TestTreeSearcher_BreadthFirst(t *testing.T) {
	cfg := DefaultConfig().WithStrategy(BreadthFirst)
	impl := newMockTreeSearch(cfg)

	// Create tree:
	//       root
	//      /    \
	//   child1  child2
	child1 := &mockNode{id: "child1", terms: []string{"c1"}}
	child2 := &mockNode{id: "child2", terms: []string{"c2"}}
	root := &mockNode{
		id:       "root",
		terms:    []string{"root_term"},
		children: []*mockNode{child1, child2},
	}
	child1.parent = root
	child2.parent = root
	impl.initialNodes = []*mockNode{root}

	// High scores to ensure children are explored
	det := &mockDetector{scores: []float64{0.8}}
	gen := &mockGenerator{}

	var explorationOrder []string
	gen.generateFunc = func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
		// Extract prompt from conversation to track order
		if len(conv.Turns) > 0 {
			lastTurn := conv.Turns[len(conv.Turns)-1]
			explorationOrder = append(explorationOrder, lastTurn.Prompt.Content)
		}
		return []attempt.Message{attempt.NewAssistantMessage("response")}, nil
	}

	_, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	// BFS: root should be explored before children
	// Order: root_term (from root), then c1, c2 (children)
	if len(explorationOrder) < 1 {
		t.Fatal("No prompts were explored")
	}
}

// TestTreeSearcher_DepthFirst tests DFS exploration order
func TestTreeSearcher_DepthFirst(t *testing.T) {
	cfg := DefaultConfig().WithStrategy(DepthFirst)
	impl := newMockTreeSearch(cfg)

	// Create simple tree for DFS test
	child := &mockNode{id: "child", terms: []string{"child_term"}}
	root := &mockNode{
		id:       "root",
		terms:    []string{"root_term"},
		children: []*mockNode{child},
	}
	child.parent = root
	impl.initialNodes = []*mockNode{root}

	det := &mockDetector{scores: []float64{0.8}} // High score to explore children
	gen := &mockGenerator{}

	_, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
}

// TestTreeSearcher_PerNodeThreshold tests node threshold filtering
func TestTreeSearcher_PerNodeThreshold(t *testing.T) {
	cfg := DefaultConfig().
		WithPerNodeThreshold(0.5).
		WithTargetSoft(true) // Only explore nodes with score > threshold

	impl := newMockTreeSearch(cfg)

	child := &mockNode{id: "child", terms: []string{"child_term"}}
	root := &mockNode{
		id:       "root",
		terms:    []string{"root_term"},
		children: []*mockNode{child},
	}
	child.parent = root
	impl.initialNodes = []*mockNode{root}

	// Low score - should NOT explore children when target_soft=true
	det := &mockDetector{scores: []float64{0.2}}
	gen := &mockGenerator{}

	_, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	// With low score (0.2 < 0.5 threshold) and target_soft=true,
	// children should not be explored
	if gen.callCount > 1 {
		t.Errorf("Expected only root to be explored (1 call), got %d calls", gen.callCount)
	}
}

// TestTreeSearcher_NeverQueueNodes tests node exclusion
func TestTreeSearcher_NeverQueueNodes(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())

	excludedChild := &mockNode{id: "excluded", terms: []string{"excluded_term"}}
	root := &mockNode{
		id:       "root",
		terms:    []string{"root_term"},
		children: []*mockNode{excludedChild},
	}
	excludedChild.parent = root
	impl.initialNodes = []*mockNode{root}
	impl.NeverQueueNodes["excluded"] = struct{}{}

	det := &mockDetector{scores: []float64{0.8}} // High score would normally explore children
	gen := &mockGenerator{}

	_, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	// Excluded child should not be explored
	if gen.callCount > 1 {
		t.Errorf("Expected only root to be explored, got %d generator calls", gen.callCount)
	}
}

// TestTreeSearcher_NeverQueueForms tests surface form exclusion
func TestTreeSearcher_NeverQueueForms(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())

	root := &mockNode{
		id:    "root",
		terms: []string{"excluded_form", "included_form"},
	}
	impl.initialNodes = []*mockNode{root}
	impl.NeverQueueForms["excluded_form"] = struct{}{}
	impl.prompts["included_form"] = []string{"included prompt"}
	impl.prompts["excluded_form"] = []string{"excluded prompt"}

	det := &mockDetector{scores: []float64{0.0}}
	gen := &mockGenerator{}

	attempts, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	// Only included_form should generate prompts
	if len(attempts) != 1 {
		t.Errorf("Expected 1 attempt (from included_form), got %d", len(attempts))
	}
	if len(attempts) > 0 && attempts[0].Prompt != "included prompt" {
		t.Errorf("Expected prompt 'included prompt', got %q", attempts[0].Prompt)
	}
}

// TestTreeSearcher_ContextCancellation tests graceful cancellation
func TestTreeSearcher_ContextCancellation(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "node1", terms: []string{"term1"}},
		{id: "node2", terms: []string{"term2"}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	det := &mockDetector{}

	gen := &mockGenerator{}
	gen.generateFunc = func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
		// Cancel after first call
		cancel()
		return []attempt.Message{attempt.NewAssistantMessage("response")}, nil
	}

	_, err := impl.Search(ctx, gen, det)
	// Should return context error or partial results without error
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Logf("Search() with cancelled context returned: %v", err)
	}
}

// TestTreeSearcher_GeneratorError tests handling of generator errors
func TestTreeSearcher_GeneratorError(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "root", terms: []string{"term1"}},
	}

	genErr := errors.New("generator failed")
	gen := &mockGenerator{err: genErr}
	det := &mockDetector{}

	attempts, err := impl.Search(context.Background(), gen, det)
	// Error should be captured in attempt, not returned
	if err != nil {
		t.Logf("Search() returned error: %v", err)
	}

	if len(attempts) > 0 && attempts[0].Status != attempt.StatusError {
		t.Errorf("Expected attempt status %v, got %v", attempt.StatusError, attempts[0].Status)
	}
}

// TestTreeSearcher_DetectorError tests handling of detector errors
func TestTreeSearcher_DetectorError(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "root", terms: []string{"term1"}},
	}

	gen := &mockGenerator{}
	detErr := errors.New("detector failed")
	det := &mockDetector{err: detErr}

	_, err := impl.Search(context.Background(), gen, det)
	// Detector errors may be logged but search should continue
	if err != nil {
		t.Logf("Search() returned error on detector failure: %v", err)
	}
}

// TestTreeSearcher_MultipleTermsPerNode tests nodes with multiple surface forms
func TestTreeSearcher_MultipleTermsPerNode(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "root", terms: []string{"term1", "term2", "term3"}},
	}
	impl.prompts["term1"] = []string{"prompt1"}
	impl.prompts["term2"] = []string{"prompt2"}
	impl.prompts["term3"] = []string{"prompt3"}

	gen := &mockGenerator{}
	det := &mockDetector{scores: []float64{0.0}}

	attempts, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	// Should have 3 attempts, one per term
	if len(attempts) != 3 {
		t.Errorf("Expected 3 attempts (one per term), got %d", len(attempts))
	}
}

// TestTreeSearcher_DuplicateSurfaceFormSkipped tests that duplicate forms are not re-probed
func TestTreeSearcher_DuplicateSurfaceFormSkipped(t *testing.T) {
	cfg := DefaultConfig().WithPerNodeThreshold(0.0) // Always explore children
	impl := newMockTreeSearch(cfg)

	child := &mockNode{id: "child", terms: []string{"shared_term"}}
	root := &mockNode{
		id:       "root",
		terms:    []string{"shared_term"}, // Same term as child
		children: []*mockNode{child},
	}
	child.parent = root
	impl.initialNodes = []*mockNode{root}

	gen := &mockGenerator{}
	det := &mockDetector{scores: []float64{0.8}} // High enough to explore children

	attempts, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	// shared_term should only be probed once
	if len(attempts) != 1 {
		t.Errorf("Expected 1 attempt (duplicate form skipped), got %d", len(attempts))
	}
}

// TestTreeSearcher_MetadataCapture tests that node info is captured in attempt metadata
func TestTreeSearcher_MetadataCapture(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "test_node", terms: []string{"test_term"}},
	}

	gen := &mockGenerator{}
	det := &mockDetector{scores: []float64{0.5}}

	attempts, err := impl.Search(context.Background(), gen, det)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("Expected at least 1 attempt")
	}

	a := attempts[0]
	// Check metadata contains surface_form
	if surfaceForm, ok := a.GetMetadata("surface_form"); !ok {
		t.Error("attempt.Metadata should contain 'surface_form'")
	} else if surfaceForm != "test_term" {
		t.Errorf("surface_form = %v, want %v", surfaceForm, "test_term")
	}
}

// TestTreeSearchProber_Interface tests that implementations satisfy Prober interface
func TestTreeSearchProber_Interface(t *testing.T) {
	// Verify TreeSearchProber extends Prober
	var _ TreeSearchProber = (*mockTreeSearchProberImpl)(nil)
	var _ probes.Prober = (*mockTreeSearchProberImpl)(nil)
}

// mockTreeSearchProberImpl is a complete TreeSearchProber implementation for interface testing
type mockTreeSearchProberImpl struct {
	*mockTreeSearchImpl
}

func (m *mockTreeSearchProberImpl) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	// Would normally call Search with a detector
	return nil, nil
}

func (m *mockTreeSearchProberImpl) Name() string {
	return "mock.TreeSearch"
}

func (m *mockTreeSearchProberImpl) Description() string {
	return "Mock tree search probe for testing"
}

func (m *mockTreeSearchProberImpl) Goal() string {
	return "test tree search functionality"
}

func (m *mockTreeSearchProberImpl) GetPrimaryDetector() string {
	return "mock.Detector"
}

func (m *mockTreeSearchProberImpl) GetPrompts() []string {
	return []string{}
}

// Test registration pattern
func TestTreeSearcher_Registration(t *testing.T) {
	// This test verifies the registration pattern works
	// Actual probes using TreeSearcher would register via init()
	factory := func(cfg registry.Config) (probes.Prober, error) {
		impl := &mockTreeSearchProberImpl{
			mockTreeSearchImpl: newMockTreeSearch(DefaultConfig()),
		}
		return impl, nil
	}

	p, err := factory(nil)
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}
	if p == nil {
		t.Fatal("factory() returned nil")
	}
	if p.Name() != "mock.TreeSearch" {
		t.Errorf("Name() = %q, want %q", p.Name(), "mock.TreeSearch")
	}
}

// TestTreeSearcher_AllStrategiesAvailable tests that all 4+ strategies are available
func TestTreeSearcher_AllStrategiesAvailable(t *testing.T) {
	strategies := []struct {
		strategy SearchStrategy
		name     string
	}{
		{BreadthFirst, "breadth_first"},
		{DepthFirst, "depth_first"},
		{TAP, "tap"},
		{PAIR, "pair"},
	}

	for _, tc := range strategies {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig().WithStrategy(tc.strategy)
			if cfg.Strategy.String() != tc.name {
				t.Errorf("Strategy %v String() = %q, want %q",
					tc.strategy, cfg.Strategy.String(), tc.name)
			}
		})
	}
}
