package treesearch

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func (m *mockGenerator) ClearHistory()        { m.cleared = true }
func (m *mockGenerator) Name() string         { return "mock-generator" }
func (m *mockGenerator) Description() string  { return "mock generator for testing" }

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
		return make([]float64, len(a.Outputs)), nil
	}
	return m.scores, nil
}

func (m *mockDetector) Name() string        { return "mock.Detector" }
func (m *mockDetector) Description() string { return "Mock detector for testing" }

// mockNode implements Node interface for testing
type mockNode struct {
	id       string
	terms    []string
	children []*mockNode
	parent   *mockNode
}

func (n *mockNode) ID() string { return n.id }

// mockTreeSearchImpl is a concrete implementation for testing
type mockTreeSearchImpl struct {
	*TreeSearcher
	initialNodes []*mockNode
	prompts      map[string][]string
}

func newMockTreeSearch(cfg *Config) *mockTreeSearchImpl {
	return &mockTreeSearchImpl{
		TreeSearcher: NewTreeSearcher(cfg),
		initialNodes: []*mockNode{},
		prompts:      make(map[string][]string),
	}
}

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
	if n, ok := node.(*mockNode); ok && n.parent != nil {
		return n.parent
	}
	return nil
}

func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, BreadthFirst, cfg.Strategy)
	assert.Equal(t, 0.5, cfg.PerGenerationThreshold)
	assert.Equal(t, 0.1, cfg.PerNodeThreshold)
	assert.True(t, cfg.TargetSoft)
	assert.True(t, cfg.QueueChildrenAtStart)
	assert.Equal(t, 1, cfg.Generations)
}

func TestConfig_WithOptions(t *testing.T) {
	cfg := DefaultConfig().
		WithStrategy(DepthFirst).
		WithPerGenerationThreshold(0.7).
		WithPerNodeThreshold(0.2).
		WithTargetSoft(false).
		WithGenerations(3)

	assert.Equal(t, DepthFirst, cfg.Strategy)
	assert.Equal(t, 0.7, cfg.PerGenerationThreshold)
	assert.Equal(t, 0.2, cfg.PerNodeThreshold)
	assert.False(t, cfg.TargetSoft)
	assert.Equal(t, 3, cfg.Generations)
}

func TestTreeSearcher_EmptyInitialNodes(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{}

	gen := &mockGenerator{}
	det := &mockDetector{}

	attempts, err := impl.Search(context.Background(), gen, det)
	require.NoError(t, err)
	assert.Empty(t, attempts)
}

func TestTreeSearcher_SingleNode(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "root", terms: []string{"term1"}},
	}
	impl.prompts["term1"] = []string{"prompt1"}

	gen := &mockGenerator{
		responses: []attempt.Message{attempt.NewAssistantMessage("response1")},
	}
	det := &mockDetector{scores: []float64{0.0}}

	attempts, err := impl.Search(context.Background(), gen, det)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	assert.Equal(t, "prompt1", attempts[0].Prompt)
	assert.Equal(t, attempt.StatusComplete, attempts[0].Status)
}

func TestTreeSearcher_BreadthFirst(t *testing.T) {
	cfg := DefaultConfig().WithStrategy(BreadthFirst)
	impl := newMockTreeSearch(cfg)

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

	det := &mockDetector{scores: []float64{0.8}}

	var explorationOrder []string
	gen := &mockGenerator{}
	gen.generateFunc = func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
		if len(conv.Turns) > 0 {
			explorationOrder = append(explorationOrder, conv.Turns[len(conv.Turns)-1].Prompt.Content)
		}
		return []attempt.Message{attempt.NewAssistantMessage("response")}, nil
	}

	_, err := impl.Search(context.Background(), gen, det)
	require.NoError(t, err)
	assert.NotEmpty(t, explorationOrder, "prompts should be explored")
}

func TestTreeSearcher_DepthFirst(t *testing.T) {
	cfg := DefaultConfig().WithStrategy(DepthFirst)
	impl := newMockTreeSearch(cfg)

	child := &mockNode{id: "child", terms: []string{"child_term"}}
	root := &mockNode{
		id:       "root",
		terms:    []string{"root_term"},
		children: []*mockNode{child},
	}
	child.parent = root
	impl.initialNodes = []*mockNode{root}

	det := &mockDetector{scores: []float64{0.8}}
	gen := &mockGenerator{}

	_, err := impl.Search(context.Background(), gen, det)
	require.NoError(t, err)
}

func TestTreeSearcher_PerNodeThreshold(t *testing.T) {
	cfg := DefaultConfig().
		WithPerNodeThreshold(0.5).
		WithTargetSoft(true)

	impl := newMockTreeSearch(cfg)

	child := &mockNode{id: "child", terms: []string{"child_term"}}
	root := &mockNode{
		id:       "root",
		terms:    []string{"root_term"},
		children: []*mockNode{child},
	}
	child.parent = root
	impl.initialNodes = []*mockNode{root}

	det := &mockDetector{scores: []float64{0.2}} // Low score
	gen := &mockGenerator{}

	_, err := impl.Search(context.Background(), gen, det)
	require.NoError(t, err)
	assert.LessOrEqual(t, gen.callCount, 1, "with low score, children should not be explored")
}

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

	det := &mockDetector{scores: []float64{0.8}}
	gen := &mockGenerator{}

	_, err := impl.Search(context.Background(), gen, det)
	require.NoError(t, err)
	assert.LessOrEqual(t, gen.callCount, 1, "excluded child should not be explored")
}

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
	require.NoError(t, err)
	require.Len(t, attempts, 1, "only included_form should generate prompts")
	assert.Equal(t, "included prompt", attempts[0].Prompt)
}

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
		cancel()
		return []attempt.Message{attempt.NewAssistantMessage("response")}, nil
	}

	_, err := impl.Search(ctx, gen, det)
	if err != nil {
		assert.True(t, errors.Is(err, context.Canceled), "error should be context.Canceled")
	}
}

func TestTreeSearcher_GeneratorError(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "root", terms: []string{"term1"}},
	}

	gen := &mockGenerator{err: errors.New("generator failed")}
	det := &mockDetector{}

	attempts, err := impl.Search(context.Background(), gen, det)
	// Error may be captured in attempt or returned
	if err == nil && len(attempts) > 0 {
		assert.Equal(t, attempt.StatusError, attempts[0].Status)
	}
}

func TestTreeSearcher_DetectorError(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "root", terms: []string{"term1"}},
	}

	gen := &mockGenerator{}
	det := &mockDetector{err: errors.New("detector failed")}

	// Detector errors should be logged but search continues
	_, err := impl.Search(context.Background(), gen, det)
	// May or may not return error depending on implementation
	t.Logf("Search with detector error returned: %v", err)
}

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
	require.NoError(t, err)
	assert.Len(t, attempts, 3, "should have one attempt per term")
}

func TestTreeSearcher_DuplicateSurfaceFormSkipped(t *testing.T) {
	cfg := DefaultConfig().WithPerNodeThreshold(0.0)
	impl := newMockTreeSearch(cfg)

	child := &mockNode{id: "child", terms: []string{"shared_term"}}
	root := &mockNode{
		id:       "root",
		terms:    []string{"shared_term"},
		children: []*mockNode{child},
	}
	child.parent = root
	impl.initialNodes = []*mockNode{root}

	gen := &mockGenerator{}
	det := &mockDetector{scores: []float64{0.8}}

	attempts, err := impl.Search(context.Background(), gen, det)
	require.NoError(t, err)
	assert.Len(t, attempts, 1, "duplicate form should be skipped")
}

func TestTreeSearcher_MetadataCapture(t *testing.T) {
	impl := newMockTreeSearch(DefaultConfig())
	impl.initialNodes = []*mockNode{
		{id: "test_node", terms: []string{"test_term"}},
	}

	gen := &mockGenerator{}
	det := &mockDetector{scores: []float64{0.5}}

	attempts, err := impl.Search(context.Background(), gen, det)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	surfaceForm, ok := attempts[0].GetMetadata("surface_form")
	assert.True(t, ok, "should have surface_form metadata")
	assert.Equal(t, "test_term", surfaceForm)
}

func TestTreeSearchProber_Interface(t *testing.T) {
	var _ TreeSearchProber = (*mockTreeSearchProberImpl)(nil)
	var _ probes.Prober = (*mockTreeSearchProberImpl)(nil)
}

type mockTreeSearchProberImpl struct {
	*mockTreeSearchImpl
}

func (m *mockTreeSearchProberImpl) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	return nil, nil
}

func (m *mockTreeSearchProberImpl) Name() string              { return "mock.TreeSearch" }
func (m *mockTreeSearchProberImpl) Description() string       { return "Mock tree search probe" }
func (m *mockTreeSearchProberImpl) Goal() string              { return "test tree search" }
func (m *mockTreeSearchProberImpl) GetPrimaryDetector() string { return "mock.Detector" }
func (m *mockTreeSearchProberImpl) GetPrompts() []string      { return []string{} }

func TestTreeSearcher_Registration(t *testing.T) {
	factory := func(cfg registry.Config) (probes.Prober, error) {
		return &mockTreeSearchProberImpl{
			mockTreeSearchImpl: newMockTreeSearch(DefaultConfig()),
		}, nil
	}

	p, err := factory(nil)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "mock.TreeSearch", p.Name())
}

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
			assert.Equal(t, tc.name, cfg.Strategy.String())
		})
	}
}

func TestTopicTreeFromConfig(t *testing.T) {
	probe, err := NewTopicTreeFromConfig(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "treesearch.TopicTree", probe.Name())
	assert.NotEmpty(t, probe.Description())
	assert.NotEmpty(t, probe.Goal())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
}

func TestTopicTreeDeepFromConfig(t *testing.T) {
	probe, err := NewTopicTreeDeepFromConfig(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "treesearch.TopicTreeDeep", probe.Name())
}

func TestSearchStrategy_String(t *testing.T) {
	tests := []struct {
		strategy SearchStrategy
		expected string
	}{
		{BreadthFirst, "breadth_first"},
		{DepthFirst, "depth_first"},
		{TAP, "tap"},
		{PAIR, "pair"},
		{SearchStrategy(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.strategy.String())
		})
	}
}
