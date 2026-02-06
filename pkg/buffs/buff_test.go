package buffs_test

import (
	"context"
	"iter"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/stretchr/testify/assert"
)

// mockPostBuff implements both Buff and PostBuff.
type mockPostBuff struct {
	name string
}

func (m *mockPostBuff) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	return attempts, nil
}
func (m *mockPostBuff) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) { yield(a) }
}
func (m *mockPostBuff) Name() string        { return m.name }
func (m *mockPostBuff) Description() string { return "mock post buff" }
func (m *mockPostBuff) HasPostBuffHook() bool { return true }
func (m *mockPostBuff) Untransform(ctx context.Context, a *attempt.Attempt) (*attempt.Attempt, error) {
	a.Outputs = []string{"untransformed"}
	return a, nil
}

func TestPostBuffInterfaceSatisfied(t *testing.T) {
	var pb buffs.PostBuff = &mockPostBuff{name: "test"}
	assert.True(t, pb.HasPostBuffHook())
}
