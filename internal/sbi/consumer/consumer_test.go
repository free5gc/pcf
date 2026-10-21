package consumer

import (
	"context"
	"testing"

	pcf_context "github.com/free5gc/pcf/internal/context"
	"github.com/free5gc/pcf/pkg/factory"
)

// testPcf is the app a test Consumer runs on. Config hands out the same value
// every time: the heartbeat fallback test rewrites the configuration through it.
type testPcf struct {
	cfg *factory.Config
	ctx *pcf_context.PCFContext
}

func (p *testPcf) Config() *factory.Config { return p.cfg }

func (p *testPcf) Context() *pcf_context.PCFContext { return p.ctx }

func (p *testPcf) CancelContext() context.Context { return context.Background() }

func newTestConsumer(t *testing.T, ctx *pcf_context.PCFContext) *Consumer {
	t.Helper()

	testConsumer, err := NewConsumer(&testPcf{
		cfg: &factory.Config{Configuration: &factory.Configuration{}},
		ctx: ctx,
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}

	return testConsumer
}
