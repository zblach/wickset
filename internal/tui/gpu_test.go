package tui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"wickset/internal/ops"
)

// TestGPUTitle: the title says wickset[gpu] when the TUI was started with
// the GPU, and a job then runs with it.
func TestGPUTitle(t *testing.T) {
	for _, on := range []bool{false, true} {
		m := newModel(context.Background(), "")
		m.gpu = on
		m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
		if v := ansi.Strip(m.View().Content); strings.Contains(v, "wickset[gpu]") != on {
			t.Fatalf("started with the GPU %v:\n%s", on, v)
		}
		var got bool
		m.start("x", func(_ context.Context, env *ops.Env) (any, error) { got = env.GPU; return nil, nil })
		m.job.run()
		if got != on {
			t.Fatalf("started with the GPU %v, a job ran with it %v", on, got)
		}
	}
}
