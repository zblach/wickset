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
// the GPU, and a job then runs with it and the memory budget it was given.
func TestGPUTitle(t *testing.T) {
	budget := ops.Budget{Share: 0.25}
	for _, on := range []bool{false, true} {
		m := newModel(context.Background(), "")
		m.gpu, m.gpuMemory = on, budget
		m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
		if v := ansi.Strip(m.View().Content); strings.Contains(v, "wickset[gpu]") != on {
			t.Fatalf("started with the GPU %v:\n%s", on, v)
		}
		var got ops.Env
		m.start("x", func(_ context.Context, env *ops.Env) (any, error) {
			got.GPU, got.GPUMemory = env.GPU, env.GPUMemory
			return nil, nil
		})
		m.job.run()
		if got.GPU != on || got.GPUMemory != budget {
			t.Fatalf("started with the GPU %v and %v, a job ran with %v and %v", on, budget, got.GPU, got.GPUMemory)
		}
	}
}
