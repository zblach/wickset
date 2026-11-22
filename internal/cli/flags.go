package cli

import (
	"strconv"
	"strings"
	"time"

	"wickset/alg"
	"wickset/internal/ops"
)

// algFlag is a defined algorithm given by id (1, 0x01) or by name
// (sha256-iter-k23). Ids that don't fit a byte are rejected, not wrapped.
type algFlag struct{ alg.Alg }

func (f *algFlag) UnmarshalText(text []byte) error {
	s := string(text)
	for _, a := range alg.All() {
		if s == a.Name() {
			f.Alg = a
			return nil
		}
	}
	id, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return alg.ErrUnknown
	}
	a, ok := alg.Lookup(alg.ID(id))
	if !ok {
		return alg.ErrUnknown
	}
	f.Alg = a
	return nil
}

// algList describes the defined algorithms for help text.
func algList() string {
	var s []string
	for _, a := range alg.All() {
		s = append(s, a.ID().String())
	}
	return strings.Join(s, ", ")
}

// delayFlag is a delay as ops.ParseDelay reads it, in systemd's notation:
// 90s, 8h, 3d, 2w, 6M (months; m is minutes), 1y, or terms that add up.
type delayFlag time.Duration

func (d *delayFlag) UnmarshalText(text []byte) error {
	v, err := ops.ParseDelay(string(text))
	*d = delayFlag(v)
	return err
}

// budgetFlag is a GPU memory budget as ops.ParseBudget reads it: 8G, 25%.
type budgetFlag ops.Budget

func (b *budgetFlag) UnmarshalText(text []byte) error {
	v, err := ops.ParseBudget(string(text))
	*b = budgetFlag(v)
	return err
}

// workersFlag is the --workers flag shared by seal and extend.
type workersFlag struct {
	Workers int `short:"w" help:"Parallel evaluations on the CPU (0 = all cores); memory is workers × the algorithm's. On the GPU, used only if it fails."`
}
