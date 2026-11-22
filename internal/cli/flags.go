package cli

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/posener/complete"

	"wickset/alg"
	"wickset/internal/ops"
	"wickset/internal/store"
)

// outputMapper reads an output path, as the types "outfile" and "keyfile"
// (with dash, which also takes "-" for standard output). Each is checked as
// kong reads it (store.CheckOutput), so a path no output can go to is a
// usage error before anything runs; ops checks again, for every front end.
func outputMapper(dash bool) kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var path string
		if err := ctx.Scan.PopValueInto("path", &path); err != nil {
			return err
		}
		if !dash || path != "-" {
			path = kong.ExpandPath(path)
			if err := store.CheckOutput(path); err != nil {
				return err
			}
		}
		target.SetString(path)
		return nil
	}
}

// either predicts what any of ps does, each suggestion once: each file
// predictor also offers the directories to go into, which complete's own
// PredictOr would repeat.
func either(ps ...complete.Predictor) complete.Predictor {
	return complete.PredictFunc(func(a complete.Args) []string {
		var out []string
		seen := map[string]bool{}
		for _, p := range ps {
			for _, s := range p.Predict(a) {
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
		return out
	})
}

// predictors tell a shell what each argument takes, by the name in its
// predictor tag: wicks for open, payloads for bypass, the defined
// algorithms for --alg.
func predictors() map[string]complete.Predictor {
	wick := complete.PredictFiles("*.wick")
	payload := complete.PredictFiles("*.payload")
	var algs []string
	for _, a := range alg.All() {
		algs = append(algs, fmt.Sprintf("%#02x", byte(a.ID())), a.Name())
	}
	return map[string]complete.Predictor{
		"file":    complete.PredictFiles("*"),
		"wick":    wick,
		"payload": payload,
		"either":  either(wick, payload),
		"key":     complete.PredictFiles("*.key"),
		"alg":     complete.PredictSet(algs...),
		"shell":   complete.PredictSet(shells...),
	}
}

// algFlag is a defined algorithm given by id (1, 0x01) or by name
// (sha256-iter-k24). Ids that don't fit a byte are rejected, not wrapped.
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
