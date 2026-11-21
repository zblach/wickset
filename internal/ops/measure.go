package ops

import (
	"context"
	"math"
	"runtime"
	"time"

	"chainlock/alg"
	"chainlock/chain"
)

// LongDelay is the delay from which a seal with no algorithm given uses 0x02
// rather than 0x01. At a day, 0x01 already makes a lock of ~8 MB, and 0x02's
// steps, about 40× as long, are still a negligible fraction of the delay;
// below it, 0x01 keeps the rounding fine and needs a quarter of the memory
// per worker.
const LongDelay = 24 * time.Hour

// AlgFor is the algorithm a seal of the given delay uses when none is given.
func AlgFor(delay time.Duration) alg.Alg {
	id := alg.Argon2id256M
	if delay >= LongDelay {
		id = alg.Argon2id1GT30
	}
	a, _ := alg.Lookup(id)
	return a
}

// stepSamples is how many steps a timing takes; it reports the fastest.
const stepSamples = 3

// stepTime measures one evaluation of a's step, the fastest of stepSamples,
// reporting as the run named label. Each sample is a whole step, ~16 s for
// the long algorithm, so it reports like a solve: one worker, one evaluation
// at a time. Cancelling ctx stops it mid-sample.
//
// The fastest, not the median: a process's first step runs cold, up to ~20%
// slower, and anything else on the machine only slows a step. A seal turns
// this time into steps, and a slow estimate would make too few, opening the
// lock early; the fastest errs, if at all, toward more.
func (e *Env) stepTime(ctx context.Context, a alg.Alg, label string) (time.Duration, error) {
	progress, activity := e.progress(label), e.activity(label, stepSamples)
	if activity != nil {
		defer activity(0, -1)
	}
	x := make([]byte, a.BlockSize())
	fastest := time.Duration(math.MaxInt64)
	for i := range stepSamples {
		if activity != nil {
			activity(0, i)
		}
		x[0] = byte(i)
		t := time.Now()
		if _, err := alg.Eval(ctx, a, x); err != nil {
			return 0, err
		}
		fastest = min(fastest, time.Since(t))
		if progress != nil {
			progress(i+1, stepSamples)
		}
	}
	return fastest, nil
}

// plan sizes the parallel run named label: steps evaluations of a, or, with
// a delay, as many as the delay takes on this machine (at least one), timed
// first. Either way it notes what the run will need, before it starts.
func (e *Env) plan(ctx context.Context, label string, a alg.Alg, steps int, delay time.Duration, workers int) (int, error) {
	var st time.Duration
	if delay > 0 {
		var err error
		if st, err = e.stepTime(ctx, a, "measuring"); err != nil {
			return 0, err
		}
		st = max(st, time.Nanosecond) // a cheap step can measure as 0
		steps = max(int((delay+st-1)/st), 1)
		e.note(Detail, "measured step %v → %d sequential steps for %s on this machine", st.Round(time.Millisecond), steps, FormatDelay(delay))
	}
	e.warnMemory(a, workers, steps)
	if st > 0 {
		e.noteCost(label, st, steps, workers)
	}
	return steps, nil
}

// workerCount is how many workers a parallel run of evals evaluations uses.
func workerCount(workers, evals int) int {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	return min(workers, evals)
}

// noteCost states up front what a parallel run will take. Making a delay
// costs as much CPU as waiting it out (SPEC.md §5), divided only by the
// workers; and parallel steps share memory bandwidth, so this is a floor.
func (e *Env) noteCost(label string, step time.Duration, evals, workers int) {
	w := workerCount(workers, evals)
	e.note(Detail, "%s computes all %d steps, the solver's whole work, split %d ways: at least %v here",
		label, evals, w, (time.Duration(evals) * step / time.Duration(w)).Round(time.Second))
}

// warnMemory notes the peak memory of a parallel run when it reaches 1 GiB.
func (e *Env) warnMemory(a alg.Alg, workers, evals int) {
	workers = workerCount(workers, evals)
	total := int64(workers) * int64(a.MemBytes())
	if total < 1<<30 {
		return
	}
	e.note(Warning, "%s uses %s per evaluation; %d parallel workers need %s (set fewer workers to lower)",
		a.Name(), Bytes(int64(a.MemBytes())), workers, Bytes(total))
}

// Bench is a step timing and the solve and seal times it predicts.
type Bench struct {
	Alg   alg.Alg
	Step  time.Duration
	Cores int // the workers a seal uses by default, which Seal assumes
	Rows  []BenchRow
}

// BenchRow is what Bench predicts for one N.
type BenchRow struct {
	N     int
	Solve time.Duration // N+1 steps, one after another
	Seal  time.Duration // the same steps, Cores at a time: a floor, as they share memory bandwidth
	Size  int           // of the lock object
}

// Bench times a's step on this machine and estimates solve and seal times.
func (e *Env) Bench(ctx context.Context, a alg.Alg) (Bench, error) {
	st, err := e.stepTime(ctx, a, "timing")
	if err != nil {
		return Bench{}, err
	}
	b := Bench{Alg: a, Step: st, Cores: workerCount(0, math.MaxInt)}
	for _, n := range []int{0, 999, 9_999, 99_999, 999_999} {
		rounds := (n + b.Cores) / b.Cores // ceil((n+1) / cores)
		b.Rows = append(b.Rows, BenchRow{
			N: n, Solve: time.Duration(n+1) * st, Seal: time.Duration(rounds) * st, Size: chain.Size(a, n),
		})
	}
	return b, nil
}
