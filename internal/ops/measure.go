package ops

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sync"
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

// stepTime measures one step of a, alone, as a solve runs it: on b (the GPU)
// if b is set, else on one core. It is the fastest of stepSamples, reported as
// the run named label. Cancelling ctx stops it mid-sample.
//
// The fastest, not the median: a process's first step runs cold, up to ~20%
// slower, and anything else on the machine only slows a step. A seal turns
// this time into steps, and a slow estimate would make too few, opening the
// lock early; the fastest errs, if at all, toward more.
func (e *Env) stepTime(ctx context.Context, a alg.Alg, label string, b chain.Batcher) (time.Duration, error) {
	progress, activity := e.progress(label), e.activity(label, stepSamples)
	if activity != nil {
		defer activity(0, -1, 0)
	}
	x := make([]byte, a.BlockSize())
	fastest := time.Duration(math.MaxInt64)
	for i := range stepSamples {
		if activity != nil {
			activity(0, i, 1)
		}
		x[0] = byte(i)
		t := time.Now()
		var err error
		if b != nil {
			_, err = b.Batch(ctx, a, [][]byte{x})
		} else {
			_, err = alg.Eval(ctx, a, x)
		}
		if err != nil {
			return 0, err
		}
		fastest = min(fastest, time.Since(t))
		if progress != nil {
			progress(i+1, stepSamples)
		}
	}
	return fastest, nil
}

// roundRate measures how fast a seal runs: n steps at once, as n workers or
// one batch on b, timed together, in steps a second. Running side by side,
// they share memory bandwidth, so this is slower than n single steps.
func (e *Env) roundRate(ctx context.Context, a alg.Alg, label string, n int, b chain.Batcher) (float64, error) {
	progress, activity := e.progress(label), e.activity(label, n)
	xs := make([][]byte, n)
	for i := range xs {
		xs[i] = make([]byte, a.BlockSize())
		xs[i][0], xs[i][1] = byte(i), byte(i>>8)
	}
	start := time.Now()
	if b != nil {
		if activity != nil {
			activity(0, 0, n)
			defer activity(0, -1, 0)
		}
		if _, err := b.Batch(ctx, a, xs); err != nil {
			return 0, err
		}
		if progress != nil {
			for i := range n {
				progress(i+1, n)
			}
		}
	} else {
		var mu sync.Mutex
		var wg sync.WaitGroup
		done := 0
		errs := make([]error, n)
		for w := range n {
			wg.Go(func() {
				if activity != nil {
					activity(w, w, 1)
					defer activity(w, -1, 0)
				}
				if _, errs[w] = alg.Eval(ctx, a, xs[w]); errs[w] == nil && progress != nil {
					mu.Lock()
					done++
					progress(done, n)
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return 0, err
			}
		}
	}
	return float64(n) / time.Since(start).Seconds(), nil
}

// plan sizes the parallel run named label: steps evaluations of a, or, with
// a delay, as many as the delay takes a solver here (at least one). A solver
// runs one step at a time, on one core or, slower, on a GPU: in GPU mode both
// are timed, and the faster sets the steps, so the delay holds against
// either. gpu is how many steps the GPU (b) holds at a time; 0 for none.
func (e *Env) plan(ctx context.Context, label string, a alg.Alg, steps int, delay time.Duration, workers int, b chain.Batcher, gpu int) (int, error) {
	if delay > 0 {
		st, err := e.stepTime(ctx, a, "measuring", nil)
		if err != nil {
			return 0, err
		}
		on := fmt.Sprintf("one core %v", st.Round(time.Millisecond))
		if b != nil {
			gt, err := e.stepTime(ctx, a, "measuring the GPU", b)
			if err != nil {
				return 0, err
			}
			on += fmt.Sprintf(", the GPU %v", gt.Round(time.Millisecond))
			st = min(st, gt)
		}
		st = max(st, time.Nanosecond) // a cheap step can measure as 0
		steps = max(int((delay+st-1)/st), 1)
		e.note(Detail, "measured a step (%s) → %d sequential steps for %s on this machine", on, steps, FormatDelay(delay))
	}
	gpu = min(gpu, steps)
	if gpu > 0 {
		e.note(Detail, "the GPU computes the steps, up to %d at a time; one of each batch is checked on the CPU", gpu)
	}
	e.warnMemory(a, workers, steps, gpu)
	return steps, nil
}

// workerCount is how many workers a parallel run of evals evaluations uses.
func workerCount(workers, evals int) int {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	return min(workers, evals)
}

// warnMemory notes the peak memory of a parallel run when it reaches 1 GiB:
// a working set per worker, or with gpu steps on the GPU, theirs and the one
// the CPU checks a batch with.
func (e *Env) warnMemory(a alg.Alg, workers, evals, gpu int) {
	held := workerCount(workers, evals)
	on := fmt.Sprintf("%d parallel workers", held)
	if gpu > 0 {
		held = gpu + 1
		on = fmt.Sprintf("%d steps on the GPU, and the one checking them", gpu)
	}
	total := int64(held) * int64(a.MemBytes())
	if total < 1<<30 {
		return
	}
	e.note(Warning, "%s uses %s per evaluation; %s need %s (set fewer workers to lower)",
		a.Name(), Bytes(int64(a.MemBytes())), on, Bytes(total))
}

// Bench is what a's steps take on this machine, measured: one alone on one
// core, as a solve runs them, and rounds side by side, as a seal does; and
// the solve and seal times they predict.
type Bench struct {
	Alg    alg.Alg
	Step   time.Duration // one step alone, on one core
	SealOn string        // where the rounds ran: "" for the CPU, or the GPU
	Rounds []BenchRound  // steps side by side
	Rows   []BenchRow
}

// BenchRound is a seal's pace with At steps at once.
type BenchRound struct {
	At   int
	Rate float64 // steps a second
}

func (r BenchRound) String() string { return fmt.Sprintf("%d at once %.1f steps/s", r.At, r.Rate) }

// Sealing says how the rounds went, for a front end: "sealing: 5 at once
// 9.8 steps/s · 10 at once 12.0 steps/s", or "sealing on the Apple M5 GPU:
// 48 at once 24.8 steps/s".
func (b Bench) Sealing() string {
	s := "sealing:"
	if b.SealOn != "" {
		s = "sealing on " + b.SealOn + ":"
	}
	for i, r := range b.Rounds {
		if i > 0 {
			s += " ·"
		}
		s += " " + r.String()
	}
	if len(b.Rounds) == 0 {
		s += " one step at a time"
	}
	return s
}

// BenchRow is what Bench predicts for one N.
type BenchRow struct {
	N     int
	Solve time.Duration // N+1 steps, one after another
	Seal  time.Duration // the same steps at the best round's pace
	Size  int           // of the lock object
}

// Bench times a's steps as this Env runs them: one alone on one core, as
// opening always runs, and rounds as sealing does: one full batch on the GPU
// in GPU mode, otherwise half the cores and all of them side by side.
func (e *Env) Bench(ctx context.Context, a alg.Alg) (Bench, error) {
	b, n, err := e.gpuBatcher(a)
	if err != nil {
		return Bench{}, err
	}
	out := Bench{Alg: a}
	rounds := []int{runtime.GOMAXPROCS(0) / 2, runtime.GOMAXPROCS(0)}
	if b != nil {
		out.SealOn, rounds = "the "+GPUName()+" GPU", []int{n}
	}
	if out.Step, err = e.stepTime(ctx, a, "timing one step", nil); err != nil {
		return Bench{}, err
	}
	best := 0.0
	for _, at := range rounds {
		if at < 2 || (len(out.Rounds) > 0 && out.Rounds[len(out.Rounds)-1].At == at) {
			continue
		}
		rate, err := e.roundRate(ctx, a, fmt.Sprintf("timing %d at once", at), at, b)
		if err != nil {
			return Bench{}, err
		}
		out.Rounds = append(out.Rounds, BenchRound{at, rate})
		best = max(best, rate)
	}
	if best == 0 { // one core only
		best = 1 / out.Step.Seconds()
	}
	for _, n := range []int{0, 999, 9_999, 99_999, 999_999} {
		seal := time.Duration(float64(n+1) / best * float64(time.Second))
		out.Rows = append(out.Rows, BenchRow{
			N: n, Solve: time.Duration(n+1) * out.Step,
			Seal: max(seal, out.Step), // never under one step, however many run at once
			Size: chain.Size(a, n),
		})
	}
	return out, nil
}
