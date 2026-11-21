package chain

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"

	"chainlock/alg"
)

// Progress reports that done of total evaluations of H have finished. Calls
// are serialized and done increases by one each call. A nil Progress is not
// called.
type Progress func(done, total int)

// Activity reports what the parallel workers of New and Extend are doing:
// worker (0 ≤ worker < the worker count) has begun evaluation index of H, or,
// with index -1, has finished all of its work. An evaluation can take seconds
// and Progress counts only finished ones, so this is what shows a run is
// under way before any finishes. Calls come from the workers concurrently and
// should return promptly. A nil Activity is not called.
type Activity func(worker, index int)

// Opts is how a parallel run of New or Extend goes: how many workers, and
// whom it tells.
type Opts struct {
	Workers  int // parallel evaluations (0 => GOMAXPROCS); memory = workers × alg memory
	Progress Progress
	Activity Activity
}

// computeOutputs evaluates H over xs in parallel. Each worker holds one
// working set at a time, so memory use is workers × the algorithm's memory.
func computeOutputs(ctx context.Context, a alg.Alg, xs [][]byte, o Opts) ([][]byte, error) {
	workers := o.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	workers = min(workers, len(xs))
	activity := o.Activity
	if activity == nil {
		activity = func(int, int) {}
	}
	outs := make([][]byte, len(xs))
	var next atomic.Int64
	var wg sync.WaitGroup
	var mu sync.Mutex // serializes progress so done is reported in order
	done := 0
	for w := range workers {
		wg.Go(func() {
			defer activity(w, -1)
			for {
				if ctx.Err() != nil {
					return
				}
				i := int(next.Add(1) - 1)
				if i >= len(xs) {
					return
				}
				activity(w, i)
				out, err := alg.Eval(ctx, a, xs[i])
				if err != nil {
					return // cancelled mid-step; ctx.Err is reported below
				}
				outs[i] = out
				mu.Lock()
				done++
				if o.Progress != nil {
					o.Progress(done, len(xs))
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return outs, nil
}
