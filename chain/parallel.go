package chain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
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
// worker (0 ≤ worker < the worker count) has begun the n evaluations of H
// from first on (one, for a worker; a batch, for a Batcher, which reports as
// worker 0), or, with first -1, has finished all of its work. Evaluations
// are begun in order of index. An evaluation can take seconds and Progress
// counts only finished ones, so this is what shows a run is under way before
// any finishes. Calls come from the workers concurrently and should return
// promptly. A nil Activity is not called.
type Activity func(worker, first, n int)

// Batcher evaluates H many at a time, as a GPU does. Its outputs must be
// exactly a.H's: one of every batch, chosen at random, is evaluated again on
// the CPU, and a difference fails the run with ErrBatchMismatch.
type Batcher interface {
	// BatchSize is how many evaluations of a one batch holds; 0 if it cannot
	// run a at all.
	BatchSize(a alg.Alg) int
	// Batch evaluates a.H over xs, in order, stopping with ctx's error once
	// ctx is done.
	Batch(ctx context.Context, a alg.Alg, xs [][]byte) ([][]byte, error)
}

// ErrBatchMismatch reports a Batcher output that is not H's. Such an object
// would never open: its solver computes H itself, and reaches a different S.
var ErrBatchMismatch = errors.New("chainlock: a batch evaluation differs from the step function; stopped")

// Opts is how a parallel run of New or Extend goes: what computes, and whom
// it tells.
type Opts struct {
	Workers  int // parallel evaluations (0 => GOMAXPROCS); memory = workers × alg memory
	Progress Progress
	Activity Activity
	// Batcher, if set and able to run the algorithm, computes the whole run
	// in batches instead of the workers. If a batch fails, BatchFailed (if
	// set) is told why, and the workers compute what is left.
	Batcher     Batcher
	BatchFailed func(error)
}

// computeOutputs evaluates H over xs: on the Batcher if there is one that can
// run a, a batch at a time, and otherwise, or for what a failed Batcher left,
// on the workers in parallel, each holding one working set (memory = workers
// × the algorithm's).
func computeOutputs(ctx context.Context, a alg.Alg, xs [][]byte, o Opts) ([][]byte, error) {
	r := &run{a: a, xs: xs, outs: make([][]byte, len(xs)), o: o}
	if r.o.Activity == nil {
		r.o.Activity = func(int, int, int) {}
	}
	todo := make([]int, len(xs))
	for i := range todo {
		todo[i] = i
	}
	if b := o.Batcher; b != nil {
		if size := b.BatchSize(a); size > 0 {
			var err error
			if todo, err = r.batches(ctx, b, size); err != nil {
				return nil, err
			}
		}
	}
	if err := r.workers(ctx, todo); err != nil {
		return nil, err
	}
	return r.outs, nil
}

// run is one computeOutputs.
type run struct {
	a    alg.Alg
	xs   [][]byte
	outs [][]byte
	o    Opts
	mu   sync.Mutex // serializes progress so done is reported in order
	done int
}

func (r *run) finish(i int, out []byte) {
	r.outs[i] = out
	r.mu.Lock()
	r.done++
	if r.o.Progress != nil {
		r.o.Progress(r.done, len(r.xs))
	}
	r.mu.Unlock()
}

// batches computes the run on b, size at a time, checking one evaluation of
// each batch on the CPU while the next runs. If a batch fails, it returns
// the indices not yet computed, for the workers.
func (r *run) batches(ctx context.Context, b Batcher, size int) ([]int, error) {
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	var checks sync.WaitGroup
	defer r.o.Activity(0, -1, 0)
	for first := 0; first < len(r.xs) && ctx.Err() == nil; first += size {
		in := r.xs[first:min(first+size, len(r.xs))]
		r.o.Activity(0, first, len(in))
		got, err := b.Batch(ctx, r.a, in)
		if err == nil && len(got) != len(in) {
			err = fmt.Errorf("%d outputs for %d inputs", len(got), len(in))
		}
		if err != nil {
			checks.Wait()
			if cause := context.Cause(ctx); cause != nil {
				return nil, cause // cancelled, or a batch was wrong
			}
			if r.o.BatchFailed != nil {
				r.o.BatchFailed(err)
			}
			rest := make([]int, 0, len(r.xs)-first)
			for i := first; i < len(r.xs); i++ {
				rest = append(rest, i)
			}
			return rest, nil
		}
		k := rand.IntN(len(in))
		checks.Go(func() {
			if want, err := alg.Eval(ctx, r.a, in[k]); err == nil && !bytes.Equal(want, got[k]) {
				stop(ErrBatchMismatch)
			}
		})
		for k, out := range got {
			r.finish(first+k, out)
		}
	}
	checks.Wait()
	return nil, context.Cause(ctx)
}

// workers computes the evaluations todo in parallel, one at a time each.
func (r *run) workers(ctx context.Context, todo []int) error {
	if len(todo) == 0 {
		return nil
	}
	workers := r.o.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	workers = min(workers, len(todo))
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			defer r.o.Activity(w, -1, 0)
			for ctx.Err() == nil {
				n := int(next.Add(1) - 1)
				if n >= len(todo) {
					return
				}
				i := todo[n]
				r.o.Activity(w, i, 1)
				out, err := alg.Eval(ctx, r.a, r.xs[i])
				if err != nil {
					return // cancelled mid-step; ctx.Err is reported below
				}
				r.finish(i, out)
			}
		})
	}
	wg.Wait()
	return ctx.Err()
}
