package wick

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/zblach/wickset/alg"
)

// A Report is told what a run of evaluations of H does, as it does it: New,
// Extend and Solve each report every evaluation's start and finish. Calls
// are serialized, and should return promptly: the workers wait on them. A
// nil Report is not called.
type Report func(Event)

// An Event is one thing a run's worker did: began or finished the N
// evaluations of H from index First on (one, for a worker; a batch, for a
// Batcher, which reports as worker 0), got partway through them, or stopped
// for good. Indices count from 0 in the order evaluations run: a solve's
// first is I[N]'s. Evaluations are begun in order of index.
//
// A cancelled run ends with its evaluations under way never finished. A
// Batcher that fails stops without finishing its batch, and the workers then
// begin those evaluations again: its worker 0 carries on as theirs, without
// going idle between.
type Event struct {
	Kind          EventKind
	Worker        int
	First, N      int
	Part, OfParts uint64 // Partway: done of total units of the work (alg.Partway)
}

// EventKind is what an Event tells.
type EventKind int

const (
	Began    EventKind = iota // the worker began evaluations First to First+N-1
	Finished                  // it finished them
	Partway                   // it is Part of OfParts through them
	Idle                      // it has no more to do in this run
)

// Batcher evaluates H many at a time, as a GPU does. Its outputs must be
// exactly a.H's: one of every batch, chosen at random, is evaluated again on
// the CPU, and a difference fails the run with ErrBatchMismatch.
type Batcher interface {
	// BatchSize is how many evaluations of a one batch holds; 0 if it cannot
	// run a at all.
	BatchSize(a alg.Alg) int
	// Batch evaluates a.H over xs, in order, stopping with ctx's error once
	// ctx is done. It reports to partway, if it can, how far through the
	// batch it is: every evaluation runs side by side, so as far as each.
	Batch(ctx context.Context, a alg.Alg, xs [][]byte, partway alg.Partway) ([][]byte, error)
}

// ErrBatchMismatch reports a Batcher output that is not H's. Such a wick
// would never open: its solver computes H itself, and reaches a different S.
var ErrBatchMismatch = errors.New("wickset: a batch evaluation differs from the step function; stopped")

// Opts is how a parallel run of New or Extend goes: what computes, and whom
// it tells.
type Opts struct {
	Workers int // parallel evaluations (0 => GOMAXPROCS); memory = workers × alg memory
	Report  Report
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
	r := &run{a: a, xs: xs, outs: make([][]byte, len(xs)), o: o, rep: reporter{report: o.Report}}
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
	rep  reporter
}

// reporter serializes a run's calls to its Report.
type reporter struct {
	mu     sync.Mutex
	report Report
}

func (r *reporter) send(e Event) {
	if r.report == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.report(e)
}

// partway is the alg.Partway that reports as worker's on evaluations from
// first, n of them; nil with no Report, so steps skip the reporting.
func (r *reporter) partway(worker, first, n int) alg.Partway {
	if r.report == nil {
		return nil
	}
	return func(done, total uint64) {
		r.send(Event{Kind: Partway, Worker: worker, First: first, N: n, Part: done, OfParts: total})
	}
}

// batches computes the run on b, size at a time, checking one evaluation of
// each batch on the CPU while the next runs. If a batch fails, it returns
// the indices not yet computed, for the workers.
func (r *run) batches(ctx context.Context, b Batcher, size int) ([]int, error) {
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	var checks sync.WaitGroup
	handover := false // to the workers, whose worker 0 carries on from the batcher's
	defer func() {
		if !handover {
			r.rep.send(Event{Kind: Idle})
		}
	}()
	for first := 0; first < len(r.xs) && ctx.Err() == nil; first += size {
		in := r.xs[first:min(first+size, len(r.xs))]
		r.rep.send(Event{Kind: Began, First: first, N: len(in)})
		got, err := b.Batch(ctx, r.a, in, r.rep.partway(0, first, len(in)))
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
			handover = true
			return rest, nil
		}
		k := rand.IntN(len(in))
		checks.Go(func() {
			if want, err := alg.Eval(ctx, r.a, in[k]); err == nil && !bytes.Equal(want, got[k]) {
				stop(ErrBatchMismatch)
			}
		})
		copy(r.outs[first:], got)
		r.rep.send(Event{Kind: Finished, First: first, N: len(in)})
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
			defer r.rep.send(Event{Kind: Idle, Worker: w})
			for ctx.Err() == nil {
				n := int(next.Add(1) - 1)
				if n >= len(todo) {
					return
				}
				i := todo[n]
				r.rep.send(Event{Kind: Began, Worker: w, First: i, N: 1})
				out, err := alg.EvalPartway(ctx, r.a, r.xs[i], r.rep.partway(w, i, 1))
				if err != nil {
					return // cancelled mid-step; ctx.Err is reported below
				}
				r.outs[i] = out
				r.rep.send(Event{Kind: Finished, Worker: w, First: i, N: 1})
			}
		})
	}
	wg.Wait()
	return ctx.Err()
}
