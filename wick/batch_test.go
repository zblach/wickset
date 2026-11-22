package wick

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"wickset/alg"
)

// fakeBatcher computes batches from testAlg32, failing its fail'th batch if
// fail > 0, and returning wrong outputs if corrupt.
type fakeBatcher struct {
	size, fail int
	corrupt    bool
	batches    atomic.Int32
	evals      atomic.Int32
}

func (f *fakeBatcher) BatchSize(alg.Alg) int { return f.size }

func (f *fakeBatcher) Batch(ctx context.Context, _ alg.Alg, xs [][]byte, partway alg.Partway) ([][]byte, error) {
	if int(f.batches.Add(1)) == f.fail {
		return nil, errors.New("out of GPU memory")
	}
	if partway != nil {
		partway(1, 2)
	}
	out := make([][]byte, len(xs))
	for i, x := range xs {
		out[i] = testAlg32.H(x)
		if f.corrupt {
			out[i][0] ^= 1
		}
	}
	f.evals.Add(int32(len(xs)))
	return out, nil
}

// counted is computeOutputs over n random inputs with b, checking every
// output against H and the run's events (checkEvents), and reporting which
// workers began an evaluation.
func counted(t *testing.T, n int, b Batcher, failed func(error)) (map[int]bool, error) {
	t.Helper()
	xs, _ := randBlocks(n, testAlg32.BlockSize())
	var events []Event
	outs, err := computeOutputs(t.Context(), testAlg32, xs, Opts{
		Workers: 2, Batcher: b, BatchFailed: failed,
		Report: func(e Event) { events = append(events, e) }, // serialized
	})
	workers := map[int]bool{}
	for _, e := range events {
		if e.Kind == Began {
			workers[e.Worker] = true
			if e.N > 1 && e.First%e.N != 0 && e.First+e.N != n {
				t.Errorf("batch of %d from %d: not where the batches fall", e.N, e.First)
			}
		}
	}
	if err != nil {
		return workers, err
	}
	for i, out := range outs {
		if !bytes.Equal(out, testAlg32.H(xs[i])) {
			t.Fatalf("output %d is not H", i)
		}
	}
	checkEvents(t, events, n)
	return workers, nil
}

// checkEvents holds a finished run's events to Event's rules: each of total
// evaluations finished once, by the worker that began it last, after it
// began; nothing from a worker after it went idle, and every worker idle at
// the end. A failed batch leaves its evaluations begun and never finished,
// for the workers to begin again.
func checkEvents(t *testing.T, events []Event, total int) {
	t.Helper()
	began := map[int]int{} // evaluation → worker
	finished := map[int]bool{}
	idle := map[int]bool{}
	for _, e := range events {
		if idle[e.Worker] {
			t.Fatalf("worker %d: %+v after going idle", e.Worker, e)
		}
		switch e.Kind {
		case Began:
			for i := e.First; i < e.First+e.N; i++ {
				began[i] = e.Worker
			}
		case Finished, Partway:
			for i := e.First; i < e.First+e.N; i++ {
				if w, ok := began[i]; !ok || w != e.Worker || finished[i] {
					t.Fatalf("%+v: evaluation %d not begun by this worker, or finished already", e, i)
				}
				if e.Kind == Finished {
					finished[i] = true
				}
			}
		case Idle:
			idle[e.Worker] = true
		}
	}
	if len(finished) != total {
		t.Fatalf("%d of %d evaluations finished", len(finished), total)
	}
	for w := range began {
		if !idle[began[w]] {
			t.Fatalf("worker %d never went idle", began[w])
		}
	}
}

// TestBatcherRuns: a batcher computes the whole run, and the workers none.
func TestBatcherRuns(t *testing.T) {
	b := &fakeBatcher{size: 16}
	workers, err := counted(t, 100, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.evals.Load() != 100 || b.batches.Load() != 7 || len(workers) != 1 {
		t.Fatalf("batcher computed %d in %d batches; workers %v", b.evals.Load(), b.batches.Load(), workers)
	}
}

// TestBatcherFailsOver: after a failed batch the workers compute what is
// left, and the failure is reported once.
func TestBatcherFailsOver(t *testing.T) {
	b := &fakeBatcher{size: 16, fail: 3}
	var reported []error
	workers, err := counted(t, 100, b, func(err error) { reported = append(reported, err) })
	if err != nil {
		t.Fatal(err)
	}
	if b.evals.Load() != 32 || len(reported) != 1 || !workers[1] {
		t.Fatalf("batcher computed %d, %d failures reported, workers %v", b.evals.Load(), len(reported), workers)
	}
}

// TestBatcherMismatch: a batch that is not H fails the run, since its object
// would never open.
func TestBatcherMismatch(t *testing.T) {
	if _, err := counted(t, 100, &fakeBatcher{size: 16, corrupt: true}, nil); !errors.Is(err, ErrBatchMismatch) {
		t.Fatalf("err %v", err)
	}
}

// TestBatcherUnable: a batcher that cannot run the algorithm leaves the run
// to the workers.
func TestBatcherUnable(t *testing.T) {
	b := &fakeBatcher{size: 0}
	if _, err := counted(t, 20, b, nil); err != nil || b.batches.Load() != 0 {
		t.Fatalf("err %v, %d batches", err, b.batches.Load())
	}
}

// TestBatcherCancel: cancelling stops a batched run.
func TestBatcherCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	xs, _ := randBlocks(50, testAlg32.BlockSize())
	if _, err := computeOutputs(ctx, testAlg32, xs, Opts{Batcher: &fakeBatcher{size: 8}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}
