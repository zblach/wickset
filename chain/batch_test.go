package chain

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"chainlock/alg"
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

func (f *fakeBatcher) Batch(ctx context.Context, _ alg.Alg, xs [][]byte) ([][]byte, error) {
	if int(f.batches.Add(1)) == f.fail {
		return nil, errors.New("out of GPU memory")
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
// output against H and that progress counts each once, and reporting which
// workers started an evaluation.
func counted(t *testing.T, n int, b Batcher, failed func(error)) (map[int]bool, error) {
	t.Helper()
	xs, _ := randBlocks(n, testAlg32.BlockSize())
	var mu sync.Mutex
	progress := 0
	workers := map[int]bool{}
	outs, err := computeOutputs(t.Context(), testAlg32, xs, Opts{
		Workers: 2, Batcher: b, BatchFailed: failed,
		Progress: func(done, total int) {
			mu.Lock()
			defer mu.Unlock()
			if done != progress+1 || total != n {
				t.Errorf("progress %d/%d after %d", done, total, progress)
			}
			progress = done
		},
		Activity: func(w, first, n int) {
			mu.Lock()
			defer mu.Unlock()
			if first >= 0 {
				workers[w] = true
				if w == 0 && b != nil && n > 1 && first%n != 0 && first+n != len(xs) {
					t.Errorf("batch of %d from %d: not where the batches fall", n, first)
				}
			}
		},
	})
	if err != nil {
		return workers, err
	}
	for i, out := range outs {
		if !bytes.Equal(out, testAlg32.H(xs[i])) {
			t.Fatalf("output %d is not H", i)
		}
	}
	if progress != n {
		t.Fatalf("progress reached %d of %d", progress, n)
	}
	return workers, nil
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
