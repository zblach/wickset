package ops

import (
	"context"
	"fmt"
	"sync"
	"time"

	"wickset/alg"
	"wickset/internal/gpu"
	"wickset/wick"
)

// device is the process's GPU, opened (and its kernels compiled) on first use.
var device = sync.OnceValues(gpu.Open)

// GPUName is the GPU this build and machine can seal on, such as "Apple M5",
// or "" if none: for a front end deciding whether to offer one.
func GPUName() string { return gpu.Name() }

// batcher runs an algorithm's steps on the GPU, for package wick: Argon2id
// through the parameters its own step uses, at most size at a time; iterated
// SHA-256 from each step's first hash, taken here, as many at a time as the
// GPU runs to best effect.
type batcher struct {
	d    *gpu.Device
	size int // Argon2id steps the memory budget holds
}

func (b *batcher) BatchSize(a alg.Alg) int {
	if _, ok := alg.SHA256IterOf(a); ok {
		return b.d.IterBatch()
	}
	p, ok := alg.Argon2idParams(a)
	if !ok {
		return 0
	}
	return min(b.d.Batch(p), b.size)
}

func (b *batcher) Batch(ctx context.Context, a alg.Alg, xs [][]byte, partway alg.Partway) ([][]byte, error) {
	c, ok := alg.SHA256IterOf(a)
	if !ok {
		p, _ := alg.Argon2idParams(a)
		return b.d.HashPartway(ctx, p, xs, partway)
	}
	var report func(uint64)
	if partway != nil {
		report = func(done uint64) { partway(done+1, c.K) } // and the first, Start
	}
	hs, err := b.d.Iterate(ctx, starts(c, xs), c.K-1, report)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(hs))
	for i := range hs {
		out[i] = hs[i][:]
	}
	return out, nil
}

func starts(c alg.SHA256Iter, xs [][]byte) [][32]byte {
	hs := make([][32]byte, len(xs))
	for i, x := range xs {
		hs[i] = c.Start(x)
	}
	return hs
}

// sampleTime is the least a GPU timing of part of an iterated SHA-256 step
// runs.
const sampleTime = 250 * time.Millisecond

// sample times a's steps over xs side by side on the GPU: whole, or for
// iterated SHA-256, each step's first hashes, doubling them until a run
// takes sampleTime, as every hash of a step costs the same. It returns the
// last run's time and the share of a step each ran.
func (b *batcher) sample(ctx context.Context, a alg.Alg, xs [][]byte) (time.Duration, float64, error) {
	c, ok := alg.SHA256IterOf(a)
	if !ok {
		start := time.Now()
		_, err := b.Batch(ctx, a, xs, nil)
		return time.Since(start), 1, err
	}
	hs := starts(c, xs)
	for n := uint64(1 << 12); ; n *= 2 {
		n = min(n, c.K-1)
		start := time.Now()
		if _, err := b.d.Iterate(ctx, hs, n, nil); err != nil {
			return 0, 0, err
		}
		if el := time.Since(start); el >= sampleTime || n == c.K-1 {
			return el, float64(n+1) / float64(c.K), nil
		}
	}
}

// gpuBatcher is the GPU, in GPU mode, as a wick.Batcher for a's steps, and
// how many it holds at a time. Argon2id steps fill memory: as many as its
// batches take, within half the memory the device recommends, less the step
// the CPU checks each batch with. On Apple silicon that memory is the whole
// machine's, shared with everything running; all of it pushed gigabytes to
// swap on an M5 with 32 GB. It is nil outside GPU mode, or with a warning if
// the GPU cannot run a.
func (e *Env) gpuBatcher(a alg.Alg) (*batcher, int, error) {
	if !e.GPU {
		return nil, 0, nil
	}
	d, err := device()
	if err != nil {
		return nil, 0, fmt.Errorf("the GPU: %w", err)
	}
	mem := uint64(max(a.MemBytes(), 1))
	size := 0
	if room := d.Memory() / 2; room > mem {
		size = int((room - mem) / mem)
	}
	b := &batcher{d: d, size: size}
	n := b.BatchSize(a)
	if n == 0 {
		e.note(Warning, "the GPU cannot run %s; the CPU does the work", a.Name())
		return nil, 0, nil
	}
	return b, n, nil
}

// withGPU gives o, a run of a's steps, to the GPU in GPU mode. The workers
// compute nothing unless the GPU fails, when they finish its work.
func (e *Env) withGPU(a alg.Alg, o wick.Opts) (wick.Opts, *batcher, int, error) {
	b, n, err := e.gpuBatcher(a)
	if err != nil || b == nil {
		return o, nil, 0, err
	}
	o.Batcher = b
	o.BatchFailed = func(err error) {
		e.note(Warning, "the GPU stopped (%v); the workers finish its work", err)
	}
	return o, b, n, nil
}
