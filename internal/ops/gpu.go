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
// how many it holds at a time; nil, with a note, wherever the CPU has to do
// the work instead: an algorithm the GPU cannot run, a GPU that will not
// open, or a memory budget too small for a step. Whether the GPU is worth it
// for a run is place's to say, once the run's steps are known.
//
// Argon2id steps fill memory: as many as e.GPUMemory holds, less the step
// the CPU checks each batch with.
func (e *Env) gpuBatcher(a alg.Alg) (*batcher, int, error) {
	if !e.GPU {
		return nil, 0, nil
	}
	_, argon := alg.Argon2idParams(a)
	if _, sha := alg.SHA256IterOf(a); !sha && !argon {
		e.note(Detail, "the GPU cannot run %s; sealing on the CPU", a.Name())
		return nil, 0, nil
	}
	d, err := device()
	if err != nil {
		e.note(Warning, "the GPU will not open (%v); sealing on the CPU", err)
		return nil, 0, nil
	}
	b := &batcher{d: d}
	if argon {
		mem, total := uint64(a.MemBytes()), d.Memory()
		budget := e.GPUMemory.Of(total)
		if budget > total {
			e.note(Warning, "--gpu-memory %v is more than the %s the GPU may use; using that", e.GPUMemory, Bytes(int64(total)))
			budget = total
		}
		if budget < 2*mem {
			e.note(Warning, "a GPU budget of %s holds no %s step beside the one the CPU checks; sealing on the CPU",
				Bytes(int64(budget)), Bytes(int64(mem)))
			return nil, 0, nil
		}
		b.size = int((budget - mem) / mem)
	}
	return b, b.BatchSize(a), nil
}

// noteGPU says, before any work starts, that a run of steps evaluations is
// on the GPU, and for Argon2id how much of its memory it will hold: on Apple
// silicon that is the whole machine's, shared with everything running.
func (e *Env) noteGPU(a alg.Alg, b *batcher, steps int) {
	n := min(b.BatchSize(a), steps) // within the budget, one GPU buffer, and the run
	if _, ok := alg.Argon2idParams(a); !ok {
		e.note(Detail, "sealing on the %s GPU, %d steps at a time", GPUName(), n)
		return
	}
	mem, total := uint64(a.MemBytes()), b.d.Memory()
	held := uint64(n+1) * mem
	e.note(Warning, "sealing on the %s GPU, which will hold up to %s of memory (%.0f%% of the %s it may use); --gpu-memory to change, --cpu to seal on the CPU",
		GPUName(), Bytes(int64(held)), 100*float64(held)/float64(total), Bytes(int64(total)))
	if n < min(b.size, steps) {
		e.note(Detail, "the budget allows %d steps at a time, but one GPU buffer holds %d", b.size, n)
	}
}

// place decides where a run of steps evaluations of a goes, once they are
// known: on the GPU (b, if not nil) only where it would finish sooner than
// the CPU workers, as it does for many steps and not for few. It notes the
// choice before any work starts, and returns o set to it.
func (e *Env) place(a alg.Alg, o wick.Opts, b *batcher, steps int) wick.Opts {
	workers := workerCount(o.Workers, steps)
	if b != nil && !b.faster(a, steps, workers) {
		what := fmt.Sprintf("%d steps are", steps)
		if steps == 1 {
			what = "1 step is"
		}
		e.note(Detail, "%s too few to fill the GPU; sealing on the CPU, which is faster here", what)
		b = nil
	}
	if b == nil {
		e.warnMemory(a, workers)
		return o
	}
	e.noteGPU(a, b, steps)
	o.Batcher = b
	o.BatchFailed = func(err error) {
		e.note(Warning, "the GPU stopped (%v); the workers finish its work", err)
	}
	return o
}

// faster reports whether steps evaluations of a finish sooner on the GPU than
// on workers cores. Iterated SHA-256 is predicted from the GPU's calibrated
// rates against one core's, timed here; one GPU thread is ~125× slower than
// a core, so the GPU needs thousands of steps at once. An Argon2id step on
// the GPU takes about 2.5 on a core, all of a batch side by side, so the GPU
// is faster from a few rounds of the workers on.
func (b *batcher) faster(a alg.Alg, steps, workers int) bool {
	c, ok := alg.SHA256IterOf(a)
	if !ok {
		return steps > 3*workers
	}
	return gpuSooner(steps, workers, b.BatchSize(a), float64(c.K), coreHashRate(c), b.d.IterRate)
}

// gpuSooner compares a run of steps of k hashes each: on workers cores at
// core hashes a second each, against batches of up to batch on a GPU that
// runs gpu(n) hashes a second with n steps side by side.
func gpuSooner(steps, workers, batch int, k, core float64, gpu func(n int) float64) bool {
	if workers < 1 || core <= 0 {
		return true
	}
	cpu := float64((steps+workers-1)/workers) * k / core
	var g float64
	for left := steps; left > 0; left -= batch {
		n := min(left, batch)
		r := gpu(n)
		if r <= 0 {
			return false
		}
		g += float64(n) * k / r
	}
	return g < cpu
}

// coreHashRate is one core's rate at c's hashes, timed once a process on a
// million of them, ~40 ms.
var coreHashRate = func() func(alg.SHA256Iter) float64 {
	var once sync.Once
	var rate float64
	return func(c alg.SHA256Iter) float64 {
		once.Do(func() {
			const n = 1 << 20
			start := time.Now()
			c.Run(context.Background(), c.Start(nil), n, nil)
			rate = n / time.Since(start).Seconds()
		})
		return rate
	}
}()
