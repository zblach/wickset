package ops

import (
	"context"
	"fmt"
	"sync"

	"chainlock/alg"
	"chainlock/chain"
	"chainlock/internal/argon2"
	"chainlock/internal/argon2gpu"
)

// gpu is the process's GPU, opened (and its kernel compiled) on first use.
var gpu = sync.OnceValues(func() (*argon2gpu.Device, error) { return argon2gpu.Open() })

// GPUName is the GPU this build and machine can seal on, such as "Apple M5",
// or "" if none: for a front end deciding whether to offer one.
func GPUName() string { return argon2gpu.Name() }

// batcher runs an algorithm's Argon2id steps on an argon2.Hasher, for chain,
// through the parameters alg's own step uses, at most size at a time.
type batcher struct {
	h    argon2.Hasher
	size int
}

func (b batcher) BatchSize(a alg.Alg) int {
	p, ok := alg.Argon2idParams(a)
	if !ok {
		return 0
	}
	return min(b.h.Batch(p), b.size)
}

func (b batcher) Batch(ctx context.Context, a alg.Alg, xs [][]byte) ([][]byte, error) {
	p, _ := alg.Argon2idParams(a)
	return b.h.Hash(ctx, p, xs)
}

// gpuBatcher is the GPU, in GPU mode, as a chain.Batcher for a's steps, and
// how many it holds at a time: as many as its batches take, within half the
// memory the device recommends, less the step the CPU checks each batch with.
// On Apple silicon that memory is the whole machine's, shared with
// everything running; all of it pushed gigabytes to swap on an M5 with 32 GB.
// It is nil outside GPU mode, or with a warning if the GPU cannot run a.
func (e *Env) gpuBatcher(a alg.Alg) (chain.Batcher, int, error) {
	if !e.GPU {
		return nil, 0, nil
	}
	d, err := gpu()
	if err != nil {
		return nil, 0, fmt.Errorf("the GPU: %w", err)
	}
	mem := uint64(max(a.MemBytes(), 1))
	size := 0
	if room := d.Memory() / 2; room > mem {
		size = int((room - mem) / mem)
	}
	b := batcher{h: d, size: size}
	n := b.BatchSize(a)
	if n == 0 {
		e.note(Warning, "the GPU cannot run %s; the CPU does the work", a.Name())
		return nil, 0, nil
	}
	return b, n, nil
}

// withGPU gives o, a run of a's steps, to the GPU in GPU mode. The workers
// compute nothing unless the GPU fails, when they finish its work.
func (e *Env) withGPU(a alg.Alg, o chain.Opts) (chain.Opts, chain.Batcher, int, error) {
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
