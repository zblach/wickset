package argon2

// This file is wickset's, not x/crypto's: the API every Argon2id backend
// implements, the CPU (this package) and the GPU (internal/gpu).

import (
	"context"

	"wickset/internal/sodium"
)

// Params is one Argon2id parameter set with one lane (threads = 1), as every
// wickset algorithm uses: a step that could spread over cores would let a
// solver do the same.
type Params struct {
	Salt      []byte
	MemoryKiB uint32
	Passes    uint32
	KeyLen    uint32
}

// Key is IDKeyContext for p: in a build with libsodium (internal/sodium),
// libsodium's, 1.2–1.7× faster, for a salt of the length it takes.
func (p Params) Key(ctx context.Context, input []byte) ([]byte, error) {
	if sodium.Built && len(p.Salt) == sodium.SaltBytes {
		return sodiumKey(ctx, p, input)
	}
	return IDKeyContext(ctx, input, p.Salt, p.Passes, p.MemoryKiB, 1, p.KeyLen)
}

// sodiumKey is Key through libsodium, which cannot be stopped once begun: on
// cancel it returns at once, and the evaluation finishes in the background,
// its memory freed when it does.
func sodiumKey(ctx context.Context, p Params, input []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type result struct {
		key []byte
		err error
	}
	done := make(chan result, 1) // buffered: an abandoned evaluation still exits
	go func() {
		k, err := sodium.Argon2idKey(input, p.Salt, p.Passes, p.MemoryKiB, p.KeyLen)
		done <- result{k, err}
	}()
	select {
	case r := <-done:
		return r.key, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// A Hasher evaluates Argon2id with one parameter set over many inputs. Every
// Hasher returns exactly IDKey's outputs, and stops with ctx's error once ctx
// is done: within a quarter pass, or with libsodium, at once, leaving the
// evaluation under way to finish unseen.
type Hasher interface {
	// Batch is how many inputs one Hash call takes to best effect: 1 where
	// each evaluation runs alone, more where many run at once.
	Batch(p Params) int
	Hash(ctx context.Context, p Params, inputs [][]byte) ([][]byte, error)
}

// CPU is the Hasher of this package: one evaluation at a time, on the
// calling goroutine. Running several at once is the caller's to arrange, as
// wick's workers do.
type CPU struct{}

func (CPU) Batch(Params) int { return 1 }

func (CPU) Hash(ctx context.Context, p Params, inputs [][]byte) ([][]byte, error) {
	out := make([][]byte, len(inputs))
	for i, in := range inputs {
		k, err := p.Key(ctx, in)
		if err != nil {
			return nil, err
		}
		out[i] = k
	}
	return out, nil
}
