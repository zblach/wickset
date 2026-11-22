package argon2

// This file is chainlock's, not x/crypto's: the API every Argon2id backend
// implements, the CPU (this package) and the GPU (internal/gpu).

import "context"

// Params is one Argon2id parameter set with one lane (threads = 1), as every
// chainlock algorithm uses: a step that could spread over cores would let a
// solver do the same.
type Params struct {
	Salt      []byte
	MemoryKiB uint32
	Passes    uint32
	KeyLen    uint32
}

// Key is IDKeyContext for p.
func (p Params) Key(ctx context.Context, input []byte) ([]byte, error) {
	return IDKeyContext(ctx, input, p.Salt, p.Passes, p.MemoryKiB, 1, p.KeyLen)
}

// A Hasher evaluates Argon2id with one parameter set over many inputs. Every
// Hasher returns exactly IDKey's outputs, and stops with ctx's error once ctx
// is done, within a quarter pass.
type Hasher interface {
	// Batch is how many inputs one Hash call takes to best effect: 1 where
	// each evaluation runs alone, more where many run at once.
	Batch(p Params) int
	Hash(ctx context.Context, p Params, inputs [][]byte) ([][]byte, error)
}

// CPU is the Hasher of this package: one evaluation at a time, on the
// calling goroutine. Running several at once is the caller's to arrange, as
// chain's workers do.
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
