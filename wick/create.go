package wick

import (
	"context"

	"github.com/zblach/wickset/alg"
)

// New draws a fresh random S and builds a wick hiding it behind n+1
// sequential steps of the algorithm id (SPEC.md §5). Total CPU equals the
// solver's; wall-clock is roughly that divided by the workers. It returns S
// as the Key: nothing here takes a caller's secret or randomness.
func New(ctx context.Context, id alg.ID, n int, o Opts) ([]byte, Key, error) {
	a, ok := alg.Lookup(id)
	if !ok {
		return nil, nil, alg.ErrUnknown
	}
	s, err := randBlocks(1, a.BlockSize())
	if err != nil {
		return nil, nil, err
	}
	obj, err := create(ctx, a, n, s[0], o)
	if err != nil {
		return nil, nil, err
	}
	return obj, s[0], nil
}

// create is New for a given algorithm and secret.
func create(ctx context.Context, a alg.Alg, n int, s []byte, o Opts) ([]byte, error) {
	if n < 0 || n > maxN(a) {
		return nil, ErrSteps
	}
	if len(s) != a.BlockSize() {
		return nil, ErrSecretLen
	}
	xs, err := randBlocks(n+1, a.BlockSize())
	if err != nil {
		return nil, err
	}
	return build(ctx, a, xs, s, o)
}

// build emits the wick for values xs = I[0..N] and secret s.
func build(ctx context.Context, a alg.Alg, xs [][]byte, s []byte, o Opts) ([]byte, error) {
	outs, err := computeOutputs(ctx, a, xs, o)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1, Size(a, len(xs)-1))
	out[0] = byte(a.ID())
	return appendChain(out, s, xs, outs), nil
}

// appendChain appends the blocks that hide each output under the value
// before it, prev ⊕ outs[0], xs[0] ⊕ outs[1], …, then the last of xs, the
// new I[N]. Sealing starts prev at S (SPEC.md §5); extending, at the old
// I[N] (§7).
func appendChain(out, prev []byte, xs, outs [][]byte) []byte {
	blk := make([]byte, len(prev))
	for k, o := range outs {
		out = append(out, xorInto(blk, prev, o)...)
		prev = xs[k]
	}
	return append(out, prev...)
}
