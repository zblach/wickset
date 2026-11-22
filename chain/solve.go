package chain

import (
	"context"

	"chainlock/alg"
)

// Solve walks the chain of o from I[N] to S (SPEC.md §6): N+1 sequential
// evaluations of H, on the CPU, one core being faster at a single step than
// a GPU. The result has no check of its own; authenticate whatever S
// protects. progress may be nil.
func Solve(ctx context.Context, o *Object, progress Progress) (Key, error) {
	x := append([]byte(nil), o.Block(o.N+1)...) // I[N]
	for j := o.N; j >= 0; j-- {
		h, err := alg.Eval(ctx, o.Alg, x) // stops mid-step if ctx is cancelled
		if err != nil {
			return nil, err
		}
		x = xorInto(x, o.Block(j), h) // I[j-1], or S at j = 0
		if progress != nil {
			progress(o.N-j+1, o.N+1)
		}
	}
	return x, nil
}
