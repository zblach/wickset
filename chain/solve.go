package chain

import (
	"context"

	"chainlock/alg"
)

// Solve walks the chain of o from I[N] to S (SPEC.md §6): N+1 sequential
// evaluations of H, on the CPU, one core being faster at a single step than
// a GPU. The result has no check of its own; authenticate whatever S
// protects. A solve is one worker, reporting its steps in the order it takes
// them, from 0; report may be nil.
func Solve(ctx context.Context, o *Object, report Report) (Key, error) {
	rep := &reporter{report: report}
	defer rep.send(Event{Kind: Idle})
	x := append([]byte(nil), o.Block(o.N+1)...) // I[N]
	for j := o.N; j >= 0; j-- {
		i := o.N - j
		rep.send(Event{Kind: Began, First: i, N: 1})
		h, err := alg.EvalPartway(ctx, o.Alg, x, rep.partway(0, i, 1)) // stops mid-step if ctx is cancelled
		if err != nil {
			return nil, err
		}
		x = xorInto(x, o.Block(j), h) // I[j-1], or S at j = 0
		rep.send(Event{Kind: Finished, First: i, N: 1})
	}
	return x, nil
}
