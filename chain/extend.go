package chain

import "context"

// Extend lengthens the delay of obj by add sequential steps (>= 1) without
// any secret (SPEC.md §7). Existing blocks are copied untouched.
func Extend(ctx context.Context, obj []byte, add int, o Opts) ([]byte, error) {
	p, err := Parse(obj)
	if err != nil {
		return nil, err
	}
	return extend(ctx, p, add, o)
}

func extend(ctx context.Context, p *Object, add int, o Opts) ([]byte, error) {
	a := p.Alg
	if add < 1 || add > maxN(a)-p.N {
		return nil, ErrSteps
	}
	xs, err := randBlocks(add, a.BlockSize()) // xs[k] = I[N+1+k]
	if err != nil {
		return nil, err
	}
	outs, err := computeOutputs(ctx, a, xs, o)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, Size(a, p.N+add))
	out = append(out, p.raw[:len(p.raw)-a.BlockSize()]...) // everything except I[N]
	return appendChain(out, p.Block(p.N+1), xs, outs), nil
}
