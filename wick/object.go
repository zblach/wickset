// Package wick is the wick of SPEC.md: steps of one algorithm, built in
// parallel (New, Extend) and burned in serial (Solve). It knows nothing of
// files or payloads; package format does.
package wick

import (
	"errors"
	"math"

	"github.com/zblach/wickset/alg"
)

var (
	ErrFormat    = errors.New("wickset: malformed wick")
	ErrSteps     = errors.New("wickset: invalid step count")
	ErrSecretLen = errors.New("wickset: secret length does not match algorithm block length")
)

// Object is a parsed wick (SPEC.md §2). It aliases the input bytes.
type Object struct {
	Alg alg.Alg
	N   int // the solver performs N+1 sequential steps
	raw []byte
}

// Parse validates b per SPEC.md §8, before any evaluation of H. Its
// algorithm must be defined (alg.Lookup), or the error is alg.ErrUnknown.
func Parse(b []byte) (*Object, error) {
	if len(b) < 1 {
		return nil, ErrFormat
	}
	a, ok := alg.Lookup(alg.ID(b[0]))
	if !ok {
		return nil, alg.ErrUnknown
	}
	return parseAs(a, b)
}

// parseAs is Parse with the algorithm already resolved.
func parseAs(a alg.Alg, b []byte) (*Object, error) {
	if len(b) < 1 || alg.ID(b[0]) != a.ID() {
		return nil, ErrFormat
	}
	body, bs := len(b)-1, a.BlockSize()
	if body%bs != 0 || body/bs < 2 {
		return nil, ErrFormat
	}
	return &Object{Alg: a, N: body/bs - 2, raw: b}, nil
}

// Size returns a wick's length in bytes for algorithm a and step parameter n.
func Size(a alg.Alg, n int) int { return 1 + (n+2)*a.BlockSize() }

// Block returns block j, 0..N+1, aliasing the wick. Block 0 hides S
// and is never changed by extension, which is why a payload is bound to it.
func (o *Object) Block(j int) []byte {
	bs := o.Alg.BlockSize()
	return o.raw[1+j*bs : 1+(j+1)*bs]
}

// maxN is the largest n for which Size cannot overflow int.
func maxN(a alg.Alg) int { return (math.MaxInt-1)/a.BlockSize() - 2 }

func xorInto(dst, a, b []byte) []byte {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}
