// Package alg is chainlock's algorithm registry (SPEC.md §3): the step
// functions H a lock can be built from, each named by the ALG_ID byte that
// leads its objects.
package alg

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"

	"chainlock/internal/argon2"
)

// ErrUnknown reports an ALG_ID that is not defined in this build.
var ErrUnknown = errors.New("chainlock: algorithm id not defined")

// ID is the ALG_ID byte that leads every object (SPEC.md §3).
type ID byte

// Defined algorithms. The values are wire format, fixed by SPEC.md §3:
// append only, never reorder or remove. 0x02's step is about 40× 0x01's (4×
// the memory, 10× the passes), for a smaller object at long delays.
const (
	_             ID = iota // 0x00 is never defined
	Argon2id256M            // 0x01: Argon2id, 256 MiB, t = 3; SPEC.md §3.1
	Argon2id1GT30           // 0x02: Argon2id, 1 GiB, t = 30; SPEC.md §3.2
	idMax                   // one past the last defined id; not an algorithm
)

// privateUse starts the private-use range 0xF0–0xFF (SPEC.md §3): never
// assigned, never interoperable.
const (
	privateUse    ID = 0xF0
	privateUseLen    = 0x100 - int(privateUse)
)

// IsPrivateUse reports whether id is in the private-use range 0xF0–0xFF.
func (id ID) IsPrivateUse() bool { return id >= privateUse }

// String formats id as its hex byte and, if defined, its name.
func (id ID) String() string {
	if a, ok := Lookup(id); ok {
		return fmt.Sprintf("%#02x (%s)", byte(id), a.Name())
	}
	return fmt.Sprintf("%#02x (undefined)", byte(id))
}

// Alg is one entry of the registry. The format uses it only through
// BlockSize and H; ID, Name and MemBytes describe it.
//
// The public entry points of package chain take an ID and resolve it through
// Lookup, so an Alg implemented outside this package can never reach an
// object.
type Alg interface {
	ID() ID
	Name() string
	// BlockSize is B, the length in bytes of S, of every chain value and of
	// every step output.
	BlockSize() int
	// MemBytes is the working set of one H evaluation. Informational (for
	// resource warnings); the format does not use it.
	MemBytes() int
	// H is the step function: BlockSize bytes in, BlockSize bytes out.
	H(x []byte) []byte
}

// argon2idAlg is an Argon2id v1.3 registry entry (SPEC.md §3.1), with one
// lane. Every value is fixed by the entry; none is a global constant.
type argon2idAlg struct {
	id     ID
	name   string
	params argon2.Params // the salt includes the entry's own id
}

func (a *argon2idAlg) ID() ID         { return a.id }
func (a *argon2idAlg) Name() string   { return a.name }
func (a *argon2idAlg) BlockSize() int { return int(a.params.KeyLen) }
func (a *argon2idAlg) MemBytes() int  { return int(a.params.MemoryKiB) << 10 }

func (a *argon2idAlg) H(x []byte) []byte {
	out, _ := a.eval(context.Background(), x) // never cancelled, so never fails
	return out
}

// eval is H, stopping at Argon2's next sync point (a quarter pass) once ctx
// is done: internal/argon2 is x/crypto's with that one change.
func (a *argon2idAlg) eval(ctx context.Context, x []byte) ([]byte, error) {
	// Argon2 allocates its whole working set (MemBytes) on every call. Left
	// to the pacer, the previous call's dead set is still held when the next
	// is allocated, doubling peak memory. Collecting first frees it; the heap
	// is a few pointer-free buffers, so this costs well under a millisecond
	// against a step of hundreds.
	runtime.GC()
	return a.params.Key(ctx, x)
}

// Argon2idParams is a's parameters, for running the same step on another
// argon2.Hasher (a GPU): Key with them is a.H. ok is false if a is not an
// Argon2id entry.
func Argon2idParams(a Alg) (p argon2.Params, ok bool) {
	e, ok := a.(*argon2idAlg)
	if !ok {
		return argon2.Params{}, false
	}
	p = e.params
	p.Salt = append([]byte(nil), p.Salt...)
	return p, true
}

// Eval is a.H(x), except that it returns ctx's error once ctx is done.
// Sealing, extending and solving all evaluate through it, so cancelling them
// returns at once rather than after a step of up to tens of seconds. The
// Argon2id entries stop mid-step, within a quarter pass, freeing their core
// and memory; any other step is left to finish in the background, and its
// result dropped.
func Eval(ctx context.Context, a Alg, x []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c, ok := a.(evaler); ok {
		return c.eval(ctx, x)
	}
	out := make(chan []byte, 1) // buffered: an abandoned step still exits
	go func() { out <- a.H(x) }()
	select {
	case h := <-out:
		return h, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// evaler is an Alg that can stop mid-step.
type evaler interface {
	eval(context.Context, []byte) ([]byte, error)
}

// registry is the closed set of defined algorithms (SPEC.md §3), indexed by
// id. Together with testAlgs it is everything Lookup accepts.
//
// testAlgs is fixed at compile time by build tag: empty normally
// (closed.go), cheap end-to-end test steps under -tags chainlock_testalgs
// (testalgs.go). The unit tests' algorithms (package chain's tests) are
// never in either table; those tests hand them straight to chain's internal
// functions.
var registry = [idMax]Alg{
	Argon2id256M: &argon2idAlg{id: Argon2id256M, name: "argon2id-m256M-t3-p1", params: argon2.Params{
		Salt: []byte("chainlock/v1::01"), MemoryKiB: 262144, Passes: 3, KeyLen: 32,
	}},
	Argon2id1GT30: &argon2idAlg{id: Argon2id1GT30, name: "argon2id-m1G-t30-p1", params: argon2.Params{
		Salt: []byte("chainlock/v1::02"), MemoryKiB: 1048576, Passes: 30, KeyLen: 32,
	}},
}

// Lookup returns the defined algorithm for id. 0x00 and unassigned IDs are
// never defined; the private-use range 0xF0–0xFF is empty unless built with
// -tags chainlock_testalgs.
func Lookup(id ID) (Alg, bool) {
	var a Alg
	switch {
	case id < idMax:
		a = registry[id]
	case id.IsPrivateUse():
		a = testAlgs[id-privateUse]
	}
	return a, a != nil
}

// All returns the defined algorithms in ID order.
func All() []Alg {
	var out []Alg
	for _, a := range slices.Concat(registry[:], testAlgs[:]) {
		if a != nil {
			out = append(out, a)
		}
	}
	return out
}
