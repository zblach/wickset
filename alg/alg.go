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

	"golang.org/x/crypto/argon2"
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

// argon2idAlg is an Argon2id v1.3 registry entry (SPEC.md §3.1). Every value
// is fixed by the entry; none is a global constant.
type argon2idAlg struct {
	id      ID
	name    string
	salt    []byte // includes the entry's own id
	memKiB  uint32
	time    uint32
	threads uint8
}

func (a *argon2idAlg) ID() ID         { return a.id }
func (a *argon2idAlg) Name() string   { return a.name }
func (a *argon2idAlg) BlockSize() int { return 32 }
func (a *argon2idAlg) MemBytes() int  { return int(a.memKiB) << 10 }

// H is x/crypto's Argon2id, unmodified.
func (a *argon2idAlg) H(x []byte) []byte {
	// Argon2 allocates its whole working set (MemBytes) on every call. Left
	// to the pacer, the previous call's dead set is still held when the next
	// is allocated, doubling peak memory. Collecting first frees it; the heap
	// is a few pointer-free buffers, so this costs well under a millisecond
	// against a step of hundreds.
	runtime.GC()
	return argon2.IDKey(x, a.salt, a.time, a.memKiB, a.threads, uint32(a.BlockSize()))
}

// Argon2idParams is a's Argon2id parameters, for running the same step by
// other means (a GPU): x/crypto's argon2.IDKey(x, salt, passes, memKiB, 1,
// a.BlockSize()) is a.H(x). ok is false if a is not an Argon2id entry.
func Argon2idParams(a Alg) (salt []byte, memKiB, passes uint32, ok bool) {
	e, ok := a.(*argon2idAlg)
	if !ok || e.threads != 1 {
		return nil, 0, 0, false
	}
	return append([]byte(nil), e.salt...), e.memKiB, e.time, true
}

// Eval is a.H(x), except that it returns ctx's error as soon as ctx is done,
// without waiting for the step. Sealing, extending and solving all evaluate
// through it, so cancelling them returns at once rather than after a step of
// up to tens of seconds.
//
// The step itself is not interrupted: no implementation of H need know about
// cancellation, whatever runs it (this CPU, or one day a GPU). It finishes in
// the background and its result is dropped, so its core and memory stay in
// use for up to one step after the cancel.
func Eval(ctx context.Context, a Alg, x []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
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

// registry is the closed set of defined algorithms (SPEC.md §3), indexed by
// id. Together with testAlgs it is everything Lookup accepts.
//
// testAlgs is fixed at compile time by build tag: empty normally
// (closed.go), cheap end-to-end test steps under -tags chainlock_testalgs
// (testalgs.go). The unit tests' algorithms (package chain's tests) are
// never in either table; those tests hand them straight to chain's internal
// functions.
var registry = [idMax]Alg{
	Argon2id256M: &argon2idAlg{
		id: Argon2id256M, name: "argon2id-m256M-t3-p1", salt: []byte("chainlock/v1::01"),
		memKiB: 262144, time: 3, threads: 1,
	},
	Argon2id1GT30: &argon2idAlg{
		id: Argon2id1GT30, name: "argon2id-m1G-t30-p1", salt: []byte("chainlock/v1::02"),
		memKiB: 1048576, time: 30, threads: 1,
	},
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
