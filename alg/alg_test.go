package alg

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"
)

// stuckAlg's step runs until the test lets it go: an implementation that
// knows nothing of cancellation.
type stuckAlg struct {
	Alg
	release chan struct{}
}

func (a stuckAlg) H(x []byte) []byte { <-a.release; return x }

// TestEvalCancels: Eval returns on cancel without waiting for the step, and
// returns the step's result when it finishes first.
func TestEvalCancels(t *testing.T) {
	a := stuckAlg{release: make(chan struct{})}
	defer close(a.release) // lets the abandoned step end
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() {
		_, err := Eval(ctx, a, []byte{1})
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Eval waited for the step after cancel")
	}

	b := stuckAlg{release: make(chan struct{})}
	close(b.release)
	if h, err := Eval(t.Context(), b, []byte{7}); err != nil || h[0] != 7 {
		t.Fatalf("finished step: %v %v", h, err)
	}
}

// TestSHA256Iter: a step is K hashes, the first of the domain and x, as
// SPEC.md §3.3 defines it, whatever the chunking; Run reports each chunk and
// stops between them on cancel.
func TestSHA256Iter(t *testing.T) {
	c := SHA256Iter{Domain: []byte("wickset/v1::test"), K: 3*chunk + 5}
	x := []byte("an input of thirty-two bytes....")
	want := sha256.Sum256(append([]byte("wickset/v1::test"), x...))
	for range c.K - 1 {
		want = sha256.Sum256(want[:])
	}
	var reports []uint64
	got, err := c.Run(t.Context(), c.Start(x), c.K-1, func(done uint64) { reports = append(reports, done) })
	if err != nil || got != want {
		t.Fatalf("step %x, %v; want %x", got, err, want)
	}
	if fmt.Sprint(reports) != fmt.Sprint([]uint64{chunk, 2 * chunk, 3 * chunk, 3*chunk + 4}) {
		t.Fatalf("reports %v", reports)
	}
	ctx, cancel := context.WithCancel(t.Context())
	n := 0
	if _, err := c.Run(ctx, want, c.K, func(uint64) { n++; cancel() }); !errors.Is(err, context.Canceled) || n != 1 {
		t.Fatalf("cancelled: %v after %d chunks", err, n)
	}
	for _, id := range []ID{SHA256Short, SHA256Long} {
		a, _ := Lookup(id)
		if c, ok := SHA256IterOf(a); !ok || string(c.Domain) != fmt.Sprintf("wickset/v1::%02x", byte(id)) {
			t.Fatalf("%v: domain %q", id, c.Domain)
		}
	}
}

func TestRegistryIsClosed(t *testing.T) {
	// Literal SPEC.md §3 values, deliberately not the ID constants: the
	// constants come from iota, and this catches a reorder.
	want := map[byte]int{0x01: 32, 0x02: 32, 0x03: 32, 0x04: 32}
	if testAlgsBuilt {
		want[0xFE], want[0xFF] = 32, 16 // testalgs.go
	}
	for id := range 256 {
		a, ok := Lookup(ID(id))
		b, defined := want[byte(id)]
		if ok != defined {
			t.Fatalf("id %#x: defined=%v want %v", id, ok, defined)
		}
		if ok && (a.BlockSize() != b || a.ID() != ID(id)) {
			t.Fatalf("id %#x: B=%d ID=%#x", id, a.BlockSize(), byte(a.ID()))
		}
	}
	if got := len(All()); got != len(want) {
		t.Fatalf("All() = %d entries, want %d", got, len(want))
	}
	if Argon2idShort != 0x01 || Argon2idLong != 0x02 || SHA256Short != 0x03 || SHA256Long != 0x04 {
		t.Fatalf("ID constants drifted from SPEC.md §3")
	}
	if got := Argon2idShort.String(); got != "0x01 (argon2id-m128M-t5-p1)" {
		t.Fatalf("String() = %q", got)
	}
	if got := ID(0xF0).String(); got != "0xf0 (undefined)" {
		t.Fatalf("String() = %q", got)
	}
	if ID(0xEF).IsPrivateUse() || !ID(0xF0).IsPrivateUse() || !ID(0xFF).IsPrivateUse() {
		t.Fatalf("IsPrivateUse boundary is not 0xF0")
	}
}
