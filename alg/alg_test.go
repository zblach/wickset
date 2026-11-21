package alg

import (
	"context"
	"errors"
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

func TestRegistryIsClosed(t *testing.T) {
	// Literal SPEC.md §3 values, deliberately not the ID constants: the
	// constants come from iota, and this catches a reorder.
	want := map[byte]int{0x01: 32, 0x02: 32}
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
	if Argon2id256M != 0x01 || Argon2id1GT30 != 0x02 {
		t.Fatalf("ID constants drifted from SPEC.md §3")
	}
	if got := Argon2id256M.String(); got != "0x01 (argon2id-m256M-t3-p1)" {
		t.Fatalf("String() = %q", got)
	}
	if got := ID(0xF0).String(); got != "0xf0 (undefined)" {
		t.Fatalf("String() = %q", got)
	}
	if ID(0xEF).IsPrivateUse() || !ID(0xF0).IsPrivateUse() || !ID(0xFF).IsPrivateUse() {
		t.Fatalf("IsPrivateUse boundary is not 0xF0")
	}
}
