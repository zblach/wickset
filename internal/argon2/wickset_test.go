package argon2

// wickset's tests of its copy; argon2_test.go is x/crypto's own.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	xargon2 "golang.org/x/crypto/argon2"
)

// TestVendored: the vendored files are exactly those SHA256SUMS records:
// x/crypto v0.59.0's, and argon2.go with argon2.go.patch applied.
func TestVendored(t *testing.T) {
	sums, err := os.ReadFile("SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(sums)) {
		want, name, _ := strings.Cut(strings.TrimSpace(line), "  ")
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != want {
			t.Errorf("%s changed: the vendored files change only by re-vendoring (README.md)", name)
		}
	}
}

// TestMatchesXCrypto: this copy is x/crypto's Argon2id, with or without a
// context, over parameters that cover both addressing modes and memory
// rounding.
func TestMatchesXCrypto(t *testing.T) {
	for _, c := range []struct{ mem, passes, keyLen uint32 }{{8, 1, 32}, {9, 2, 32}, {64, 3, 16}, {1024, 2, 64}} {
		in, salt := make([]byte, 32), make([]byte, 16)
		rand.Read(in)
		rand.Read(salt)
		want := xargon2.IDKey(in, salt, c.passes, c.mem, 1, c.keyLen)
		p := Params{Salt: salt, MemoryKiB: c.mem, Passes: c.passes, KeyLen: c.keyLen}
		got, err := p.Key(context.Background(), in)
		if err != nil || !bytes.Equal(got, want) || !bytes.Equal(IDKey(in, salt, c.passes, c.mem, 1, c.keyLen), want) {
			t.Fatalf("%+v: differs from x/crypto (%v)", c, err)
		}
		if hs, err := (CPU{}).Hash(context.Background(), p, [][]byte{in, in}); err != nil || !bytes.Equal(hs[1], want) {
			t.Fatalf("CPU.Hash: %v", err)
		}
	}
}

// TestCancelMidStep: a cancel stops an evaluation at its next sync point,
// well before it would end.
func TestCancelMidStep(t *testing.T) {
	p := Params{MemoryKiB: 64 << 10, Passes: 40, KeyLen: 32} // seconds, at 4 sync points a pass
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	go func() {
		_, err := p.Key(ctx, []byte("x"))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("returned %v after cancel: not at the next sync point", el)
	}
}
