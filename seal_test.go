package wickset

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/zblach/wickset/alg"
	"github.com/zblach/wickset/format"
	"github.com/zblach/wickset/wick"
)

// countingAlg wraps an Alg and counts evaluations of H.
type countingAlg struct {
	alg.Alg
	steps int
}

func (c *countingAlg) H(x []byte) []byte { c.steps++; return c.Alg.H(x) }

// TestRealAlgSmoke runs the whole path on 0x01: seal at N = 0, extend by one,
// open, and open again with the key. Opening only the extended wick still
// proves the seal (it burns down to the same S), at three real evaluations
// of H instead of five.
func TestRealAlgSmoke(t *testing.T) {
	t.Parallel()
	start := time.Now()
	pt := []byte("hello")
	raw, payload, key, err := Seal(t.Context(), pt, SealOpts{Alg: alg.Argon2idShort, N: 0})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := wick.Extend(t.Context(), raw, 1, wick.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	got, solved, err := Open(t.Context(), ext, payload, nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("after extend: %q %v", got, err)
	}
	if !bytes.Equal(solved, key) {
		t.Fatal("solving the extended wick recovered a different key than Seal returned")
	}
	if got, err := format.OpenPayload(key, payload); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("with key: %q %v", got, err)
	}
	if _, _, _, err := Seal(t.Context(), pt, SealOpts{Alg: 0x00}); !errors.Is(err, alg.ErrUnknown) {
		t.Fatalf("alg 0x00: %v", err)
	}
	t.Logf("seal, extend, open on %v in %v", alg.Argon2idShort, time.Since(start).Round(time.Millisecond))
}

// TestOpenChecksFirst: Open refuses a damaged or mismatched payload before
// any evaluation of H, so a mistake never costs the delay.
func TestOpenChecksFirst(t *testing.T) {
	t.Parallel()
	raw, payload, _, err := Seal(t.Context(), []byte("x"), SealOpts{Alg: alg.Argon2idShort, N: 0})
	if err != nil {
		t.Fatal(err)
	}
	other, _, _, err := Seal(t.Context(), []byte("x"), SealOpts{Alg: alg.Argon2idShort, N: 0})
	if err != nil {
		t.Fatal(err)
	}
	damaged := append([]byte(nil), payload...)
	damaged[len(damaged)-1] ^= 1
	for _, c := range []struct {
		name         string
		raw, payload []byte
		want         error
	}{
		{"other wick", other, payload, format.ErrMismatch},
		{"damaged payload", raw, damaged, format.ErrCorrupt},
		{"wick file as payload", raw, format.EncodeWickFile(raw), format.ErrFormat},
	} {
		o, err := wick.Parse(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		counting := &countingAlg{Alg: o.Alg}
		o.Alg = counting
		if _, _, err := open(t.Context(), o, c.payload, nil); !errors.Is(err, c.want) || counting.steps != 0 {
			t.Errorf("%s: err %v after %d steps, want %v after 0", c.name, err, counting.steps, c.want)
		}
	}
}
