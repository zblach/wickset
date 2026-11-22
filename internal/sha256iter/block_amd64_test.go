//go:build !purego

package sha256iter

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// TestEachRoutine: both of the vendored amd64 routines, SHA-NI and AVX2,
// compress as crypto/sha256 does, each where this CPU can run it, whichever
// Iterate chose. A CPU with SHA-NI also runs the AVX2 routine, so one machine
// can check both; one without either, such as an emulator, skips.
func TestEachRoutine(t *testing.T) {
	for _, r := range []struct {
		name string
		ok   bool
		f    func(*[8]uint32, []byte)
	}{
		{"SHA-NI", useSHANI, blockSHANI},
		{"AVX2", useAVX2, blockAVX2},
	} {
		t.Run(r.name, func(t *testing.T) {
			if !r.ok {
				t.Skipf("this CPU cannot run the %s routine", r.name)
			}
			for _, seed := range []string{"", "wickset", "\xff\x00 any 32 bytes"} {
				h := sha256.Sum256([]byte(seed))
				var buf [64]byte
				copy(buf[:], h[:])
				buf[32], buf[62] = 0x80, 0x01
				st := iv
				r.f(&st, buf[:])
				var got [32]byte
				for i, w := range st {
					binary.BigEndian.PutUint32(got[4*i:], w)
				}
				if want := sha256.Sum256(h[:]); got != want {
					t.Fatalf("%q: %x, want %x", seed, got, want)
				}
			}
		})
	}
}
