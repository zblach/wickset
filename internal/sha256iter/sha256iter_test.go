package sha256iter

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// TestVendored: Go's files are exactly those SHA256SUMS records, so none has
// been edited, and every one listed is present.
func TestVendored(t *testing.T) {
	sums, err := os.ReadFile("SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for line := range strings.Lines(string(sums)) {
		want, name, ok := strings.Cut(strings.TrimSpace(line), "  ")
		if !ok {
			t.Fatalf("SHA256SUMS line %q", line)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != want {
			t.Errorf("%s differs from Go 1.27.4's: vendored files are never edited", name)
		}
		n++
	}
	if n != 3 {
		t.Errorf("%d files in SHA256SUMS, want 3", n)
	}
}

// TestMatchesStdlib: Iterate is crypto/sha256's Sum256 applied n times, for
// any start and count, on the assembly where this CPU has it.
func TestMatchesStdlib(t *testing.T) {
	t.Logf("accelerated: %v", Accelerated())
	for _, n := range []uint64{0, 1, 2, 3, 64, 1000, 100_003} {
		for _, seed := range []string{"", "wickset", "\xff\x00 any 32 bytes, or fewer"} {
			h := sha256.Sum256([]byte(seed))
			want := h
			for range n {
				want = sha256.Sum256(want[:])
			}
			if got := Iterate(h, n); got != want {
				t.Fatalf("Iterate(%q, %d) = %x, want %x", seed, n, got, want)
			}
		}
	}
}

// TestFaster: where it runs on the SHA instructions, Iterate is well ahead of
// Sum256, which pays a digest's setup and finish on every hash.
func TestFaster(t *testing.T) {
	if !Accelerated() || testing.Short() {
		t.Skip("needs SHA instructions; skipped with -short")
	}
	const n = 1 << 22
	h := sha256.Sum256(nil)
	start := time.Now()
	for range n {
		h = sha256.Sum256(h[:])
	}
	slow := time.Since(start)
	start = time.Now()
	Iterate(h, n)
	fast := time.Since(start)
	t.Logf("Sum256 %.1f M/s, Iterate %.1f M/s", n/slow.Seconds()/1e6, n/fast.Seconds()/1e6)
	if fast > slow*3/4 {
		t.Errorf("Iterate %v against Sum256's %v: not faster", fast, slow)
	}
}

// BenchmarkIterate reports one core's iterated SHA-256 rate.
func BenchmarkIterate(b *testing.B) {
	var h [32]byte
	for b.Loop() {
		h = Iterate(h, 1<<20)
	}
	b.ReportMetric(float64(b.N<<20)/b.Elapsed().Seconds()/1e6, "Mhash/s")
}
