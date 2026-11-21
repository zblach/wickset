//go:build unix

package chain

import (
	"runtime"
	"syscall"
	"testing"

	"chainlock/alg"
)

// Benchmarks for the real algorithms. Run one at a time, so peak RSS belongs
// to that benchmark:
//
//	go test -run '^$' -bench 'Step/argon2id-m256M' -benchtime 8x ./chain

// reportPeakRSS reports the process's peak resident set size so far.
func reportPeakRSS(b *testing.B) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return
	}
	unit := 1024.0 // Linux and the BSDs report KiB
	if runtime.GOOS == "darwin" {
		unit = 1 << 20 // macOS reports bytes
	}
	b.ReportMetric(float64(ru.Maxrss)/unit, "peak-MiB")
}

// BenchmarkStep is one evaluation of H, back to back as a solve does them.
func BenchmarkStep(b *testing.B) {
	for _, a := range alg.All() {
		b.Run(a.Name(), func(b *testing.B) {
			x := make([]byte, a.BlockSize())
			b.ReportAllocs()
			for b.Loop() {
				x = a.H(x)
			}
			reportPeakRSS(b)
		})
	}
}

// BenchmarkBuildParallel builds a 0x01 object with N = 7 on four workers,
// as sealing does: eight evaluations of H, four at a time.
func BenchmarkBuildParallel(b *testing.B) {
	a, _ := alg.Lookup(alg.Argon2id256M)
	xs, err := randBlocks(8, a.BlockSize())
	if err != nil {
		b.Fatal(err)
	}
	s := make([]byte, a.BlockSize())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := build(b.Context(), a, xs, s, Opts{Workers: 4}); err != nil {
			b.Fatal(err)
		}
	}
	reportPeakRSS(b)
}

// BenchmarkSolveN7 is a full sequential solve of eight steps on 0x01.
func BenchmarkSolveN7(b *testing.B) {
	a, _ := alg.Lookup(alg.Argon2id256M)
	o, err := Parse(append([]byte{byte(a.ID())}, make([]byte, 9*a.BlockSize())...))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Solve(b.Context(), o, nil); err != nil {
			b.Fatal(err)
		}
	}
	reportPeakRSS(b)
}
