//go:build darwin && cgo

package gpu

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	xargon2 "golang.org/x/crypto/argon2"

	"chainlock/alg"
	"chainlock/internal/argon2"
)

var (
	devOnce sync.Once
	dev     *Device
	devErr  error
)

// device is the Metal device, opened once for every test: compiling the
// kernel takes seconds the first time.
func device(t testing.TB) *Device {
	t.Helper()
	devOnce.Do(func() {
		start := time.Now()
		dev, devErr = Open()
		t.Logf("compiled the kernel in %v", time.Since(start).Round(time.Millisecond))
	})
	if devErr != nil {
		t.Fatal(devErr)
	}
	return dev
}

func random(n, size int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = make([]byte, size)
		rand.Read(out[i])
	}
	return out
}

// same holds every GPU output to x/crypto's own for the same input.
func same(t *testing.T, p argon2.Params, inputs, got [][]byte) {
	t.Helper()
	if len(got) != len(inputs) {
		t.Fatalf("%d outputs for %d inputs", len(got), len(inputs))
	}
	for i, in := range inputs {
		want := xargon2.IDKey(in, p.Salt, p.Passes, p.MemoryKiB, 1, p.KeyLen)
		if !bytes.Equal(got[i], want) {
			t.Fatalf("input %d of %d: GPU %x, x/crypto %x", i, len(inputs), got[i], want)
		}
	}
}

// TestMatchesXCrypto is the gate: the GPU's Argon2id is x/crypto's, over
// parameters that exercise both addressing modes, rounding of memory, every
// segment boundary, and batches either side of a SIMD group of 32.
func TestMatchesXCrypto(t *testing.T) {
	d := device(t)
	for _, c := range []struct {
		mem, passes, keyLen uint32
		inLen, saltLen      int
	}{
		{8, 1, 32, 32, 16},    // the least memory there is
		{9, 1, 32, 32, 16},    // rounded down to 8
		{64, 1, 32, 32, 16},   // one address block per segment
		{64, 3, 32, 32, 16},   // later passes: data-dependent, XOR
		{1024, 2, 32, 32, 16}, // segments of 256 blocks: several address blocks
		{4100, 3, 32, 32, 16}, // rounded down, long segments
		{256, 2, 64, 4, 0},    // short input, no salt, longest key
		{256, 1, 8, 256, 256}, // longest input and salt, shortest key
	} {
		p := argon2.Params{Salt: random(1, c.saltLen)[0], MemoryKiB: c.mem, Passes: c.passes, KeyLen: c.keyLen}
		for _, n := range []int{1, 2, 31, 32, 33} {
			t.Run(fmt.Sprintf("m%d-t%d-k%d-in%d-salt%d-n%d", c.mem, c.passes, c.keyLen, c.inLen, c.saltLen, n), func(t *testing.T) {
				inputs := random(n, c.inLen)
				got, err := d.Hash(t.Context(), p, inputs)
				if err != nil {
					t.Fatal(err)
				}
				same(t, p, inputs, got)
			})
		}
	}
}

// TestChainlockAlgs: the GPU computes chainlock's own steps, H of each
// registered Argon2id entry, exactly. 0x02 (192 passes) runs without -short.
func TestChainlockAlgs(t *testing.T) {
	d := device(t)
	for _, id := range []alg.ID{alg.Argon2idShort, alg.Argon2idLong} {
		a, _ := alg.Lookup(id)
		t.Run(a.Name(), func(t *testing.T) {
			if testing.Short() && id == alg.Argon2idLong {
				t.Skip("192 passes: skipped with -short")
			}
			p, ok := alg.Argon2idParams(a)
			if !ok {
				t.Fatal("not Argon2id")
			}
			inputs := random(3, a.BlockSize())
			start := time.Now()
			got, err := d.Hash(t.Context(), p, inputs)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d steps on the GPU in %v", len(inputs), time.Since(start).Round(time.Millisecond))
			for i, in := range inputs {
				if !bytes.Equal(got[i], a.H(in)) {
					t.Fatalf("step %d: GPU and %s differ", i, a.Name())
				}
			}
		})
	}
}

// TestChain: the GPU's SHA-256 chains are the CPU's (alg.SHA256Chain.Run),
// across dispatches and either side of a SIMD group, reporting after each
// dispatch.
func TestChain(t *testing.T) {
	d := device(t)
	c := alg.SHA256Chain{Domain: []byte("chainlock/v1::test"), K: 2*chainDispatch + 7}
	for _, n := range []int{1, 31, 33} {
		hs := make([][32]byte, n)
		for i, x := range random(n, 32) {
			hs[i] = c.Start(x)
		}
		var reports []uint64
		got, err := d.Chain(t.Context(), hs, c.K-1, func(done uint64) { reports = append(reports, done) })
		if err != nil {
			t.Fatal(err)
		}
		for i, h := range hs {
			if want, _ := c.Run(t.Context(), h, c.K-1, nil); got[i] != want {
				t.Fatalf("chain %d of %d: GPU %x, CPU %x", i, n, got[i], want)
			}
		}
		if fmt.Sprint(reports) != fmt.Sprint([]uint64{chainDispatch, 2 * chainDispatch, c.K - 1}) {
			t.Fatalf("reports %v", reports)
		}
	}
	if b := d.ChainBatch(); b < minChains || b > maxChains {
		t.Fatalf("ChainBatch %d", b)
	} else {
		t.Logf("%d chains at a time", b)
	}
}

// TestCancel: a cancelled batch stops at the next segment.
func TestCancel(t *testing.T) {
	d := device(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p := argon2.Params{MemoryKiB: 64, Passes: 1, KeyLen: 32}
	if _, err := d.Hash(ctx, p, random(2, 32)); err != context.Canceled {
		t.Fatalf("err %v", err)
	}
}

// BenchmarkSteps reports GPU throughput on chainlock's algorithms, in steps
// a second, for batches of the given sizes (and Batch). Run on its own:
//
//	go test -run '^$' -bench Steps -benchtime 1x ./internal/gpu
func BenchmarkSteps(b *testing.B) {
	d := device(b)
	for _, id := range []alg.ID{alg.Argon2idShort, alg.Argon2idLong} {
		a, _ := alg.Lookup(id)
		p, _ := alg.Argon2idParams(a)
		for _, n := range []int{1, 8, d.Batch(p)} {
			b.Run(fmt.Sprintf("%s/batch%d", a.Name(), n), func(b *testing.B) {
				inputs := random(n, 32)
				start := time.Now()
				for b.Loop() {
					if _, err := d.Hash(b.Context(), p, inputs); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(b.N*n)/time.Since(start).Seconds(), "steps/s")
			})
		}
	}
}
