//go:build darwin && cgo

package ops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wickset/alg"
	"wickset/internal/store"
	"wickset/wick"
)

// TestSealWithGPU seals a real 0x01 wick through Seal, which puts its 60
// steps on the GPU (many more than 2 workers' worth), then opens it on the
// CPU, as any solver would: the GPU's steps are exactly the CPU's, or the
// plaintext never comes back.
func TestSealWithGPU(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	plaintext := []byte("sealed on the GPU")
	if err := os.WriteFile(file, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	var notes []string
	workers := map[int]bool{}
	e := &Env{
		Note: func(n Note) { notes = append(notes, n.String()) },
		Events: func(ev Event) { // serialized
			if ev.Kind == StepEvent && ev.Step.Kind == wick.Began {
				workers[ev.Step.Worker] = true
			}
		},
		GPU: true,
	}
	a, _ := alg.Lookup(alg.Argon2idShort)
	start := time.Now()
	if err := e.Seal(t.Context(), SealArgs{File: file, Alg: a, N: 59, Workers: 2}); err != nil {
		t.Fatal(err)
	}
	t.Logf("sealed 60 steps in %v", time.Since(start).Round(time.Millisecond))
	if !strings.Contains(strings.Join(notes, "\n"), "sealing on the "+GPUName()+" GPU") {
		t.Fatalf("no GPU note:\n%s", strings.Join(notes, "\n"))
	}
	if len(workers) != 1 || !workers[0] {
		t.Fatalf("the GPU is the one worker, 0; started: %v", workers)
	}
	os.Remove(file)
	if err := (&Env{}).Open(t.Context(), OpenArgs{File: file + store.WickSuffix}); err != nil {
		t.Fatalf("the GPU-sealed wick does not open on the CPU: %v", err)
	}
	if got, _ := os.ReadFile(file); !bytes.Equal(got, plaintext) {
		t.Fatalf("opened to %q", got)
	}
}

// TestSHA256OnGPU: a few SHA-256 steps go to the CPU, being far quicker
// there; and the GPU's steps, built on it directly, burn on the CPU to the
// same secret. One GPU thread takes ~45 s a 0x03 step: without -short only.
func TestSHA256OnGPU(t *testing.T) {
	a, _ := alg.Lookup(alg.SHA256Short)
	var notes []string
	e := &Env{Note: func(n Note) { notes = append(notes, n.String()) }, GPU: true}
	b, _, err := e.gpuBatcher(a)
	if err != nil || b == nil {
		t.Fatalf("no GPU batcher: %v %q", err, notes)
	}
	if o := e.place(a, wick.Opts{Workers: 2}, b, 30); o.Batcher != nil || !strings.Contains(strings.Join(notes, "\n"), "too few to fill the GPU") {
		t.Fatalf("30 steps went to the GPU: %q", notes)
	}
	if testing.Short() {
		t.Skip("~45 s of one GPU thread a step: skipped with -short")
	}
	raw, key, err := wick.New(t.Context(), a.ID(), 2, wick.Opts{Batcher: b})
	if err != nil {
		t.Fatal(err)
	}
	o, err := wick.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if solved, err := wick.Solve(t.Context(), o, nil); err != nil || !bytes.Equal(solved, key) {
		t.Fatalf("the GPU's wick burns on the CPU to a different key (%v)", err)
	}
}
