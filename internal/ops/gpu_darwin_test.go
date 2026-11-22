//go:build darwin && cgo

package ops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chainlock/alg"
	"chainlock/chain"
)

// TestSealWithGPU seals real short-step locks on the GPU, then opens them on
// the CPU, as any solver would: the GPU's steps are exactly the CPU's, or the
// plaintext never comes back. The SHA-256 chain, ~45 s of one GPU thread a
// step, runs without -short.
func TestSealWithGPU(t *testing.T) {
	for _, id := range []alg.ID{alg.Argon2idShort, alg.SHA256Short} {
		t.Run(id.String(), func(t *testing.T) {
			if testing.Short() && id == alg.SHA256Short {
				t.Skip("~45 s a step on the GPU: skipped with -short")
			}
			sealWithGPU(t, id)
		})
	}
}

func sealWithGPU(t *testing.T, id alg.ID) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	plaintext := []byte("sealed partly on the GPU")
	if err := os.WriteFile(file, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	var notes []string
	workers := map[int]bool{}
	e := &Env{
		Note: func(n Note) { notes = append(notes, n.String()) },
		Events: func(ev Event) { // serialized
			if ev.Kind == StepEvent && ev.Step.Kind == chain.Began {
				workers[ev.Step.Worker] = true
			}
		},
	}
	a, _ := alg.Lookup(id)
	start := time.Now()
	e.GPU = true
	if err := e.Seal(t.Context(), SealArgs{File: file, Alg: a, N: 59, Workers: 2}); err != nil {
		t.Fatal(err)
	}
	t.Logf("sealed 60 steps in %v", time.Since(start).Round(time.Millisecond))
	if !strings.Contains(strings.Join(notes, "\n"), "the GPU computes the steps") {
		t.Fatalf("no GPU note:\n%s", strings.Join(notes, "\n"))
	}
	if len(workers) != 1 || !workers[0] {
		t.Fatalf("the GPU is the one worker, 0; started: %v", workers)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if err := (&Env{}).Open(t.Context(), OpenArgs{File: file + ".lock"}); err != nil {
		t.Fatalf("the GPU-sealed lock does not open on the CPU: %v", err)
	}
	t.Logf("opened 60 steps on one core in %v", time.Since(start).Round(time.Millisecond))
	if got, _ := os.ReadFile(file); !bytes.Equal(got, plaintext) {
		t.Fatalf("opened to %q", got)
	}
}
