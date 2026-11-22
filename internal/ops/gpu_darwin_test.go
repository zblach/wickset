//go:build darwin && cgo

package ops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"chainlock/alg"
	"chainlock/chain"
)

// TestSealWithGPU seals a real 0x01 lock on the GPU, then opens it on the
// CPU, as any solver would: the GPU's steps are exactly the CPU's, or the
// plaintext never comes back.
func TestSealWithGPU(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	plaintext := []byte("sealed partly on the GPU")
	if err := os.WriteFile(file, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	var notes []string
	var mu sync.Mutex
	workers := map[int]bool{}
	e := &Env{
		Note: func(n Note) { notes = append(notes, n.String()) },
		Activity: func(label string, total int) chain.Activity {
			return func(w, first, _ int) {
				mu.Lock()
				defer mu.Unlock()
				if first >= 0 {
					workers[w] = true
				}
			}
		},
	}
	a, _ := alg.Lookup(alg.Argon2id256M)
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
