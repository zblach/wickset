package ops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wickset/alg"
	"wickset/internal/gpu"
	"wickset/internal/store"
)

// TestGPUUnavailable: asking for the GPU in a build without one fails at
// once, before anything is measured or sealed.
func TestGPUUnavailable(t *testing.T) {
	if gpu.Built {
		t.Skip("this build has a GPU backend")
	}
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, []byte("x"), 0o600)
	a, _ := alg.Lookup(alg.Argon2idShort)
	err := (&Env{GPU: true}).Seal(context.Background(), SealArgs{File: file, Alg: a, N: 1000})
	if err == nil || !strings.Contains(err.Error(), "GPU") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(file + store.WickSuffix); err == nil {
		t.Fatal("sealed anyway")
	}
}
