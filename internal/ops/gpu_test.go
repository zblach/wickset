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

// noted is an Env that keeps its notes as lines.
func noted() (*Env, *[]string) {
	var notes []string
	return &Env{Note: func(n Note) { notes = append(notes, n.String()) }}, &notes
}

// TestGPUFallsBack: where the GPU cannot do the work, the CPU does, and says
// so: a build without one, and an algorithm it cannot run.
func TestGPUFallsBack(t *testing.T) {
	e, notes := noted()
	e.GPU = true
	if b, _, err := e.gpuBatcher(fakeAlg{}); b != nil || err != nil || !strings.Contains(strings.Join(*notes, "\n"), "sealing on the CPU") {
		t.Fatalf("an algorithm the GPU cannot run: batcher %v, err %v, notes %q", b, err, *notes)
	}
	if gpu.Built {
		return // the rest needs a build with no GPU backend
	}
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, []byte("x"), 0o600)
	a, _ := alg.Lookup(alg.Argon2idShort)
	e, notes = noted()
	e.GPU = true
	if err := e.Seal(context.Background(), SealArgs{File: file, Alg: a, N: 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file + store.WickSuffix); err != nil || !strings.Contains(strings.Join(*notes, "\n"), "sealing on the CPU") {
		t.Fatalf("no GPU backend: %v, notes %q", err, *notes)
	}
}

// TestBudget: a GPU memory budget is a size in binary units or a share of
// the GPU's memory, half by default.
func TestBudget(t *testing.T) {
	const total = 32 << 30
	for in, want := range map[string]uint64{
		"8G":    8 << 30,
		"8GiB":  8 << 30,
		"8 GB":  8 << 30,
		"512M":  512 << 20,
		"1.5G":  3 << 29,
		"2T":    2 << 40,
		"4096B": 4096,
		"25%":   total / 4,
		"100%":  total,
		"12.5%": total / 8,
	} {
		b, err := ParseBudget(in)
		if err != nil || b.Of(total) != want {
			t.Errorf("ParseBudget(%q) = %v of %d, %v; want %d", in, b, b.Of(total), err, want)
		}
	}
	for _, in := range []string{"", "8", "0G", "-1G", "101%", "8X", "G", "half"} {
		if b, err := ParseBudget(in); err == nil {
			t.Errorf("ParseBudget(%q) = %v, want an error", in, b)
		}
	}
	if (Budget{}).Of(total) != total/2 || (Budget{}).String() != "50%" {
		t.Errorf("the zero budget is %d (%v), not half", (Budget{}).Of(total), Budget{})
	}
}
