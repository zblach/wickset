package argon2gpu

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestVendored: hashcat's files are exactly those SHA256SUMS records, so
// none has been edited, and every file listed is present.
func TestVendored(t *testing.T) {
	sums, err := files.ReadFile("hashcat/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for line := range strings.Lines(string(sums)) {
		want, name, ok := strings.Cut(strings.TrimSpace(line), "  ")
		if !ok {
			t.Fatalf("SHA256SUMS line %q", line)
		}
		data, err := files.ReadFile("hashcat/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != want {
			t.Errorf("%s differs from hashcat v8.0.0: vendored files are never edited", name)
		}
		n++
	}
	if n != 11 {
		t.Errorf("%d files in SHA256SUMS, want 11", n)
	}
}

// TestSource: the kernel expands to one unit with no include left but
// Metal's own, each file once, and hashcat's Argon2 in it.
func TestSource(t *testing.T) {
	src, err := source()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(src) {
		if include.MatchString(line) {
			t.Errorf("unexpanded: %s", line)
		}
	}
	for _, s := range []string{"argon2_fill_segment", "chainlock_argon2_fill", "#include <metal_stdlib>"} {
		if !strings.Contains(src, s) {
			t.Errorf("source lacks %q", s)
		}
	}
	if n := strings.Count(src, "#line 1 \"inc_common.cl\""); n != 1 {
		t.Errorf("inc_common.cl expanded %d times", n)
	}
}

// TestJob: the job is chainlock_job_t's size, with the options x/crypto
// would use.
func TestJob(t *testing.T) {
	p := Params{Salt: []byte("chainlock/v1::01"), MemoryKiB: 262145, Passes: 3, KeyLen: 32}
	j := p.job(5, 32)
	if len(j) != 12*4+256 {
		t.Fatalf("job is %d bytes", len(j))
	}
	if p.blocks() != 262144 || (Params{MemoryKiB: 3}).blocks() != 8 {
		t.Fatalf("blocks %d", p.blocks())
	}
	if p.check(32) != nil || p.check(30) == nil || (Params{Passes: 1, KeyLen: 12}).check(4) == nil {
		t.Fatal("check")
	}
}
