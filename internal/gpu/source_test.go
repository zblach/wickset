package gpu

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"wickset/internal/argon2"
)

// A Device is an Argon2id backend like any other, in every build.
var _ argon2.Hasher = (*Device)(nil)

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
	if n != 13 {
		t.Errorf("%d files in SHA256SUMS, want 13", n)
	}
}

// TestSource: the kernel expands to one unit with no include left but
// Metal's own, each file once, and hashcat's Argon2 and SHA-256 in it.
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
	for _, s := range []string{"argon2_fill_segment", "wickset_argon2_fill", "sha256_transform", "wickset_sha256_iter", "#include <metal_stdlib>"} {
		if !strings.Contains(src, s) {
			t.Errorf("source lacks %q", s)
		}
	}
	if n := strings.Count(src, "#line 1 \"inc_common.cl\""); n != 1 {
		t.Errorf("inc_common.cl expanded %d times", n)
	}
}

// TestJob: the job is wickset_job_t's size, with the options x/crypto
// would use.
func TestJob(t *testing.T) {
	p := argon2.Params{Salt: []byte("wickset/v1::01"), MemoryKiB: 262145, Passes: 3, KeyLen: 32}
	if j := job(p, 5, 32); len(j) != 12*4+256 {
		t.Fatalf("job is %d bytes", len(j))
	}
	if blocks(p) != 262144 || blocks(argon2.Params{MemoryKiB: 3}) != 8 {
		t.Fatalf("blocks %d", blocks(p))
	}
	if check(p, 32) != nil || check(p, 30) == nil || check(argon2.Params{Passes: 1, KeyLen: 12}, 4) == nil {
		t.Fatal("check")
	}
}
