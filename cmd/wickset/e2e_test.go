//go:build wickset_testalgs

// End-to-end tests of the wickset CLI. Each run re-executes this test binary
// as the real command (see TestMain), against the cheap private-use
// algorithms that the wickset_testalgs tag registers:
//
//	go test -tags wickset_testalgs ./cmd/wickset
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runMainEnv tells a re-executed test binary to act as the CLI.
const runMainEnv = "WICKSET_E2E_RUN_MAIN"

// wickFileHeader is CONTAINER.md §2's MAGIC ‖ VERSION ‖ DIGEST.
const wickFileHeader = 8 + 1 + 32

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type result struct {
	stdout, stderr string
	code           int
}

// output is everything the command printed; kong sends help to stdout and
// errors to stderr.
func (r result) output() string { return r.stdout + r.stderr }

// run runs the command with args and returns its output and exit code.
func run(t *testing.T, args ...string) result {
	t.Helper()
	return runStdin(t, nil, args...)
}

// runStdin is run with stdin as the command's standard input.
func runStdin(t *testing.T, stdin []byte, args ...string) result {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil && cmd.ProcessState == nil {
		t.Fatalf("wickset %v: %v", args, err)
	}
	return result{stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()}
}

// mustRun is run for a command that must exit 0.
func mustRun(t *testing.T, args ...string) result {
	t.Helper()
	r := run(t, args...)
	if r.code != 0 {
		t.Fatalf("wickset %v: exit %d\n%s", args, r.code, r.output())
	}
	return r
}

// wantFail runs a command that must exit with code and mention msg.
func wantFail(t *testing.T, code int, msg string, args ...string) {
	t.Helper()
	r := run(t, args...)
	if r.code != code || !strings.Contains(r.output(), msg) {
		t.Errorf("wickset %v: exit %d, want %d mentioning %q\n%s", args, r.code, code, msg, r.output())
	}
}

// writePlain writes a random plaintext to dir/name and returns its path.
func writePlain(t *testing.T, dir, name string) (string, []byte) {
	t.Helper()
	pt := make([]byte, 4096)
	rand.Read(pt)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pt, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pt
}

// wantInfo checks that info on wick succeeds and prints the row key: value.
func wantInfo(t *testing.T, wick, key, value string) {
	t.Helper()
	line := fmt.Sprintf("%-8s %s", key, value)
	if r := mustRun(t, "info", wick); !strings.Contains(r.stdout, line) {
		t.Fatalf("info: want %q in\n%s", line, r.stdout)
	}
}

func wantFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s: plaintext mismatch (%v)", path, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s: mode %v, want 0600", path, fi.Mode().Perm())
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestSealExtendOpen is the whole lifecycle for each block size, using the
// default paths: seal FILE, extend FILE.wick in place, open FILE.wick back
// into FILE. The pre-extension wick still opens, with explicit paths.
func TestSealExtendOpen(t *testing.T) {
	for _, tc := range []struct {
		alg string // as given to --alg: id or name
		b   int
	}{{"0xFE", 32}, {"test-e2e-sha256-16", 16}} {
		t.Run(tc.alg, func(t *testing.T) {
			dir := t.TempDir()
			p := func(name string) string { return filepath.Join(dir, name) }
			plain, pt := writePlain(t, dir, "plain")

			mustRun(t, "seal", "--alg", tc.alg, "-n", "50", "-w", "4", plain)
			wantInfo(t, p("plain.wick"), "N", "50 (51 sequential steps)")
			wantInfo(t, p("plain.wick"), "form", "wick file v1, digest ok")
			wantInfo(t, p("plain.wick"), "payload", p("plain.payload")+": pairs with this wick, digest ok")
			orig := readFile(t, p("plain.wick"))
			if len(orig) != wickFileHeader+1+52*tc.b {
				t.Fatalf("wick file is %d bytes, want %d", len(orig), wickFileHeader+1+52*tc.b)
			}
			os.WriteFile(p("orig.wick"), orig, 0o600)

			mustRun(t, "extend", "--add", "25", p("plain.wick"))
			wantInfo(t, p("plain.wick"), "N", "75 (76 sequential steps)")
			ext := readFile(t, p("plain.wick"))
			origObj, extObj := orig[wickFileHeader:], ext[wickFileHeader:]
			if !bytes.Equal(extObj[:len(origObj)-tc.b], origObj[:len(origObj)-tc.b]) {
				t.Fatal("extend changed existing blocks")
			}
			// The payload names its wick by block 0, so it still pairs.
			wantInfo(t, p("plain.wick"), "payload", p("plain.payload")+": pairs with this wick, digest ok")

			// The default output is FILE, which still exists: refused up front.
			wantFail(t, 1, "already exists", "open", p("plain.wick"))
			os.Remove(plain)
			mustRun(t, "open", p("plain.wick"))
			wantFile(t, plain, pt)

			// SPEC.md §10: extension binds only those who never saw the original.
			mustRun(t, "open", "--payload", p("plain.payload"), "--out", p("out.orig"), p("orig.wick"))
			wantFile(t, p("out.orig"), pt)

			if names, want := dirNames(t, dir), []string{"orig.wick", "out.orig", "plain", "plain.payload", "plain.wick"}; !slices.Equal(names, want) {
				t.Fatalf("directory holds %v, want %v (stray temp files?)", names, want)
			}
		})
	}
}

func TestSealByDelay(t *testing.T) {
	dir := t.TempDir()
	plain, pt := writePlain(t, dir, "plain")
	mustRun(t, "seal", "--alg", "0xFE", "-d", "2ms", plain)
	if r := mustRun(t, "info", plain+".wick"); strings.Contains(r.stdout, "N        0 ") {
		t.Fatalf("2ms of nanosecond steps gave N = 0:\n%s", r.stdout)
	}
	os.Remove(plain)
	mustRun(t, "open", plain+".wick")
	wantFile(t, plain, pt)

	// Without --alg, a delay chooses: under a day on the CPU, 0x01 (real,
	// so this costs four ~0.3 s steps: three to measure, one to seal).
	r := mustRun(t, "--cpu", "seal", "-d", "1ms", "--wick", plain+".auto.wick", "--payload", plain+".auto.payload", plain)
	if !strings.Contains(r.stderr, "algorithm 0x01") || !strings.Contains(r.stderr, "measuring") {
		t.Fatalf("auto choice or measuring not reported:\n%s", r.stderr)
	}
	wantInfo(t, plain+".auto.wick", "alg", "0x01 (argon2id-m128M-t5-p1) (B = 32)")
}

// TestEitherFile: open and info take either file of a pair and find the
// other by name, or by --wick and --payload; extend takes only the wick. A
// payload whose wick is missing is a usage error, before any work.
func TestEitherFile(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	plain, pt := writePlain(t, dir, "plain")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "20", plain)
	os.Remove(plain)

	wantInfo(t, p("plain.payload"), "N", "20 (21 sequential steps)")
	mustRun(t, "open", p("plain.payload"))
	wantFile(t, plain, pt)

	wantFail(t, 2, "plain.payload is a payload; extend works on its wick", "extend", "-a", "1", p("plain.payload"))
	// A file is one end of the pair; a flag for that same end is a conflict.
	other, _ := writePlain(t, dir, "other")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "0", other)
	wantFail(t, 2, "drop --wick", "open", "--wick", other+".wick", "--out", p("x"), p("plain.wick"))
	wantFail(t, 2, "drop --payload", "open", "--payload", other+".payload", "--out", p("x"), p("plain.payload"))
	wantFail(t, 1, "this is a payload file, not a wick", "open", "--wick", other+".payload", "--out", p("x"), p("plain.payload"))

	// Renamed apart, the pair is named by flag, from either end.
	os.Rename(p("plain.wick"), p("burn-me"))
	wantFail(t, 2, "its wick "+p("plain.wick")+" is not there; give it with --wick", "open", "--out", p("x"), p("plain.payload"))
	mustRun(t, "open", "--wick", p("burn-me"), "--out", p("by-wick"), p("plain.payload"))
	wantFile(t, p("by-wick"), pt)
	mustRun(t, "open", "--payload", p("plain.payload"), "--out", p("by-payload"), p("burn-me"))
	wantFile(t, p("by-payload"), pt)

	// A library error's own "wickset: " is not said twice.
	os.WriteFile(p("junk"), []byte("not a wick"), 0o600)
	if r := run(t, "info", p("junk")); r.code != 1 || strings.Count(r.stderr, "wickset:") != 1 {
		t.Errorf("exit %d:\n%s", r.code, r.stderr)
	}
}

// TestRaw: --raw writes the bare SPEC.md wick, and extend keeps it raw.
func TestRaw(t *testing.T) {
	dir := t.TempDir()
	plain, pt := writePlain(t, dir, "plain")
	wick := plain + ".wick"
	mustRun(t, "seal", "--alg", "0xFE", "-n", "5", "--raw", plain)
	if b := readFile(t, wick); len(b) != 1+7*32 || b[0] != 0xFE {
		t.Fatalf("raw wick: %d bytes starting %#x, want %d starting 0xfe", len(b), b[0], 1+7*32)
	}
	wantInfo(t, wick, "form", "raw wick (no digest)")
	mustRun(t, "extend", "-a", "5", wick)
	if b := readFile(t, wick); len(b) != 1+12*32 {
		t.Fatalf("extended raw wick is %d bytes, want %d", len(b), 1+12*32)
	}
	os.Remove(plain)
	mustRun(t, "open", wick)
	wantFile(t, plain, pt)
}

// TestDamage: everything checkable without the secret fails before burning
// (CONTAINER.md); a raw wick has no digest, so its damage reaches the GCM tag.
// No plaintext is ever written.
func TestDamage(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	a, _ := writePlain(t, dir, "a")
	b, _ := writePlain(t, dir, "b")
	r, _ := writePlain(t, dir, "r")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "10", a)
	mustRun(t, "seal", "--alg", "0xFE", "-n", "10", b)
	mustRun(t, "seal", "--alg", "0xFE", "-n", "10", "--raw", r)

	corrupt := func(src, dst string) {
		data := readFile(t, src)
		data[len(data)/2] ^= 1
		os.WriteFile(dst, data, 0o600)
	}
	corrupt(p("a.wick"), p("bad.wick"))
	corrupt(p("a.payload"), p("bad.payload"))
	corrupt(p("r.wick"), p("badraw.wick"))

	for _, c := range []struct{ name, wick, payload, msg string }{
		{"corrupt wick", "bad.wick", "a.payload", "wick file digest mismatch"},
		{"corrupt payload", "a.wick", "bad.payload", "payload file digest mismatch"},
		{"mismatched pair", "a.wick", "b.payload", "payload belongs to a different wick"},
		{"corrupt raw wick", "badraw.wick", "r.payload", "payload authentication failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantFail(t, 1, c.msg, "open", "--payload", p(c.payload), "--out", p("out"), p(c.wick))
		})
	}
	if _, err := os.Stat(p("out")); !os.IsNotExist(err) {
		t.Error("plaintext written despite failure")
	}

	// info is the same pre-flight, without burning.
	os.WriteFile(p("mixed.wick"), readFile(t, p("a.wick")), 0o600)
	os.WriteFile(p("mixed.payload"), readFile(t, p("b.payload")), 0o600)
	wantFail(t, 1, "payload belongs to a different wick", "info", p("mixed.wick"))

	// extend refuses a corrupt wick rather than sealing the damage under a new
	// digest, and leaves the file as it was.
	before := readFile(t, p("bad.wick"))
	wantFail(t, 1, "wick file digest mismatch", "extend", "-a", "1", p("bad.wick"))
	if !bytes.Equal(readFile(t, p("bad.wick")), before) {
		t.Error("extend rewrote a corrupt wick")
	}
}

// TestKeyBypass: the key saved by seal --key-out, or by open --key-out after
// burning, opens the payload with bypass, with no burning and however far the
// wick has been extended: from the payload alone or via its wick,
// from a file or standard input.
func TestKeyBypass(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	plain, pt := writePlain(t, dir, "plain")

	r := mustRun(t, "seal", "--alg", "0xFE", "-n", "30", "--key-out", p("k"), plain)
	if strings.Contains(r.output(), "wickset-key-v1:") {
		t.Fatalf("seal printed the key:\n%s", r.output())
	}
	key := readFile(t, p("k"))
	if !strings.HasPrefix(string(key), "wickset-key-v1:") {
		t.Fatalf("key file holds %q", key)
	}
	if fi, _ := os.Stat(p("k")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", fi.Mode().Perm())
	}
	mustRun(t, "extend", "-a", "20", p("plain.wick"))
	os.Remove(plain)

	mustRun(t, "bypass", "--key", p("k"), p("plain.payload")) // default output: plain
	wantFile(t, plain, pt)
	mustRun(t, "bypass", "--key", p("k"), "--out", p("via-wick"), p("plain.wick"))
	wantFile(t, p("via-wick"), pt)
	if r := runStdin(t, key, "bypass", "--key", "-", "--out", p("via-stdin"), p("plain.payload")); r.code != 0 {
		t.Fatalf("key on stdin: exit %d\n%s", r.code, r.output())
	}
	wantFile(t, p("via-stdin"), pt)

	// Burning recovers the same key, and --key-out - prints it to stdout.
	mustRun(t, "open", "--out", p("solved"), "--key-out", p("k2"), p("plain.wick"))
	if !bytes.Equal(readFile(t, p("k2")), key) {
		t.Fatal("open --key-out saved a different key than seal")
	}
	if r := mustRun(t, "open", "--out", p("solved2"), "--key-out", "-", p("plain.wick")); r.stdout != string(key) {
		t.Fatalf("open --key-out - printed %q, want the key", r.stdout)
	}

	// Failures: wrong key, a wick that is not the payload's, a bad key file,
	// no key at all. A key file others can read is used, with a warning.
	other, _ := writePlain(t, dir, "other")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "5", "--key-out", p("ko"), other)
	wantFail(t, 1, "wrong key for this payload", "bypass", "--key", p("ko"), "--out", p("x"), p("plain.payload"))
	wantFail(t, 1, "payload belongs to a different wick", "bypass", "--key", p("k"), "--payload", p("plain.payload"), "--out", p("x"), other+".wick")
	os.WriteFile(p("bad-key"), []byte("hunter2\n"), 0o600)
	wantFail(t, 1, "malformed key", "bypass", "--key", p("bad-key"), "--out", p("x"), p("plain.payload"))
	wantFail(t, 2, "missing flags: --key", "bypass", p("plain.payload"))
	if _, err := os.Stat(p("x")); !os.IsNotExist(err) {
		t.Error("plaintext written despite failure")
	}
	os.Chmod(p("k"), 0o644)
	if r := mustRun(t, "bypass", "--key", p("k"), "--out", p("loose"), p("plain.payload")); !strings.Contains(r.stderr, "readable by others") {
		t.Errorf("no warning for a world-readable key file:\n%s", r.stderr)
	}
}

// TestRejectsUndefined: only the tagged end-to-end ids are enabled. The unit
// tests' 0xF0 and unassigned ids are still refused, by flag and by Parse.
func TestRejectsUndefined(t *testing.T) {
	dir := t.TempDir()
	plain, _ := writePlain(t, dir, "plain")
	for _, alg := range []string{"0xF0", "0x05", "0", "256", "nope", "argon2id-m1G-t30-p1"} {
		wantFail(t, 2, "--alg", "seal", "--alg", alg, "-n", "1", plain)
	}
	f0 := filepath.Join(dir, "f0.wick")
	os.WriteFile(f0, append([]byte{0xF0}, make([]byte, 3*32)...), 0o600)
	wantFail(t, 1, "algorithm id not defined", "info", f0)
}

// TestUsage: bad invocations exit 2 with the command's usage; --help exits 0.
func TestUsage(t *testing.T) {
	dir := t.TempDir()
	plain, _ := writePlain(t, dir, "plain")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "0", plain)
	wick := plain + ".wick"

	// Nothing is replaced: an earlier wick, or a key, may be the only copy.
	wantFail(t, 1, wick+" already exists", "seal", "--alg", "0xFE", "-n", "0", plain)
	key := filepath.Join(dir, "k")
	os.WriteFile(key, []byte("someone's key"), 0o600)
	wantFail(t, 1, key+" already exists", "seal", "--alg", "0xFE", "-n", "0", "--wick", filepath.Join(dir, "w2"), "--payload", filepath.Join(dir, "p2"), "--key-out", key, plain)
	wantFail(t, 1, key+" already exists", "open", "--out", filepath.Join(dir, "o"), "--key-out", key, wick)
	wantFail(t, 1, key+" already exists", "extend", "-a", "1", "--out", key, wick)
	if names := dirNames(t, dir); slices.Contains(names, "w2") || slices.Contains(names, "o") {
		t.Fatalf("a refused command wrote files: %v", names)
	}

	wantFail(t, 2, "give -n or --delay", "seal", plain)
	wantFail(t, 2, "-n needs --alg", "seal", "-n", "1", plain)
	wantFail(t, 2, "can't be used together", "seal", "--alg", "0xFE", "-n", "1", "-d", "1s", plain)
	wantFail(t, 2, "give --add or --delay", "extend", wick)
	wantFail(t, 2, "Usage: wickset seal", "seal")
	wantFail(t, 2, "no such file", "info", filepath.Join(dir, "missing.wick"))
	wantFail(t, 2, "unexpected argument frob", "frob")
	wantFail(t, 2, "--gpu-memory", "--gpu-memory", "lots", "seal", "--alg", "0xFE", "-n", "1", plain)

	// Outputs that cannot be written are usage errors, before any work.
	missing := filepath.Join(dir, "missing", "x")
	wantFail(t, 2, "--out: cannot write", "open", "--out", missing, wick)
	wantFail(t, 2, "is a directory", "open", "--out", dir, wick)
	wantFail(t, 2, "--key-out: cannot write", "seal", "--alg", "0xFE", "-n", "0", "--key-out", missing, plain)
	wantFail(t, 2, "--wick: cannot write", "seal", "--alg", "0xFE", "-n", "0", "--wick", missing, plain)

	// Without a .wick suffix there is no default output name.
	os.Rename(wick, filepath.Join(dir, "renamed"))
	wantFail(t, 1, "does not end in .wick", "open", "--payload", plain+".payload", filepath.Join(dir, "renamed"))

	for _, args := range [][]string{{"--help"}, {"seal", "--help"}, {"open", "-h"}} {
		if r := mustRun(t, args...); !strings.Contains(r.stdout, "Usage: wickset") {
			t.Errorf("wickset %v: no usage on stdout\n%s", args, r.output())
		}
	}
}

// TestDevNull: opening into /dev/null burns the wick and checks the payload,
// keeping nothing: a way to prove a wick opens.
func TestDevNull(t *testing.T) {
	dir := t.TempDir()
	plain, _ := writePlain(t, dir, "plain")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "3", plain)
	os.Remove(plain)
	mustRun(t, "open", "--out", "/dev/null", plain+".wick")
	if names := dirNames(t, dir); !slices.Equal(names, []string{"plain.payload", "plain.wick"}) {
		t.Fatalf("directory holds %v", names)
	}
}

// TestCompletion: asked as a shell asks (COMP_LINE), the command completes
// wicks where only a wick goes, either file of a pair where either does,
// and the algorithms for --alg.
func TestCompletion(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.wick", "b.wick", "c.payload", "d.txt"} {
		os.WriteFile(filepath.Join(dir, name), nil, 0o600)
	}
	complete := func(line string) []string {
		cmd := exec.CommandContext(t.Context(), os.Args[0])
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), runMainEnv+"=1", "COMP_LINE="+line, fmt.Sprintf("COMP_POINT=%d", len(line)))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		return strings.Fields(string(out))
	}
	if got := complete("wickset extend "); !slices.Contains(got, "a.wick") || !slices.Contains(got, "b.wick") ||
		slices.Contains(got, "c.payload") || slices.Contains(got, "d.txt") {
		t.Errorf("extend completes %v", got)
	}
	if got := complete("wickset open "); !slices.Contains(got, "a.wick") || !slices.Contains(got, "c.payload") || slices.Contains(got, "d.txt") {
		t.Errorf("open completes %v", got)
	}
	if got := complete("wickset bypass "); !slices.Contains(got, "a.wick") || !slices.Contains(got, "c.payload") || slices.Contains(got, "d.txt") {
		t.Errorf("bypass completes %v", got)
	}
	if got := complete("wickset seal --alg "); !slices.Contains(got, "0x01") || !slices.Contains(got, "sha256-iter-k29") {
		t.Errorf("--alg completes %v", got)
	}
}

// TestBenchCSV: bench --csv prints a header and one row of the same width,
// for benchmarks/scores.csv.
func TestBenchCSV(t *testing.T) {
	r := mustRun(t, "--cpu", "bench", "--csv", "--alg", "0xFE")
	rows, err := csv.NewReader(strings.NewReader(r.stdout)).ReadAll()
	if err != nil || len(rows) != 2 || rows[0][0] != "date" || len(rows[1]) != len(rows[0]) {
		t.Fatalf("bench --csv printed %q (%v)", r.stdout, err)
	}
}

// TestVersion: --version names the program and says this is a test build.
func TestVersion(t *testing.T) {
	r := mustRun(t, "--version")
	if !strings.HasPrefix(r.stdout, "wickset ") || !strings.Contains(r.stdout, "TEST BUILD") {
		t.Fatalf("--version printed %q", r.stdout)
	}
}

func TestWarnsTestBuild(t *testing.T) {
	dir := t.TempDir()
	plain, _ := writePlain(t, dir, "plain")
	if r := mustRun(t, "seal", "--alg", "0xFE", "-n", "0", plain); !strings.Contains(r.stderr, "warning: test build") {
		t.Fatalf("no test-build warning:\n%s", r.stderr)
	}
}
