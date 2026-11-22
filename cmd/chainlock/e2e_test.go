//go:build chainlock_testalgs

// End-to-end tests of the chainlock CLI. Each run re-executes this test binary
// as the real command (see TestMain), against the cheap private-use
// algorithms that the chainlock_testalgs tag registers:
//
//	go test -tags chainlock_testalgs ./cmd/chainlock
package main

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runMainEnv tells a re-executed test binary to act as the CLI.
const runMainEnv = "CHAINLOCK_E2E_RUN_MAIN"

// lockFileHeader is CONTAINER.md §2's MAGIC ‖ VERSION ‖ DIGEST.
const lockFileHeader = 8 + 1 + 32

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
		t.Fatalf("chainlock %v: %v", args, err)
	}
	return result{stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()}
}

// mustRun is run for a command that must exit 0.
func mustRun(t *testing.T, args ...string) result {
	t.Helper()
	r := run(t, args...)
	if r.code != 0 {
		t.Fatalf("chainlock %v: exit %d\n%s", args, r.code, r.output())
	}
	return r
}

// wantFail runs a command that must exit with code and mention msg.
func wantFail(t *testing.T, code int, msg string, args ...string) {
	t.Helper()
	r := run(t, args...)
	if r.code != code || !strings.Contains(r.output(), msg) {
		t.Errorf("chainlock %v: exit %d, want %d mentioning %q\n%s", args, r.code, code, msg, r.output())
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

// wantInfo checks that info on lock succeeds and prints the row key: value.
func wantInfo(t *testing.T, lock, key, value string) {
	t.Helper()
	line := fmt.Sprintf("%-8s %s", key, value)
	if r := mustRun(t, "info", lock); !strings.Contains(r.stdout, line) {
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
// default paths: seal FILE, extend FILE.lock in place, open FILE.lock back
// into FILE. The pre-extension lock still opens, with explicit paths.
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
			wantInfo(t, p("plain.lock"), "N", "50 (51 sequential steps)")
			wantInfo(t, p("plain.lock"), "form", "lock file v1, digest ok")
			wantInfo(t, p("plain.lock"), "payload", p("plain.payload")+": pairs with this lock, digest ok")
			orig := readFile(t, p("plain.lock"))
			if len(orig) != lockFileHeader+1+52*tc.b {
				t.Fatalf("lock file is %d bytes, want %d", len(orig), lockFileHeader+1+52*tc.b)
			}
			os.WriteFile(p("orig.lock"), orig, 0o600)

			mustRun(t, "extend", "--add", "25", p("plain.lock"))
			wantInfo(t, p("plain.lock"), "N", "75 (76 sequential steps)")
			ext := readFile(t, p("plain.lock"))
			origObj, extObj := orig[lockFileHeader:], ext[lockFileHeader:]
			if !bytes.Equal(extObj[:len(origObj)-tc.b], origObj[:len(origObj)-tc.b]) {
				t.Fatal("extend changed existing blocks")
			}
			// The payload names its lock by block 0, so it still pairs.
			wantInfo(t, p("plain.lock"), "payload", p("plain.payload")+": pairs with this lock, digest ok")

			// The default output is FILE, which still exists: refused up front.
			wantFail(t, 1, "already exists", "open", p("plain.lock"))
			os.Remove(plain)
			mustRun(t, "open", p("plain.lock"))
			wantFile(t, plain, pt)

			// SPEC.md §10: extension binds only those who never saw the original.
			mustRun(t, "open", "--payload", p("plain.payload"), "--out", p("out.orig"), p("orig.lock"))
			wantFile(t, p("out.orig"), pt)

			if names, want := dirNames(t, dir), []string{"orig.lock", "out.orig", "plain", "plain.lock", "plain.payload"}; !slices.Equal(names, want) {
				t.Fatalf("directory holds %v, want %v (stray temp files?)", names, want)
			}
		})
	}
}

func TestSealByDelay(t *testing.T) {
	dir := t.TempDir()
	plain, pt := writePlain(t, dir, "plain")
	mustRun(t, "seal", "--alg", "0xFE", "-d", "2ms", plain)
	if r := mustRun(t, "info", plain+".lock"); strings.Contains(r.stdout, "N        0 ") {
		t.Fatalf("2ms of nanosecond steps gave N = 0:\n%s", r.stdout)
	}
	os.Remove(plain)
	mustRun(t, "open", plain+".lock")
	wantFile(t, plain, pt)

	// Without --alg, a delay chooses: under a day, 0x01 (real, so
	// this costs four ~0.4 s steps: three to measure, one to seal).
	r := mustRun(t, "seal", "-d", "1ms", "--archive", plain)
	if !strings.Contains(r.stderr, "algorithm 0x01") || !strings.Contains(r.stderr, "measuring") {
		t.Fatalf("auto choice or measuring not reported:\n%s", r.stderr)
	}
	wantInfo(t, plain+".chainlock.tar", "alg", "0x01 (argon2id-m128M-t5-p1) (B = 32)")
}

// TestArchive: seal --archive writes one tar holding the usual pair, which
// info, extend and open use directly, and whose members also work extracted.
func TestArchive(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	plain, pt := writePlain(t, dir, "plain")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "20", "--archive", plain)
	if names, want := dirNames(t, dir), []string{"plain", "plain.chainlock.tar"}; !slices.Equal(names, want) {
		t.Fatalf("directory holds %v, want %v", names, want)
	}
	arc := p("plain.chainlock.tar")
	wantInfo(t, arc, "form", "archive v1, lock digest ok")
	wantInfo(t, arc, "payload", "in archive: pairs with this lock, digest ok")

	mustRun(t, "extend", "-a", "5", arc)
	wantInfo(t, arc, "N", "25 (26 sequential steps)")

	// Members: exactly the pair, anonymous (CONTAINER.md §4).
	members := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(readFile(t, arc)))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Mode != 0o600 || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.ModTime.Unix() != 0 {
			t.Errorf("%s: header leaks metadata: mode %o uid %d gid %d %q/%q mtime %v",
				h.Name, h.Mode, h.Uid, h.Gid, h.Uname, h.Gname, h.ModTime)
		}
		members[h.Name], _ = io.ReadAll(tr)
	}
	if len(members) != 2 || members["plain.lock"] == nil || members["plain.payload"] == nil {
		t.Fatalf("members %v, want plain.lock and plain.payload", slices.Sorted(maps.Keys(members)))
	}

	wantFail(t, 1, "already exists", "open", arc)
	wantFail(t, 1, "holds its own payload", "open", "--payload", arc, "--out", p("x"), arc)
	os.Remove(plain)
	mustRun(t, "open", arc)
	wantFile(t, plain, pt)

	// Extracted, the members are an ordinary pair, already extended.
	sub := p("x")
	os.Mkdir(sub, 0o700)
	for name, data := range members {
		os.WriteFile(filepath.Join(sub, name), data, 0o600)
	}
	wantInfo(t, filepath.Join(sub, "plain.lock"), "N", "25 (26 sequential steps)")
	mustRun(t, "open", filepath.Join(sub, "plain.lock"))
	wantFile(t, filepath.Join(sub, "plain"), pt)
}

// TestRaw: --raw writes the bare SPEC.md object, and extend keeps it raw.
func TestRaw(t *testing.T) {
	dir := t.TempDir()
	plain, pt := writePlain(t, dir, "plain")
	lock := plain + ".lock"
	mustRun(t, "seal", "--alg", "0xFE", "-n", "5", "--raw", plain)
	if b := readFile(t, lock); len(b) != 1+7*32 || b[0] != 0xFE {
		t.Fatalf("raw lock: %d bytes starting %#x, want %d starting 0xfe", len(b), b[0], 1+7*32)
	}
	wantInfo(t, lock, "form", "raw object (no digest)")
	mustRun(t, "extend", "-a", "5", lock)
	if b := readFile(t, lock); len(b) != 1+12*32 {
		t.Fatalf("extended raw lock is %d bytes, want %d", len(b), 1+12*32)
	}
	os.Remove(plain)
	mustRun(t, "open", lock)
	wantFile(t, plain, pt)
}

// TestDamage: everything checkable without the secret fails before solving
// (CONTAINER.md); a raw lock has no digest, so its damage reaches the GCM tag.
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
	corrupt(p("a.lock"), p("bad.lock"))
	corrupt(p("a.payload"), p("bad.payload"))
	corrupt(p("r.lock"), p("badraw.lock"))

	for _, c := range []struct{ name, lock, payload, msg string }{
		{"corrupt lock", "bad.lock", "a.payload", "lock file digest mismatch"},
		{"corrupt payload", "a.lock", "bad.payload", "payload file digest mismatch"},
		{"mismatched pair", "a.lock", "b.payload", "payload belongs to a different lock"},
		{"payload as lock", "a.payload", "a.payload", "this is a payload file, not a lock"},
		{"corrupt raw lock", "badraw.lock", "r.payload", "payload authentication failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantFail(t, 1, c.msg, "open", "--payload", p(c.payload), "--out", p("out"), p(c.lock))
		})
	}
	if _, err := os.Stat(p("out")); !os.IsNotExist(err) {
		t.Error("plaintext written despite failure")
	}

	// info is the same pre-flight, without solving.
	os.WriteFile(p("mixed.lock"), readFile(t, p("a.lock")), 0o600)
	os.WriteFile(p("mixed.payload"), readFile(t, p("b.payload")), 0o600)
	wantFail(t, 1, "payload belongs to a different lock", "info", p("mixed.lock"))

	// extend refuses a corrupt lock rather than sealing the damage under a new
	// digest, and leaves the file as it was.
	before := readFile(t, p("bad.lock"))
	wantFail(t, 1, "lock file digest mismatch", "extend", "-a", "1", p("bad.lock"))
	if !bytes.Equal(readFile(t, p("bad.lock")), before) {
		t.Error("extend rewrote a corrupt lock")
	}
}

// TestKeyBypass: the key saved by seal --key-out, or by open --key-out after
// solving, opens the payload with bypass, with no solving and however far the
// lock has been extended: from the payload alone, via its lock or archive,
// from a file or standard input.
func TestKeyBypass(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	plain, pt := writePlain(t, dir, "plain")

	r := mustRun(t, "seal", "--alg", "0xFE", "-n", "30", "--key-out", p("k"), plain)
	if strings.Contains(r.output(), "chainlock-key-v1:") {
		t.Fatalf("seal printed the key:\n%s", r.output())
	}
	key := readFile(t, p("k"))
	if !strings.HasPrefix(string(key), "chainlock-key-v1:") {
		t.Fatalf("key file holds %q", key)
	}
	if fi, _ := os.Stat(p("k")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", fi.Mode().Perm())
	}
	mustRun(t, "extend", "-a", "20", p("plain.lock"))
	os.Remove(plain)

	mustRun(t, "bypass", "--key", p("k"), p("plain.payload")) // default output: plain
	wantFile(t, plain, pt)
	mustRun(t, "bypass", "--key", p("k"), "--out", p("via-lock"), p("plain.lock"))
	wantFile(t, p("via-lock"), pt)
	if r := runStdin(t, key, "bypass", "--key", "-", "--out", p("via-stdin"), p("plain.payload")); r.code != 0 {
		t.Fatalf("key on stdin: exit %d\n%s", r.code, r.output())
	}
	wantFile(t, p("via-stdin"), pt)

	// Solving recovers the same key, and --key-out - prints it to stdout.
	mustRun(t, "open", "--out", p("solved"), "--key-out", p("k2"), p("plain.lock"))
	if !bytes.Equal(readFile(t, p("k2")), key) {
		t.Fatal("open --key-out saved a different key than seal")
	}
	if r := mustRun(t, "open", "--out", p("solved2"), "--key-out", "-", p("plain.lock")); r.stdout != string(key) {
		t.Fatalf("open --key-out - printed %q, want the key", r.stdout)
	}

	// An archive works the same way.
	arc, arcPT := writePlain(t, dir, "arc")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "5", "--archive", "--key-out", p("ka"), arc)
	mustRun(t, "bypass", "--key", p("ka"), "--out", p("from-archive"), arc+".chainlock.tar")
	wantFile(t, p("from-archive"), arcPT)

	// Failures: wrong key, a lock that is not the payload's, a bad key file,
	// no key at all. A key file others can read is used, with a warning.
	wantFail(t, 1, "wrong key for this payload", "bypass", "--key", p("ka"), "--out", p("x"), p("plain.payload"))
	other, _ := writePlain(t, dir, "other")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "5", other)
	wantFail(t, 1, "payload belongs to a different lock", "bypass", "--key", p("k"), "--payload", p("plain.payload"), "--out", p("x"), other+".lock")
	wantFail(t, 1, "holds its own payload", "bypass", "--key", p("ka"), "--payload", p("plain.payload"), "--out", p("x"), arc+".chainlock.tar")
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
	f0 := filepath.Join(dir, "f0.lock")
	os.WriteFile(f0, append([]byte{0xF0}, make([]byte, 3*32)...), 0o600)
	wantFail(t, 1, "algorithm id not defined", "info", f0)
}

// TestUsage: bad invocations exit 2 with the command's usage; --help exits 0.
func TestUsage(t *testing.T) {
	dir := t.TempDir()
	plain, _ := writePlain(t, dir, "plain")
	mustRun(t, "seal", "--alg", "0xFE", "-n", "0", plain)
	lock := plain + ".lock"

	// Nothing is replaced: an earlier lock, or a key, may be the only copy.
	wantFail(t, 1, lock+" already exists", "seal", "--alg", "0xFE", "-n", "0", plain)
	key := filepath.Join(dir, "k")
	os.WriteFile(key, []byte("someone's key"), 0o600)
	wantFail(t, 1, key+" already exists", "seal", "--alg", "0xFE", "-n", "0", "--archive", "--key-out", key, plain)
	wantFail(t, 1, key+" already exists", "open", "--out", filepath.Join(dir, "o"), "--key-out", key, lock)
	wantFail(t, 1, key+" already exists", "extend", "-a", "1", "--out", key, lock)
	if names := dirNames(t, dir); slices.Contains(names, "plain.chainlock.tar") || slices.Contains(names, "o") {
		t.Fatalf("a refused command wrote files: %v", names)
	}

	wantFail(t, 2, "give -n or --delay", "seal", plain)
	wantFail(t, 2, "-n needs --alg", "seal", "-n", "1", plain)
	wantFail(t, 2, "can't be used together", "seal", "--alg", "0xFE", "-n", "1", "-d", "1s", plain)
	wantFail(t, 2, "--raw and --archive can't be used together", "seal", "--alg", "0xFE", "-n", "1", "--raw", "--archive", plain)
	wantFail(t, 2, "--archive and --lock can't be used together", "seal", "--alg", "0xFE", "-n", "1", "--archive", "--lock", lock, plain)
	wantFail(t, 2, "give --add or --delay", "extend", lock)
	wantFail(t, 2, "Usage: chainlock seal", "seal")
	wantFail(t, 2, "no such file", "info", filepath.Join(dir, "missing.lock"))
	wantFail(t, 2, "unexpected argument frob", "frob")

	// Without a .lock suffix there is no default output name.
	os.Rename(lock, filepath.Join(dir, "renamed"))
	wantFail(t, 1, "does not end in .lock", "open", "--payload", plain+".payload", filepath.Join(dir, "renamed"))

	for _, args := range [][]string{{"--help"}, {"seal", "--help"}, {"open", "-h"}} {
		if r := mustRun(t, args...); !strings.Contains(r.stdout, "Usage: chainlock") {
			t.Errorf("chainlock %v: no usage on stdout\n%s", args, r.output())
		}
	}
}

func TestWarnsTestBuild(t *testing.T) {
	dir := t.TempDir()
	plain, _ := writePlain(t, dir, "plain")
	if r := mustRun(t, "seal", "--alg", "0xFE", "-n", "0", plain); !strings.Contains(r.stderr, "warning: test build") {
		t.Fatalf("no test-build warning:\n%s", r.stderr)
	}
}
