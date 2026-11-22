package wick

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"wickset/alg"
)

var update = flag.Bool("update", false, "rewrite golden vectors in testdata/")

// Cheap algorithms for tests. They live only in this file, are never
// registered, and are exercised through the internal entry points, so the
// production registry stays exactly SPEC.md §3. The IDs are in the
// private-use range (0xF0–0xFF) and Parse must reject them.
var (
	testAlg32 alg.Alg = &shaAlg{id: 0xF0, name: "test-sha256", bs: 32}
	testAlg16 alg.Alg = &shaAlg{id: 0xF1, name: "test-sha256-16", bs: 16}
	testAlgs          = []alg.Alg{testAlg32, testAlg16}
)

// testAlgsBuilt reports a build with -tags wickset_testalgs, which
// registers 0xFE and 0xFF.
var _, testAlgsBuilt = alg.Lookup(0xFF)

// shaAlg is a cheap step: SHA-256 of name ‖ x, truncated to bs bytes.
type shaAlg struct {
	id   alg.ID
	name string
	bs   int
}

func (a *shaAlg) ID() alg.ID     { return a.id }
func (a *shaAlg) Name() string   { return a.name }
func (a *shaAlg) BlockSize() int { return a.bs }
func (a *shaAlg) MemBytes() int  { return 0 }

func (a *shaAlg) H(x []byte) []byte {
	h := sha256.Sum256(append([]byte(a.name), x...))
	return h[:a.bs]
}

// countingAlg wraps an Alg and counts evaluations of H.
type countingAlg struct {
	alg.Alg
	steps int
}

func (c *countingAlg) H(x []byte) []byte { c.steps++; return c.Alg.H(x) }

// detRand is a deterministic randomness source (counter-mode SHA-256).
type detRand struct {
	label string
	ctr   uint64
	buf   []byte
}

func (d *detRand) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], d.ctr)
		d.ctr++
		h := sha256.Sum256(append([]byte(d.label), c[:]...))
		d.buf = append(d.buf, h[:]...)
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

func withDetRand(t *testing.T, label string) {
	t.Helper()
	old := randSource
	randSource = &detRand{label: label}
	t.Cleanup(func() { randSource = old })
}

func secretFor(a alg.Alg, seed byte) []byte {
	s := make([]byte, a.BlockSize())
	for i := range s {
		s[i] = seed + byte(i)
	}
	return s
}

func mustCreate(t *testing.T, a alg.Alg, n int, s []byte) []byte {
	t.Helper()
	obj, err := create(t.Context(), a, n, s, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func mustParse(t *testing.T, a alg.Alg, b []byte) *Object {
	t.Helper()
	o, err := parseAs(a, b)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestRoundTrip(t *testing.T) {
	for _, a := range testAlgs {
		for _, n := range []int{0, 1, 2, 5, 17} {
			s := secretFor(a, 0x40)
			obj := mustCreate(t, a, n, s)
			if len(obj) != Size(a, n) {
				t.Fatalf("%s n=%d: size %d want %d", a.Name(), n, len(obj), Size(a, n))
			}
			o := mustParse(t, a, obj)
			if o.N != n {
				t.Fatalf("%s: parsed N=%d want %d", a.Name(), o.N, n)
			}
			got, err := Solve(t.Context(), o, nil)
			if err != nil || !bytes.Equal(got, s) {
				t.Fatalf("%s n=%d: solve = %x, %v; want %x", a.Name(), n, []byte(got), err, s)
			}
		}
	}
}

// TestNew: New draws S itself, and the object it returns hides that S.
func TestNew(t *testing.T) {
	if !testAlgsBuilt {
		t.Skip("needs a registered cheap algorithm: -tags wickset_testalgs")
	}
	obj, key, err := New(t.Context(), 0xFE, 3, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	o, err := Parse(obj)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Solve(t.Context(), o, nil); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("solve: %v", err)
	}
	if _, _, err := New(t.Context(), 0x00, 1, Opts{}); !errors.Is(err, alg.ErrUnknown) {
		t.Fatalf("alg 0x00: %v", err)
	}
}

// TestCancelMidStep: cancelling a real build stops its workers inside their
// steps, not after them: within half a step (a sync point is a twelfth of
// one). It measures its own step, so load cannot fake either.
func TestCancelMidStep(t *testing.T) {
	a, _ := alg.Lookup(alg.Argon2idShort)
	t0 := time.Now()
	a.H(make([]byte, a.BlockSize()))
	step := time.Since(t0)

	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{}, 2)
	done := make(chan error)
	go func() {
		_, _, err := New(ctx, alg.Argon2idShort, 3, Opts{Workers: 2,
			Report: func(e Event) {
				if e.Kind == Began {
					started <- struct{}{}
				}
			}})
		done <- err
	}()
	<-started
	<-started
	time.Sleep(step / 8) // both workers are mid-step
	cancelled := time.Now()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if el := time.Since(cancelled); el > step/2 && !raceEnabled {
		t.Fatalf("build returned %v after cancel, against a %v step: it waited the step out", el, step)
	}
}

// TestEvents: workers report every evaluation's start and finish, one at a
// time, by Event's rules; an iterated SHA-256 step reports partway too.
func TestEvents(t *testing.T) {
	a := testAlg32
	xs, _ := randBlocks(20, a.BlockSize())
	var events []Event
	if _, err := computeOutputs(t.Context(), a, xs, Opts{
		Workers: 3, Report: func(e Event) { events = append(events, e) },
	}); err != nil {
		t.Fatal(err)
	}
	checkEvents(t, events, len(xs))
	for _, e := range events {
		if e.Worker < 0 || e.Worker >= 3 || (e.Kind == Began && e.N != 1) {
			t.Fatalf("%+v: out of range, or a worker began more than one", e)
		}
	}

	// A real SHA-256 step reports partway, in hashes, as it goes.
	sha, _ := alg.Lookup(alg.SHA256Short)
	events = nil
	if _, err := computeOutputs(t.Context(), sha, xs[:1], Opts{Report: func(e Event) { events = append(events, e) }}); err != nil {
		t.Fatal(err)
	}
	checkEvents(t, events, 1)
	last := events[len(events)-3] // ... Partway, Finished, Idle
	if c, _ := alg.SHA256IterOf(sha); last.Kind != Partway || last.Part != c.K || last.OfParts != c.K {
		t.Fatalf("last partway %+v", last)
	}
}

// TestLayout recomputes the object from SPEC.md §2 by hand, for N = 2.
func TestLayout(t *testing.T) {
	a := testAlg32
	withDetRand(t, "layout")
	xs, _ := randBlocks(3, a.BlockSize()) // I[0..2]
	s := secretFor(a, 7)
	obj, err := build(t.Context(), a, xs, s, Opts{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	xor := func(p, q []byte) []byte { return xorInto(make([]byte, len(p)), p, q) }
	var want []byte
	want = append(want, byte(a.ID()))
	want = append(want, xor(s, a.H(xs[0]))...)
	want = append(want, xor(xs[0], a.H(xs[1]))...)
	want = append(want, xor(xs[1], a.H(xs[2]))...)
	want = append(want, xs[2]...)
	if !bytes.Equal(obj, want) {
		t.Fatalf("layout mismatch:\n got %x\nwant %x", obj, want)
	}
}

func TestN0IsOneStep(t *testing.T) {
	a := testAlg32
	s := secretFor(a, 1)
	obj := mustCreate(t, a, 0, s)
	if len(obj) != 1+2*a.BlockSize() {
		t.Fatalf("N=0 object length %d", len(obj))
	}
	counting := &countingAlg{Alg: a}
	got, err := Solve(t.Context(), mustParse(t, counting, obj), nil)
	if err != nil || !bytes.Equal(got, s) || counting.steps != 1 {
		t.Fatalf("got %x err %v steps %d", []byte(got), err, counting.steps)
	}
}

func TestSolveDoesNPlusOneSteps(t *testing.T) {
	a := testAlg32
	obj := mustCreate(t, a, 6, secretFor(a, 3))
	counting := &countingAlg{Alg: a}
	if _, err := Solve(t.Context(), mustParse(t, counting, obj), nil); err != nil {
		t.Fatal(err)
	}
	if counting.steps != 7 {
		t.Fatalf("steps = %d, want 7", counting.steps)
	}
}

func TestExtend(t *testing.T) {
	for _, a := range testAlgs {
		s := secretFor(a, 0x10)
		obj := mustCreate(t, a, 3, s)
		ext, err := extend(t.Context(), mustParse(t, a, obj), 4, Opts{})
		if err != nil {
			t.Fatal(err)
		}
		eo := mustParse(t, a, ext)
		if eo.N != 7 || len(ext) != Size(a, 7) {
			t.Fatalf("%s: N=%d len=%d", a.Name(), eo.N, len(ext))
		}
		// blocks 0..N are untouched; only I[N] (the last block) is replaced.
		if !bytes.Equal(ext[:len(obj)-a.BlockSize()], obj[:len(obj)-a.BlockSize()]) {
			t.Fatalf("%s: existing blocks changed", a.Name())
		}
		got, err := Solve(t.Context(), eo, nil)
		if err != nil || !bytes.Equal(got, s) {
			t.Fatalf("%s: extended object does not open to S", a.Name())
		}
		// extending again composes
		ext2, err := extend(t.Context(), eo, 1, Opts{})
		if err != nil {
			t.Fatal(err)
		}
		got, err = Solve(t.Context(), mustParse(t, a, ext2), nil)
		if err != nil || !bytes.Equal(got, s) {
			t.Fatalf("%s: twice-extended object does not open to S", a.Name())
		}
	}
}

func TestExtendAddsSteps(t *testing.T) {
	a := testAlg32
	obj := mustCreate(t, a, 2, secretFor(a, 9))
	ext, err := extend(t.Context(), mustParse(t, a, obj), 5, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingAlg{Alg: a}
	if _, err := Solve(t.Context(), mustParse(t, counting, ext), nil); err != nil {
		t.Fatal(err)
	}
	if counting.steps != 8 { // (2+5)+1
		t.Fatalf("steps = %d, want 8", counting.steps)
	}
}

func TestExtendRejectsBadAdd(t *testing.T) {
	a := testAlg32
	o := mustParse(t, a, mustCreate(t, a, 1, secretFor(a, 0)))
	for _, add := range []int{0, -1} {
		if _, err := extend(t.Context(), o, add, Opts{}); !errors.Is(err, ErrSteps) {
			t.Fatalf("add=%d: err %v", add, err)
		}
	}
}

func TestCreateRejectsBadArgs(t *testing.T) {
	a := testAlg32
	ctx := t.Context()
	if _, err := create(ctx, a, -1, secretFor(a, 0), Opts{}); !errors.Is(err, ErrSteps) {
		t.Fatalf("N=-1: %v", err)
	}
	if _, err := create(ctx, a, 1, make([]byte, a.BlockSize()-1), Opts{}); !errors.Is(err, ErrSecretLen) {
		t.Fatalf("short secret: %v", err)
	}
	if _, _, err := New(ctx, 0x00, 1, Opts{}); !errors.Is(err, alg.ErrUnknown) {
		t.Fatalf("alg 0x00: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	good := func(id byte, blocks int) []byte {
		return append([]byte{id}, make([]byte, blocks*32)...)
	}
	// Under -tags wickset_testalgs, 0xFF is a registered end-to-end
	// algorithm (B = 16), so good(0xFF, 3) is a valid 6-block object. 0xF0 is
	// rejected in every build.
	var wantFF error = alg.ErrUnknown
	if testAlgsBuilt {
		wantFF = nil
	}
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrFormat},
		{"id 0x00", good(0x00, 3), alg.ErrUnknown},
		{"unassigned 0x05", good(0x05, 3), alg.ErrUnknown},
		{"unassigned 0xEF", good(0xEF, 3), alg.ErrUnknown},
		{"private use 0xF0", good(0xF0, 3), alg.ErrUnknown},
		{"private use 0xFF", good(0xFF, 3), wantFF},
		{"id only", []byte{0x01}, ErrFormat},
		{"one block", good(0x01, 1), ErrFormat},
		{"not a multiple", append(good(0x01, 3), 0), ErrFormat},
		{"short by one", good(0x01, 3)[:len(good(0x01, 3))-1], ErrFormat},
	}
	for _, c := range cases {
		if _, err := Parse(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.want)
		}
	}
	// the smallest valid object parses as N = 0
	o, err := Parse(good(0x01, 2))
	if err != nil || o.N != 0 {
		t.Fatalf("minimal object: %v %+v", err, o)
	}
	if o, err = Parse(good(0x02, 5)); err != nil || o.N != 3 {
		t.Fatalf("N derivation: %v %+v", err, o)
	}
}

func TestTamperChangesS(t *testing.T) {
	a := testAlg32
	s := secretFor(a, 0x22)
	obj := mustCreate(t, a, 4, s)
	for _, pos := range []int{1, 1 + a.BlockSize(), 1 + 3*a.BlockSize(), len(obj) - 1} {
		bad := append([]byte(nil), obj...)
		bad[pos] ^= 1
		got, err := Solve(t.Context(), mustParse(t, a, bad), nil)
		if err != nil {
			t.Fatal(err) // the format has no check: success is only payload auth
		}
		if bytes.Equal(got, s) {
			t.Fatalf("flip at %d still opened to S", pos)
		}
	}
}

func TestAlgByteSelectsStep(t *testing.T) {
	// parseAs insists the object's ID byte is the algorithm it was given.
	a := testAlg32
	obj := mustCreate(t, a, 1, secretFor(a, 0))
	if _, err := parseAs(testAlg16, obj); !errors.Is(err, ErrFormat) {
		t.Fatalf("err %v", err)
	}
}

func TestCancel(t *testing.T) {
	a := testAlg32
	obj := mustCreate(t, a, 5, secretFor(a, 0))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Solve(ctx, mustParse(t, a, obj), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

// TestSolveEvents: a solve is one worker, taking its steps from 0 in order.
func TestSolveEvents(t *testing.T) {
	a := testAlg32
	obj := mustCreate(t, a, 3, secretFor(a, 0))
	var events []Event
	if _, err := Solve(t.Context(), mustParse(t, a, obj), func(e Event) { events = append(events, e) }); err != nil {
		t.Fatal(err)
	}
	checkEvents(t, events, 4)
	var order []int
	for _, e := range events {
		if e.Kind == Began {
			order = append(order, e.First)
		}
	}
	if fmt.Sprint(order) != "[0 1 2 3]" {
		t.Fatalf("began %v", order)
	}
}

// ---- golden vectors (real algorithms only) ----

type vector struct {
	Alg    string   `json:"alg"`
	N      int      `json:"n"`
	Secret string   `json:"secret"`
	I      []string `json:"i"` // I[0..N]
	Object string   `json:"object"`
}

var vectorSpecs = []struct {
	id alg.ID
	n  int
}{
	{alg.Argon2idShort, 0}, {alg.Argon2idShort, 2}, {alg.Argon2idLong, 0},
	{alg.SHA256Short, 0}, {alg.SHA256Short, 2}, {alg.SHA256Long, 0},
}

// long reports whether id's step takes seconds, for tests to skip with -short.
func long(id alg.ID) bool { return id == alg.Argon2idLong || id == alg.SHA256Long }

// alg.ID has a String method, so format it as byte(id) wherever %x means the
// raw id.
func vectorPath(id alg.ID, n int) string {
	return filepath.Join("testdata", fmt.Sprintf("vector-%02x-n%d.json", byte(id), n))
}

// memoAlg caches H by input, so a test can evaluate each real step once and
// share it between build and solve. Steps are deterministic, so this loses
// nothing: a wrong value I[j] in solve misses the cache and still yields a
// wrong S.
type memoAlg struct {
	alg.Alg
	mu   sync.Mutex
	outs map[string][]byte
}

func newMemoAlg(a alg.Alg) *memoAlg { return &memoAlg{Alg: a, outs: map[string][]byte{}} }

func (m *memoAlg) H(x []byte) []byte {
	m.mu.Lock()
	out, ok := m.outs[string(x)]
	m.mu.Unlock()
	if !ok {
		out = m.Alg.H(x)
		m.mu.Lock()
		m.outs[string(x)] = out
		m.mu.Unlock()
	}
	return out
}

// realParallel runs a real-algorithm test alongside the others. Not while
// rewriting vectors: -update swaps the package-wide randSource.
func realParallel(t *testing.T) {
	if !*update {
		t.Parallel()
	}
}

func TestVectors(t *testing.T) {
	realParallel(t)
	for _, vs := range vectorSpecs {
		t.Run(fmt.Sprintf("alg%02x-n%d", byte(vs.id), vs.n), func(t *testing.T) {
			if testing.Short() && long(vs.id) {
				t.Skip("long step (~10 s) skipped with -short")
			}
			realParallel(t)
			start := time.Now()
			reg, _ := alg.Lookup(vs.id)
			a := newMemoAlg(reg)
			path := vectorPath(vs.id, vs.n)
			if *update {
				withDetRand(t, path)
				s, _ := randBlocks(1, a.BlockSize())
				xs, _ := randBlocks(vs.n+1, a.BlockSize())
				obj, err := build(t.Context(), a, xs, s[0], Opts{})
				if err != nil {
					t.Fatal(err)
				}
				v := vector{Alg: fmt.Sprintf("%#02x", byte(vs.id)), N: vs.n, Secret: hex.EncodeToString(s[0]), Object: hex.EncodeToString(obj)}
				for _, x := range xs {
					v.I = append(v.I, hex.EncodeToString(x))
				}
				b, _ := json.MarshalIndent(v, "", "  ")
				if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var v vector
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			secret, _ := hex.DecodeString(v.Secret)
			want, _ := hex.DecodeString(v.Object)
			var xs [][]byte
			for _, h := range v.I {
				x, _ := hex.DecodeString(h)
				xs = append(xs, x)
			}
			got, err := build(t.Context(), a, xs, secret, Opts{})
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("create from I does not reproduce the vector object (%v)", err)
			}
			s, err := Solve(t.Context(), mustParse(t, a, want), nil)
			if err != nil || !bytes.Equal(s, secret) {
				t.Fatalf("solve: %x %v", []byte(s), err)
			}
			t.Logf("%v N=%d: build + solve with %d real evaluations of H in %v",
				vs.id, vs.n, len(a.outs), time.Since(start).Round(time.Millisecond))
		})
	}
}
