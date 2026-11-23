package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zblach/wickset/alg"
)

// zeroObject is a well-formed 0x01 wick with N = 1. Loading it evaluates no
// step, so it costs nothing.
func zeroObject() []byte {
	return append([]byte{byte(alg.Argon2idShort)}, make([]byte, 3*32)...)
}

// TestPair: either file of a pair names it, and the flags override the
// names; a payload with no wick to burn is refused.
func TestPair(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "x")
	if _, err := WriteSealed(file, FormFile, "", "", zeroObject(), []byte("\x00WS-PAYL")); err != nil { // a payload's magic: enough to be told apart

		t.Fatal(err)
	}
	w, p := file+WickSuffix, file+PayloadSuffix
	other := filepath.Join(dir, "other")
	for _, c := range []struct {
		path, wick, payload string
		want                [2]string
		err                 string
	}{
		{path: w, want: [2]string{w, ""}},
		{path: p, want: [2]string{w, p}},
		{path: w, payload: other, want: [2]string{w, other}},
		{path: p, wick: w, want: [2]string{w, p}},
		{path: w, wick: other, err: "drop --wick"},
		{path: p, payload: other, err: "drop --payload"},
	} {
		gw, gp, err := Pair(c.path, c.wick, c.payload)
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%+v: %v, want %q", c, err, c.err)
		case c.err == "" && (err != nil || [2]string{gw, gp} != c.want):
			t.Errorf("%+v: %q %q %v, want %q", c, gw, gp, err, c.want)
		}
	}
	os.Remove(w)
	if _, _, err := Pair(p, "", ""); err == nil || !strings.Contains(err.Error(), "give it with --wick") {
		t.Errorf("a payload without its wick: %v", err)
	}
	if err := NotPayload(p, "extend"); err == nil || !strings.Contains(err.Error(), "x.wick") {
		t.Errorf("NotPayload: %v", err)
	}
}

// TestWriteSealed: each form loads back as itself, beside its payload.
func TestWriteSealed(t *testing.T) {
	obj, payload := zeroObject(), []byte("payload bytes")
	for _, f := range []Form{FormFile, FormRaw} {
		file := filepath.Join(t.TempDir(), "x")
		w, err := WriteSealed(file, f, "", "", obj, payload)
		if err != nil {
			t.Fatal(err)
		}
		if want := file + WickSuffix; w[0].Path != want {
			t.Fatalf("%v: wrote %s, want %s", f, w[0].Path, want)
		}
		l, err := Load(w[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		got, where, err := l.PayloadOf(w[0].Path, "")
		if err != nil || l.Form != f || string(got) != string(payload) {
			t.Fatalf("%v: loaded form %v, payload %q from %s, err %v", f, l.Form, got, where, err)
		}
	}
}
