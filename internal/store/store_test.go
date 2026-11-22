package store

import (
	"errors"
	"path/filepath"
	"testing"

	"wickset/alg"
	"wickset/format"
)

// zeroObject is a well-formed 0x01 wick with N = 1. Loading it evaluates no
// step, so it costs nothing.
func zeroObject() []byte {
	return append([]byte{byte(alg.Argon2idShort)}, make([]byte, 3*32)...)
}

func TestArchiveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x"+ArchiveSuffix)
	obj, payload := zeroObject(), []byte("payload bytes")
	if err := writeArchive(path, "x", format.EncodeWickFile(obj), payload); err != nil {
		t.Fatal(err)
	}
	l, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if l.Form != FormArchive || l.Name != "x" || string(l.Payload) != string(payload) || l.Parsed.N != 1 {
		t.Fatalf("loaded %+v", l)
	}
}

// TestArchiveRejectsRawWick: an archive's wick member must be a wick file
// (CONTAINER.md §4), not a raw wick without a digest.
func TestArchiveRejectsRawWick(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x"+ArchiveSuffix)
	if err := writeArchive(path, "x", zeroObject(), []byte("p")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrArchive) {
		t.Fatalf("err %v, want ErrArchive", err)
	}
}

// TestWriteSealed: each form loads back as itself, beside its payload.
func TestWriteSealed(t *testing.T) {
	obj, payload := zeroObject(), []byte("payload bytes")
	for _, f := range []Form{FormFile, FormRaw, FormArchive} {
		file := filepath.Join(t.TempDir(), "x")
		w, err := WriteSealed(file, f, "", "", obj, payload)
		if err != nil {
			t.Fatal(err)
		}
		if want := file + f.Suffix(); w[0].Path != want {
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
