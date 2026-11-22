// Package store reads and writes wickset's on-disk forms (CONTAINER.md):
// wick files, raw wicks, archives, payloads and keys, and the naming
// convention that pairs them. It never prints; callers report.
package store

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wickset/format"
	"wickset/wick"
)

// File names pair by convention: seal writes FILE.wick and FILE.payload (or
// FILE.wick.tar holding both), and open reads them back into FILE.
const (
	WickSuffix    = ".wick"
	PayloadSuffix = ".payload"
	ArchiveSuffix = ".wick.tar"
)

// PayloadFor is the payload that pairs with wickPath by name.
func PayloadFor(wickPath string) string {
	return strings.TrimSuffix(wickPath, WickSuffix) + PayloadSuffix
}

// OutputFor is where open and bypass write the plaintext: out if given, else
// path without suffix, which must not exist yet. It is decided before any
// solving, so a name clash never costs the delay.
func OutputFor(out, path, suffix string) (string, error) {
	if out != "" {
		return out, nil
	}
	if !strings.HasSuffix(path, suffix) {
		return "", fmt.Errorf("%s does not end in %s; give --out", path, suffix)
	}
	out = strings.TrimSuffix(path, suffix)
	if _, err := os.Stat(out); err == nil {
		return "", fmt.Errorf("%s already exists; give --out to choose where the plaintext goes", out)
	}
	return out, nil
}

// Form is how a wick is stored on disk (CONTAINER.md).
type Form int

const (
	FormFile    Form = iota // wick file: header, digest, wick
	FormRaw                 // the bare SPEC.md wick, no digest
	FormArchive             // tar of a wick file and its payload
)

func (f Form) String() string {
	return [...]string{
		FormFile:    "wick file v1, digest ok",
		FormRaw:     "raw wick (no digest)",
		FormArchive: "archive v1, wick digest ok",
	}[f]
}

// Suffix is the conventional file name suffix for f.
func (f Form) Suffix() string {
	if f == FormArchive {
		return ArchiveSuffix
	}
	return WickSuffix
}

// Wick is a wick read from disk, in any form.
type Wick struct {
	Form    Form
	Obj     []byte // the SPEC.md wick
	Parsed  *wick.Object
	Name    string // archive only: NAME of its NAME.wick and NAME.payload
	Payload []byte // archive only
}

// Load reads a wick in any form, verifying its digest if it has one, so
// damage is reported before any evaluation of H.
func Load(path string) (*Wick, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l := &Wick{Form: FormRaw}
	wickBytes := b
	if isArchive(b) {
		l.Form = FormArchive
		if l.Name, wickBytes, l.Payload, err = readArchive(b); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	obj, wrapped, err := format.DecodeWick(wickBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case l.Form == FormArchive && !wrapped:
		// CONTAINER.md §4: an archive's wick member is a wick file, with a digest.
		return nil, fmt.Errorf("%s: %w: its wick member has no digest", path, ErrArchive)
	case wrapped && l.Form == FormRaw:
		l.Form = FormFile
	}
	if l.Parsed, err = wick.Parse(obj); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	l.Obj = obj
	return l, nil
}

// Save writes obj to path in l's form. An archive keeps its payload.
func (l *Wick) Save(path string, obj []byte) error {
	switch l.Form {
	case FormRaw:
		return WriteFile(path, obj)
	case FormArchive:
		return writeArchive(path, l.Name, format.EncodeWickFile(obj), l.Payload)
	}
	return WriteFile(path, format.EncodeWickFile(obj))
}

// PayloadOf returns the payload that goes with l, read from wickPath, and
// where it came from: the archive's own, or the file at override, or
// FILE.payload beside it.
func (l *Wick) PayloadOf(wickPath, override string) (payload []byte, where string, err error) {
	if l.Form == FormArchive {
		if override != "" {
			return nil, "", errors.New("an archive holds its own payload; drop --payload")
		}
		return l.Payload, "in archive", nil
	}
	where = cmp.Or(override, PayloadFor(wickPath))
	payload, err = os.ReadFile(where)
	return payload, where, err
}

// LoadPayload reads the payload at path, or, if path is a wick, the payload
// that goes with it (at override if given), checking that the two pair.
// suffix is what OutputFor strips from path to name the plaintext.
func LoadPayload(path, override string) (payload []byte, suffix string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	if format.IsPayload(b) {
		if override != "" {
			return nil, "", fmt.Errorf("%s is already a payload; drop --payload", path)
		}
		return b, PayloadSuffix, nil
	}
	l, err := Load(path)
	if err != nil {
		return nil, "", err
	}
	if payload, _, err = l.PayloadOf(path, override); err != nil {
		return nil, "", err
	}
	if err := format.CheckPayload(l.Parsed, payload); err != nil {
		return nil, "", err
	}
	return payload, l.Form.Suffix(), nil
}

// Written is a file a write produced.
type Written struct {
	Path string
	Size int
}

// SealedPaths is where WriteSealed writes for the same arguments: the
// archive, or the wick and then the payload.
func SealedPaths(file string, f Form, wickPath, payloadPath string) []string {
	if f == FormArchive {
		return []string{file + ArchiveSuffix}
	}
	return []string{cmp.Or(wickPath, file+WickSuffix), cmp.Or(payloadPath, file+PayloadSuffix)}
}

// Absent refuses each path that already exists: what it would replace may
// be the only copy of an earlier wick, or of the key to one.
func Absent(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s already exists, and is not replaced; move it away or choose another name", p)
		}
	}
	return nil
}

// WriteSealed stores a new wick and its payload, sealed from plaintext
// file, in form f: FILE.wick.tar, or the pair at wickPath and payloadPath
// (default FILE.wick and FILE.payload).
func WriteSealed(file string, f Form, wickPath, payloadPath string, obj, payload []byte) ([]Written, error) {
	paths := SealedPaths(file, f, wickPath, payloadPath)
	var files [][]byte
	switch f {
	case FormArchive:
		data, err := archive(filepath.Base(file), format.EncodeWickFile(obj), payload)
		if err != nil {
			return nil, err
		}
		files = [][]byte{data}
	case FormRaw:
		files = [][]byte{obj, payload}
	default:
		files = [][]byte{format.EncodeWickFile(obj), payload}
	}
	var w []Written
	for i, data := range files {
		if err := WriteFile(paths[i], data); err != nil {
			return nil, err
		}
		w = append(w, Written{paths[i], len(data)})
	}
	return w, nil
}

// WriteFile atomically replaces path with data, mode 0600. The temp file
// lives beside path so the rename stays on one filesystem, and is removed on
// any failure.
func WriteFile(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
