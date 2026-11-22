// Package store reads and writes wickset's on-disk forms (CONTAINER.md):
// wick files, raw wicks, payloads and keys, and the naming
// convention that pairs them. It never prints; callers report.
package store

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"wickset/format"
	"wickset/wick"
)

// File names pair by convention: seal writes FILE.wick and FILE.payload,
// and open reads them back into FILE.
const (
	WickSuffix    = ".wick"
	PayloadSuffix = ".payload"
)

// PayloadFor is the payload that pairs with wickPath by name.
func PayloadFor(wickPath string) string {
	return strings.TrimSuffix(wickPath, WickSuffix) + PayloadSuffix
}

// IsPayloadFile reports whether path holds a payload rather than a wick.
func IsPayloadFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	return format.IsPayload(head[:n]), nil
}

// Pair names a wick and its payload from either file of the pair. path is a
// wick in any form, or a payload; wickPath and payloadPath, where given,
// override the names a pair takes by convention, FILE.wick and FILE.payload.
// It returns the wick's path, and the payload's for PayloadOf: "" for
// FILE.payload beside the wick. A payload whose wick is not
// there is refused, as there is nothing to burn.
func Pair(path, wickPath, payloadPath string) (wick, payload string, err error) {
	isPayload, err := IsPayloadFile(path)
	if err != nil {
		return "", "", err
	}
	if !isPayload {
		if wickPath != "" && wickPath != path {
			return "", "", fmt.Errorf("%s is already a wick; drop --wick", path)
		}
		return path, payloadPath, nil
	}
	if payloadPath != "" && payloadPath != path {
		return "", "", fmt.Errorf("%s is already a payload; drop --payload", path)
	}
	if wickPath != "" {
		return wickPath, path, nil
	}
	if !strings.HasSuffix(path, PayloadSuffix) {
		return "", "", fmt.Errorf("%s does not end in %s, so names no wick; give --wick", path, PayloadSuffix)
	}
	w := strings.TrimSuffix(path, PayloadSuffix) + WickSuffix
	if _, err := os.Stat(w); err != nil {
		return "", "", fmt.Errorf("%s: its wick %s is not there; give it with --wick", path, w)
	}
	return w, path, nil
}

// NotPayload refuses a payload where only a wick will do, as for extend:
// the payload never changes.
func NotPayload(path, what string) error {
	isPayload, err := IsPayloadFile(path)
	if err == nil && isPayload {
		return fmt.Errorf("%s is a payload; %s works on its wick, %s", path, what,
			strings.TrimSuffix(path, PayloadSuffix)+WickSuffix)
	}
	return err
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
	FormFile Form = iota // wick file: header, digest, wick
	FormRaw              // the bare SPEC.md wick, no digest
)

func (f Form) String() string {
	return [...]string{
		FormFile: "wick file v1, digest ok",
		FormRaw:  "raw wick (no digest)",
	}[f]
}

// Wick is a wick read from disk, in any form.
type Wick struct {
	Form   Form
	Obj    []byte // the SPEC.md wick
	Parsed *wick.Object
}

// Load reads a wick in any form, verifying its digest if it has one, so
// damage is reported before any evaluation of H.
func Load(path string) (*Wick, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l := &Wick{Form: FormRaw}
	obj, wrapped, err := format.DecodeWick(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if wrapped {
		l.Form = FormFile
	}
	if l.Parsed, err = wick.Parse(obj); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	l.Obj = obj
	return l, nil
}

// Save writes obj to path in l's form.
func (l *Wick) Save(path string, obj []byte) error {
	if l.Form == FormRaw {
		return WriteFile(path, obj)
	}
	return WriteFile(path, format.EncodeWickFile(obj))
}

// PayloadOf returns the payload that goes with l, read from wickPath, and
// where it came from: the file at override, or FILE.payload beside it.
func (l *Wick) PayloadOf(wickPath, override string) (payload []byte, where string, err error) {
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
	return payload, WickSuffix, nil
}

// Written is a file a write produced.
type Written struct {
	Path string
	Size int
}

// SealedPaths is where WriteSealed writes for the same arguments: the wick,
// then the payload.
func SealedPaths(file, wickPath, payloadPath string) []string {
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
// file, in form f, at wickPath and payloadPath (default FILE.wick and
// FILE.payload).
func WriteSealed(file string, f Form, wickPath, payloadPath string, obj, payload []byte) ([]Written, error) {
	paths := SealedPaths(file, wickPath, payloadPath)
	files := [][]byte{format.EncodeWickFile(obj), payload}
	if f == FormRaw {
		files[0] = obj
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

// CheckOutput reports why path cannot take an output, so that a run fails
// before its work rather than after it: path is a directory, or the
// directory it would go in is missing or refuses a new file (tried, as
// WriteFile will). An existing device or pipe, such as /dev/null, is fine:
// WriteFile writes it directly.
func CheckOutput(path string) error {
	if fi, err := os.Stat(path); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".wickset-check-*")
	if err != nil {
		return fmt.Errorf("cannot write %s: %w", path, unwrapPath(err))
	}
	f.Close()
	return os.Remove(f.Name())
}

// unwrapPath drops a PathError's own path, a temp file's name that would
// only confuse.
func unwrapPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// WriteFile atomically replaces path with data, mode 0600. The temp file
// lives beside path so the rename stays on one filesystem, and is removed on
// any failure. An existing device or pipe, such as /dev/null, is written
// directly: nothing of it persists to be left half-written.
func WriteFile(path string, data []byte) (err error) {
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() && !fi.IsDir() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return errors.Join(err, f.Close())
	}
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
