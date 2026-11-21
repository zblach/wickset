// Package store reads and writes chainlock's on-disk forms (CONTAINER.md):
// lock files, raw objects, archives, payloads and keys, and the naming
// convention that pairs them. It never prints; callers report.
package store

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"chainlock/chain"
	"chainlock/format"
)

// File names pair by convention: seal writes FILE.lock and FILE.payload (or
// FILE.chainlock.tar holding both), and open reads them back into FILE.
const (
	LockSuffix    = ".lock"
	PayloadSuffix = ".payload"
	ArchiveSuffix = ".chainlock.tar"
)

// PayloadFor is the payload that pairs with lockPath by name.
func PayloadFor(lockPath string) string {
	return strings.TrimSuffix(lockPath, LockSuffix) + PayloadSuffix
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

// Form is how a lock is stored on disk (CONTAINER.md).
type Form int

const (
	FormFile    Form = iota // lock file: header, digest, object
	FormRaw                 // the bare SPEC.md object, no digest
	FormArchive             // tar of a lock file and its payload
)

func (f Form) String() string {
	return [...]string{
		FormFile:    "lock file v1, digest ok",
		FormRaw:     "raw object (no digest)",
		FormArchive: "archive v1, lock digest ok",
	}[f]
}

// Suffix is the conventional file name suffix for f.
func (f Form) Suffix() string {
	if f == FormArchive {
		return ArchiveSuffix
	}
	return LockSuffix
}

// Lock is a lock read from disk, in any form.
type Lock struct {
	Form    Form
	Obj     []byte // the SPEC.md object
	Parsed  *chain.Object
	Name    string // archive only: NAME of its NAME.lock and NAME.payload
	Payload []byte // archive only
}

// Load reads a lock in any form, verifying its digest if it has one, so
// damage is reported before any evaluation of H.
func Load(path string) (*Lock, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l := &Lock{Form: FormRaw}
	lockBytes := b
	if isArchive(b) {
		l.Form = FormArchive
		if l.Name, lockBytes, l.Payload, err = readArchive(b); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	obj, wrapped, err := format.DecodeLock(lockBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case l.Form == FormArchive && !wrapped:
		// CONTAINER.md §4: an archive's lock member is a lock file, with a digest.
		return nil, fmt.Errorf("%s: %w: its lock member has no digest", path, ErrArchive)
	case wrapped && l.Form == FormRaw:
		l.Form = FormFile
	}
	if l.Parsed, err = chain.Parse(obj); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	l.Obj = obj
	return l, nil
}

// Save writes obj to path in l's form. An archive keeps its payload.
func (l *Lock) Save(path string, obj []byte) error {
	switch l.Form {
	case FormRaw:
		return WriteFile(path, obj)
	case FormArchive:
		return writeArchive(path, l.Name, format.EncodeLockFile(obj), l.Payload)
	}
	return WriteFile(path, format.EncodeLockFile(obj))
}

// PayloadOf returns the payload that goes with l, read from lockPath, and
// where it came from: the archive's own, or the file at override, or
// FILE.payload beside it.
func (l *Lock) PayloadOf(lockPath, override string) (payload []byte, where string, err error) {
	if l.Form == FormArchive {
		if override != "" {
			return nil, "", errors.New("an archive holds its own payload; drop --payload")
		}
		return l.Payload, "in archive", nil
	}
	where = cmp.Or(override, PayloadFor(lockPath))
	payload, err = os.ReadFile(where)
	return payload, where, err
}

// LoadPayload reads the payload at path, or, if path is a lock, the payload
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
// archive, or the lock and then the payload.
func SealedPaths(file string, f Form, lockPath, payloadPath string) []string {
	if f == FormArchive {
		return []string{file + ArchiveSuffix}
	}
	return []string{cmp.Or(lockPath, file+LockSuffix), cmp.Or(payloadPath, file+PayloadSuffix)}
}

// Absent refuses each path that already exists: what it would replace may
// be the only copy of an earlier lock, or of the key to one.
func Absent(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s already exists, and is not replaced; move it away or choose another name", p)
		}
	}
	return nil
}

// WriteSealed stores a new lock object and its payload, sealed from
// plaintext file, in form f: FILE.chainlock.tar, or the pair at lockPath and
// payloadPath (default FILE.lock and FILE.payload).
func WriteSealed(file string, f Form, lockPath, payloadPath string, obj, payload []byte) ([]Written, error) {
	paths := SealedPaths(file, f, lockPath, payloadPath)
	var files [][]byte
	switch f {
	case FormArchive:
		data, err := archive(filepath.Base(file), format.EncodeLockFile(obj), payload)
		if err != nil {
			return nil, err
		}
		files = [][]byte{data}
	case FormRaw:
		files = [][]byte{obj, payload}
	default:
		files = [][]byte{format.EncodeLockFile(obj), payload}
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
