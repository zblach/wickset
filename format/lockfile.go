// Package format is chainlock's two file formats (CONTAINER.md): the lock
// file, which wraps a lock object with a digest, and the payload file, the
// encrypted data bound to its lock. Naming and archives are internal/store's.
package format

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	ErrFormat   = errors.New("chainlock: malformed file")
	ErrCorrupt  = errors.New("chainlock: file is corrupt")
	ErrMismatch = errors.New("chainlock: payload belongs to a different lock")
	ErrAuth     = errors.New("chainlock: payload authentication failed")
)

// Both magics start with 0x00, which SPEC.md §3 makes an invalid ALG_ID, so
// neither file can be mistaken for a raw object.
var (
	magicLock    = []byte("\x00CL-LOCK")
	magicPayload = []byte("\x00CL-PAYL")
)

const (
	version   = 1
	digestLen = sha256.Size
	// lockFileHeader is MAGIC_LOCK ‖ VERSION ‖ DIGEST (CONTAINER.md §2).
	lockFileHeader = 8 + 1 + digestLen
)

// EncodeLockFile wraps a lock object in a lock file: magic, version and a
// SHA-256 of the object, then the object verbatim (CONTAINER.md §2).
func EncodeLockFile(obj []byte) []byte {
	d := sha256.Sum256(obj)
	out := make([]byte, 0, lockFileHeader+len(obj))
	out = append(out, magicLock...)
	out = append(out, version)
	out = append(out, d[:]...)
	return append(out, obj...)
}

// DecodeLock returns the lock object in b, which is either a lock file or a
// raw object (CONTAINER.md §1). A lock file's digest is verified, so damage
// is reported as ErrCorrupt before any evaluation of H; wrapped reports
// which form b was. A raw object is returned as is: chain.Parse validates it.
func DecodeLock(b []byte) (obj []byte, wrapped bool, err error) {
	if len(b) == 0 || b[0] != 0x00 {
		return b, false, nil
	}
	switch {
	case bytes.HasPrefix(b, magicPayload):
		return nil, false, fmt.Errorf("%w: this is a payload file, not a lock", ErrFormat)
	case !bytes.HasPrefix(b, magicLock):
		return nil, false, fmt.Errorf("%w: unrecognized container", ErrFormat)
	case len(b) < lockFileHeader:
		return nil, false, fmt.Errorf("%w: truncated lock file header", ErrFormat)
	case b[8] != version:
		return nil, false, fmt.Errorf("%w: lock file version %d (this build reads %d)", ErrFormat, b[8], version)
	}
	obj = b[lockFileHeader:]
	if d := sha256.Sum256(obj); !bytes.Equal(d[:], b[9:lockFileHeader]) {
		return nil, true, fmt.Errorf("%w: lock file digest mismatch", ErrCorrupt)
	}
	return obj, true, nil
}
