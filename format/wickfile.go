// Package format is wickset's two file formats (CONTAINER.md): the wick
// file, which wraps a wick with a digest, and the payload file, the
// encrypted data bound to its wick. Naming is internal/store's.
package format

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	ErrFormat   = errors.New("wickset: malformed file")
	ErrCorrupt  = errors.New("wickset: file is corrupt")
	ErrMismatch = errors.New("wickset: payload belongs to a different wick")
	ErrAuth     = errors.New("wickset: payload authentication failed")
)

// Both magics start with 0x00, which SPEC.md §3 makes an invalid ALG_ID, so
// neither file can be mistaken for a raw wick.
var (
	magicWick    = []byte("\x00WS-WICK")
	magicPayload = []byte("\x00WS-PAYL")
)

const (
	version   = 1
	digestLen = sha256.Size
	// wickFileHeader is MAGIC_WICK ‖ VERSION ‖ DIGEST (CONTAINER.md §2).
	wickFileHeader = 8 + 1 + digestLen
)

// EncodeWickFile wraps a raw wick in a wick file: magic, version and a
// SHA-256 of the wick, then the wick verbatim (CONTAINER.md §2).
func EncodeWickFile(obj []byte) []byte {
	d := sha256.Sum256(obj)
	out := make([]byte, 0, wickFileHeader+len(obj))
	out = append(out, magicWick...)
	out = append(out, version)
	out = append(out, d[:]...)
	return append(out, obj...)
}

// DecodeWick returns the raw wick in b, which is either a wick file or a raw
// wick (CONTAINER.md §1). A wick file's digest is verified, so damage is
// reported as ErrCorrupt before any evaluation of H; wrapped reports which
// form b was. A raw wick is returned as is: wick.Parse validates it.
func DecodeWick(b []byte) (obj []byte, wrapped bool, err error) {
	if len(b) == 0 || b[0] != 0x00 {
		return b, false, nil
	}
	switch {
	case bytes.HasPrefix(b, magicPayload):
		return nil, false, fmt.Errorf("%w: this is a payload file, not a wick", ErrFormat)
	case !bytes.HasPrefix(b, magicWick):
		return nil, false, fmt.Errorf("%w: unrecognized container", ErrFormat)
	case len(b) < wickFileHeader:
		return nil, false, fmt.Errorf("%w: truncated wick file header", ErrFormat)
	case b[8] != version:
		return nil, false, fmt.Errorf("%w: wick file version %d (this build reads %d)", ErrFormat, b[8], version)
	}
	obj = b[wickFileHeader:]
	if d := sha256.Sum256(obj); !bytes.Equal(d[:], b[9:wickFileHeader]) {
		return nil, true, fmt.Errorf("%w: wick file digest mismatch", ErrCorrupt)
	}
	return obj, true, nil
}
