package chain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrKey reports text that is not a key in Encode's form.
var ErrKey = errors.New("chainlock: malformed key")

// Key is a lock's secret S, which is also its payload's key. Anyone holding it
// opens the payload at once, without solving, however far the lock has since
// been extended. New draws it and Solve recovers it; nothing here takes a
// caller's.
//
// A Key formats as a redaction, so an accidental %v or log line never shows
// it. Encode is the one way to get its text (CONTAINER.md §5).
type Key []byte

const (
	keyPrefix   = "chainlock-key-v1:"
	keyRedacted = "chain.Key(redacted)"
)

func (Key) String() string   { return keyRedacted }
func (Key) GoString() string { return keyRedacted }

// Format prints the redaction for every verb, %x included.
func (Key) Format(f fmt.State, _ rune) { io.WriteString(f, keyRedacted) }

// Encode returns the key's text form, chainlock-key-v1: followed by its bytes
// in unpadded URL-safe base64. ParseKey reads it back.
func (k Key) Encode() string {
	return keyPrefix + base64.RawURLEncoding.EncodeToString(k)
}

// ParseKey reads a key in Encode's text form. Surrounding whitespace, such as
// the newline at the end of a key file, is ignored.
func ParseKey(text string) (Key, error) {
	text = strings.TrimSpace(text)
	enc, ok := strings.CutPrefix(text, keyPrefix)
	if !ok {
		return nil, fmt.Errorf("%w: missing %q prefix", ErrKey, keyPrefix)
	}
	k, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	switch len(k) {
	case 16, 24, 32: // the AES key sizes; every defined algorithm has B = 32
	default:
		return nil, fmt.Errorf("%w: %d bytes", ErrKey, len(k))
	}
	return k, nil
}
