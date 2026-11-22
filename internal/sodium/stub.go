//go:build !libsodium || !cgo

package sodium

import "errors"

// Built reports whether this build has libsodium: not this one (build with
// -tags libsodium, and cgo, for it).
const Built = false

// SaltBytes is the one salt length libsodium's Argon2id takes.
const SaltBytes = 16

// Version is "": no libsodium.
func Version() string { return "" }

// Argon2idKey reports that this build has no libsodium.
func Argon2idKey([]byte, []byte, uint32, uint32, uint32) ([]byte, error) {
	return nil, errors.New("sodium: not in this build (-tags libsodium)")
}
