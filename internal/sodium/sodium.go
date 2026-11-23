//go:build libsodium && cgo

// Package sodium is libsodium's Argon2id, for builds that want it (-tags
// libsodium, and cgo): it runs a step ~1.4× faster than x/crypto's pure Go
// on arm64, so a wick opens as fast as a capable opener's would. Elsewhere it
// reports itself absent (stub.go), and x/crypto's does the work.
//
// libsodium takes salts of exactly 16 bytes; wickset's are (SPEC.md §3.1).
//
// It links the installed shared library (link.go). With the libsodium_static
// tag as well, it links nothing itself, and the build names the archive:
//
//	CGO_LDFLAGS=/opt/homebrew/lib/libsodium.a go build -tags "libsodium libsodium_static" ./cmd/wickset
//
// so a release binary runs where libsodium is not installed.
package sodium

/*
#cgo darwin CFLAGS: -I/opt/homebrew/include -I/usr/local/include
#include <sodium.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Built reports whether this build has libsodium.
const Built = true

// SaltBytes is the one salt length libsodium's Argon2id takes.
const SaltBytes = C.crypto_pwhash_SALTBYTES

var ready = C.sodium_init() >= 0

// Version is libsodium's, such as "1.0.22".
func Version() string { return C.GoString(C.sodium_version_string()) }

// Argon2idKey is Argon2id v1.3 of input with salt (SaltBytes long), passes
// passes over memKiB KiB, one lane, keyLen bytes out: x/crypto's IDKey with
// threads = 1. It cannot be stopped once begun.
func Argon2idKey(input, salt []byte, passes, memKiB, keyLen uint32) ([]byte, error) {
	switch {
	case !ready:
		return nil, errors.New("sodium: libsodium did not initialize")
	case len(salt) != SaltBytes:
		return nil, errors.New("sodium: libsodium takes 16-byte salts only")
	}
	out := make([]byte, keyLen)
	in := unsafe.Pointer(unsafe.SliceData(input))
	if C.crypto_pwhash((*C.uchar)(&out[0]), C.ulonglong(keyLen), (*C.char)(in), C.ulonglong(len(input)),
		(*C.uchar)(&salt[0]), C.ulonglong(passes), C.size_t(memKiB)<<10, C.crypto_pwhash_ALG_ARGON2ID13) != 0 {
		return nil, errors.New("sodium: Argon2id failed (out of memory?)")
	}
	return out, nil
}
