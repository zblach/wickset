// Package sha256iter hashes a 32-byte value with SHA-256 many times over, as
// fast as one core can: the step of wickset's iterated SHA-256 algorithms.
//
// Each hash is of the 32 bytes before it, one padded block, one compression.
// Through crypto/sha256's Sum256, every call pays for padding, copying and
// finishing a digest, and runs at about half the compression rate. Here the
// block is padded once and the compression called directly: Go's own SHA-256
// assembly, vendored unmodified (sha256block_*.s, README.md), at the rate the
// hardware's SHA instructions allow. An opener can do no better on this core,
// so a delay timed with this holds against one that tries.
package sha256iter

import (
	"crypto/sha256"
	"encoding/binary"
)

// iv is SHA-256's initial hash value (FIPS 180-4 §5.3.3).
var iv = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// Iterate hashes h n times over with SHA-256: h = SHA-256(h), n times. On a
// CPU with SHA instructions it compresses directly (hasBlock); elsewhere it
// is crypto/sha256's Sum256, to the same result.
func Iterate(h [32]byte, n uint64) [32]byte {
	if !hasBlock {
		for range n {
			h = sha256.Sum256(h[:])
		}
		return h
	}
	// One block: the 32-byte message, 0x80, zeros, and its length, 256 bits.
	var buf [64]byte
	copy(buf[:32], h[:])
	buf[32] = 0x80
	buf[62] = 0x01 // 256 = 0x0100, big-endian in the last 8 bytes
	for range n {
		st := iv
		block(&st, buf[:])
		for i, w := range st {
			binary.BigEndian.PutUint32(buf[4*i:], w)
		}
	}
	copy(h[:], buf[:32])
	return h
}

// Accelerated reports whether this CPU runs Iterate on its SHA instructions.
func Accelerated() bool { return hasBlock }
