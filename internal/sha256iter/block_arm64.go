//go:build !purego

package sha256iter

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// Every Apple silicon core has the SHA-256 instructions; elsewhere, ask.
var hasBlock = runtime.GOOS == "darwin" || cpu.ARM64.HasSHA2

// blockSHA2 is sha256block_arm64.s: it compresses p, whole 64-byte blocks,
// into the state at dig (its first 32 bytes, as Go's sha256.Digest begins).
//
//go:noescape
func blockSHA2(dig *[8]uint32, p []byte)

func block(dig *[8]uint32, p []byte) { blockSHA2(dig, p) }
