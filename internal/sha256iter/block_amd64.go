//go:build !purego

package sha256iter

import "golang.org/x/sys/cpu"

// The conditions Go's crypto/sha256 uses for its two amd64 routines.
var (
	useSHANI = cpu.X86.HasAVX && hasSHA() && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3
	useAVX2  = cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasBMI2
	hasBlock = useSHANI || useAVX2
)

// hasSHA reports the SHA extensions: CPUID leaf 7, EBX bit 29.
func hasSHA() bool {
	if maxID, _, _, _ := cpuid(0, 0); maxID < 7 {
		return false
	}
	_, ebx, _, _ := cpuid(7, 0)
	return ebx&(1<<29) != 0
}

// cpuid is cpuid_amd64.s.
func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// blockSHANI and blockAVX2 are sha256block_amd64.s: each compresses p, whole
// 64-byte blocks, into the state at dig (its first 32 bytes, as Go's
// sha256.Digest begins).
//
//go:noescape
func blockSHANI(dig *[8]uint32, p []byte)

//go:noescape
func blockAVX2(dig *[8]uint32, p []byte)

func block(dig *[8]uint32, p []byte) {
	if useSHANI {
		blockSHANI(dig, p)
	} else {
		blockAVX2(dig, p)
	}
}
