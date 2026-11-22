//go:build (!arm64 && !amd64) || purego

package sha256iter

// No vendored assembly for this architecture: Iterate uses crypto/sha256.
const hasBlock = false

func block(*[8]uint32, []byte) { panic("sha256iter: no block function") }
