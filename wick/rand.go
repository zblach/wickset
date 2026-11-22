package wick

import (
	"crypto/rand"
	"io"
)

// randSource is the only source of randomness. It is deliberately unexported:
// callers cannot supply seeds or readers. Tests in this package may replace it.
var randSource io.Reader = rand.Reader

// randBlocks draws n independent uniform blocks of size b.
func randBlocks(n, b int) ([][]byte, error) {
	flat := make([]byte, n*b)
	if _, err := io.ReadFull(randSource, flat); err != nil {
		return nil, err
	}
	out := make([][]byte, n)
	for i := range out {
		out[i] = flat[i*b : (i+1)*b : (i+1)*b]
	}
	return out, nil
}
