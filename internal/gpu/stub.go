//go:build !(darwin && cgo)

package gpu

import (
	"context"

	"chainlock/internal/argon2"
)

// Built reports whether this build has a GPU backend.
const Built = false

// Name is "": this build has no GPU.
func Name() string { return "" }

// Device is a GPU; this build has none (Metal needs darwin and cgo).
type Device struct{}

// Open reports ErrUnavailable: no GPU backend is built in.
func Open() (*Device, error) { return nil, ErrUnavailable }

func (d *Device) Close()                  {}
func (d *Device) Batch(argon2.Params) int { return 0 }
func (d *Device) Memory() uint64          { return 0 }

func (d *Device) Hash(context.Context, argon2.Params, [][]byte) ([][]byte, error) {
	return nil, ErrUnavailable
}

func (d *Device) ChainBatch() int { return 0 }

func (d *Device) Chain(context.Context, [][32]byte, uint64, func(uint64)) ([][32]byte, error) {
	return nil, ErrUnavailable
}
