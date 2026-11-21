//go:build !(darwin && cgo)

package argon2gpu

import "context"

// Device is a GPU; this build has none (Metal needs darwin and cgo).
type Device struct{}

// Open reports ErrUnavailable: no GPU backend is built in.
func Open() (*Device, error) { return nil, ErrUnavailable }

func (d *Device) Close()              {}
func (d *Device) MaxBatch(Params) int { return 0 }

func (d *Device) Hash(context.Context, Params, [][]byte) ([][]byte, error) {
	return nil, ErrUnavailable
}
