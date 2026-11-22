//go:build darwin && cgo

package argon2gpu

/*
#cgo CFLAGS: -fno-objc-arc
#cgo LDFLAGS: -framework Metal -framework Foundation
#include <stdlib.h>
#include "metal_darwin.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"chainlock/internal/argon2"
)

// Built reports whether this build has a GPU backend: Metal, here.
const Built = true

// Name is the GPU's name, such as "Apple M5", or "" if the machine has none.
// It compiles nothing, so it is cheap to show.
func Name() string {
	n := C.clm_device_name()
	if n == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(n))
	return C.GoString(n)
}

// Device is the system's GPU, through Metal, with the kernel compiled. It is
// an argon2.Hasher.
type Device struct {
	mu sync.Mutex // one batch at a time: each holds most of the GPU's memory
	c  *C.clm
}

// Open compiles the kernel for the default Metal device. It takes seconds:
// open once and reuse.
func Open() (*Device, error) {
	src, err := source()
	if err != nil {
		return nil, err
	}
	defs := macros(1<<1, runtime.GOARCH == "arm64") // VENDOR_ID 2: Apple
	var lines []string
	for k, v := range defs {
		lines = append(lines, k+"="+v)
	}
	sort.Strings(lines)
	csrc, cdefs := C.CString(src), C.CString(strings.Join(lines, "\n"))
	defer C.free(unsafe.Pointer(csrc))
	defer C.free(unsafe.Pointer(cdefs))
	var cerr *C.char
	c := C.clm_open(csrc, cdefs, &cerr)
	if c == nil {
		return nil, cError("argon2gpu: Metal", cerr)
	}
	return &Device{c: c}, nil
}

// Close releases the device.
func (d *Device) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	C.clm_close(d.c)
	d.c = nil
}

// Batch is how many evaluations of p one batch holds: as many as fit one
// buffer, and half the working set the device recommends, which on Apple
// silicon is shared with everything else the machine runs.
func (d *Device) Batch(p argon2.Params) int {
	limit := min(uint64(C.clm_max_buffer(d.c)), uint64(C.clm_working_set(d.c))/2)
	return max(int(limit/instanceBytes(p)), 1)
}

// Memory is the working set the device recommends: on Apple silicon, most of
// the machine's memory, which the CPU shares.
func (d *Device) Memory() uint64 { return uint64(C.clm_working_set(d.c)) }

// Hash evaluates Argon2id with p over each input, as p.Key would, in batches
// of up to Batch. Inputs are all one length. Cancelling ctx stops it at the
// next segment, a quarter pass.
func (d *Device) Hash(ctx context.Context, p argon2.Params, inputs [][]byte) ([][]byte, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	n := len(inputs[0])
	if err := check(p, n); err != nil {
		return nil, err
	}
	for _, in := range inputs {
		if len(in) != n {
			return nil, errors.New("argon2gpu: inputs of different lengths")
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out [][]byte
	for batch := d.Batch(p); len(inputs) > 0; inputs = inputs[min(batch, len(inputs)):] {
		got, err := d.batch(ctx, p, inputs[:min(batch, len(inputs))])
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// batch runs one batch: init, every segment, final.
func (d *Device) batch(ctx context.Context, p argon2.Params, inputs [][]byte) ([][]byte, error) {
	job := job(p, len(inputs), len(inputs[0]))
	flat := make([]byte, 0, len(inputs)*len(inputs[0]))
	for _, in := range inputs {
		flat = append(flat, in...)
	}
	outLen := len(inputs) * int(p.KeyLen)
	var cerr *C.char
	j := C.clm_begin(d.c, unsafe.Pointer(&job[0]), C.size_t(len(job)), unsafe.Pointer(&flat[0]), C.size_t(len(flat)),
		C.uint32_t(len(inputs)), C.uint64_t(instanceBytes(p)), C.size_t(outLen), &cerr)
	if j == nil {
		return nil, cError("argon2gpu: starting a batch", cerr)
	}
	defer C.clm_free(j)
	for pass := range p.Passes {
		for slice := range uint32(syncPoints) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if C.clm_segment(d.c, j, C.uint32_t(pass), C.uint32_t(slice), &cerr) != 0 {
				return nil, cError(fmt.Sprintf("argon2gpu: pass %d slice %d", pass, slice), cerr)
			}
		}
	}
	buf := make([]byte, outLen)
	if C.clm_end(d.c, j, unsafe.Pointer(&buf[0]), &cerr) != 0 {
		return nil, cError("argon2gpu: final", cerr)
	}
	out := make([][]byte, len(inputs))
	for i := range out {
		out[i] = buf[i*int(p.KeyLen) : (i+1)*int(p.KeyLen) : (i+1)*int(p.KeyLen)]
	}
	return out, nil
}

func cError(what string, s *C.char) error {
	defer C.free(unsafe.Pointer(s))
	return fmt.Errorf("%s: %s", what, C.GoString(s))
}
