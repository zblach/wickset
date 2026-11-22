//go:build darwin && cgo

package gpu

/*
#cgo CFLAGS: -fno-objc-arc
#cgo LDFLAGS: -framework Metal -framework Foundation
#include <stdlib.h>
#include "metal_darwin.h"
*/
import "C"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"wickset/internal/argon2"
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

	iterOnce  sync.Once
	iterBatch int
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
		return nil, cError("gpu: Metal", cerr)
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

// Batch is the most evaluations of p one batch can hold: as many as fit one
// buffer. How much of the device's memory to use is the caller's to decide
// (Memory).
func (d *Device) Batch(p argon2.Params) int {
	return max(int(uint64(C.clm_max_buffer(d.c))/instanceBytes(p)), 1)
}

// Memory is the working set the device recommends: on Apple silicon, most of
// the machine's memory, which the CPU shares.
func (d *Device) Memory() uint64 { return uint64(C.clm_working_set(d.c)) }

// Hash evaluates Argon2id with p over each input, as p.Key would, in batches
// of up to Batch. Inputs are all one length. Cancelling ctx stops it at the
// next segment, a quarter pass.
func (d *Device) Hash(ctx context.Context, p argon2.Params, inputs [][]byte) ([][]byte, error) {
	return d.HashPartway(ctx, p, inputs, nil)
}

// HashPartway is Hash, reporting after each segment, if report is set, how
// many of the batch under way's segments (four a pass) are done, of all.
func (d *Device) HashPartway(ctx context.Context, p argon2.Params, inputs [][]byte, report func(done, total uint64)) ([][]byte, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	n := len(inputs[0])
	if err := check(p, n); err != nil {
		return nil, err
	}
	for _, in := range inputs {
		if len(in) != n {
			return nil, errors.New("gpu: inputs of different lengths")
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out [][]byte
	for batch := d.Batch(p); len(inputs) > 0; inputs = inputs[min(batch, len(inputs)):] {
		got, err := d.batch(ctx, p, inputs[:min(batch, len(inputs))], report)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// batch runs one batch: init, every segment, final.
func (d *Device) batch(ctx context.Context, p argon2.Params, inputs [][]byte, report func(done, total uint64)) ([][]byte, error) {
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
		return nil, cError("gpu: starting a batch", cerr)
	}
	defer C.clm_free(j)
	for pass := range p.Passes {
		for slice := range uint32(syncPoints) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if C.clm_segment(d.c, j, C.uint32_t(pass), C.uint32_t(slice), &cerr) != 0 {
				return nil, cError(fmt.Sprintf("gpu: pass %d slice %d", pass, slice), cerr)
			}
			if report != nil {
				report(uint64(pass*syncPoints+slice+1), uint64(p.Passes*syncPoints))
			}
		}
	}
	buf := make([]byte, outLen)
	if C.clm_end(d.c, j, unsafe.Pointer(&buf[0]), &cerr) != 0 {
		return nil, cError("gpu: final", cerr)
	}
	out := make([][]byte, len(inputs))
	for i := range out {
		out[i] = buf[i*int(p.KeyLen) : (i+1)*int(p.KeyLen) : (i+1)*int(p.KeyLen)]
	}
	return out, nil
}

// Iterate hashes each of hs n times over with SHA-256, as alg.SHA256Iter.Run
// does, one thread each. It runs in dispatches of iterDispatch hashes;
// after each it reports the hashes done per step, if report is set, and
// stops with ctx's error once ctx is done.
func (d *Device) Iterate(ctx context.Context, hs [][32]byte, n uint64, report func(done uint64)) ([][32]byte, error) {
	if len(hs) == 0 {
		return nil, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	words := make([]byte, 0, 32*len(hs)) // big-endian words, as the kernel holds them, in host order
	for _, h := range hs {
		for i := 0; i < 32; i += 4 {
			words = binary.NativeEndian.AppendUint32(words, binary.BigEndian.Uint32(h[i:]))
		}
	}
	s := C.clm_sha_begin(d.c, unsafe.Pointer(&words[0]), C.size_t(len(words)))
	if s == nil {
		return nil, errors.New("gpu: could not allocate the steps")
	}
	defer C.clm_sha_end(s)
	for done := uint64(0); done < n; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m := min(n-done, iterDispatch)
		var cerr *C.char
		if C.clm_sha_iter(d.c, s, C.uint32_t(len(hs)), C.uint32_t(m), &cerr) != 0 {
			return nil, cError("gpu: iterated SHA-256", cerr)
		}
		done += m
		if report != nil {
			report(done)
		}
	}
	C.clm_sha_read(s, unsafe.Pointer(&words[0]), C.size_t(len(words)))
	out := make([][32]byte, len(hs))
	for i := range out {
		for w := range 8 {
			binary.BigEndian.PutUint32(out[i][4*w:], binary.NativeEndian.Uint32(words[32*i+4*w:]))
		}
	}
	return out, nil
}

// IterBatch is how many steps Iterate runs at once to best effect here: one
// thread is far slower than a CPU core, so a GPU needs many. It is found on
// first use, in a second or two, by doubling the steps until throughput
// stops growing.
func (d *Device) IterBatch() int {
	d.iterOnce.Do(func() { d.iterBatch = d.calibrate() })
	return d.iterBatch
}

func (d *Device) calibrate() int {
	const hashes = 1 << 11 // per step, per probe: one dispatch
	best, at, flat := 0.0, minBatch, 0
	for n := minBatch; n <= maxBatch && flat < 2; n *= 2 {
		start := time.Now()
		if _, err := d.Iterate(context.Background(), make([][32]byte, n), hashes, nil); err != nil {
			break
		}
		rate := float64(n) / time.Since(start).Seconds()
		if rate > best*1.05 {
			at, flat = n, 0
		} else {
			flat++ // two probes in a row without 5% more: past the knee
		}
		best = max(best, rate)
	}
	return at
}

func cError(what string, s *C.char) error {
	defer C.free(unsafe.Pointer(s))
	return fmt.Errorf("%s: %s", what, C.GoString(s))
}
