// Package gpu runs chainlock's step functions on a GPU, many independent
// evaluations at a time, as sealing needs: Argon2id (its Device is an
// argon2.Hasher, like internal/argon2's CPU) and SHA-256 chains. The hashing
// is hashcat's (hashcat/, vendored unmodified); this package is only the
// kernels' entry points and the host that loads them and moves inputs and
// outputs, and its tests hold every result to x/crypto's and the standard
// library's.
package gpu

import (
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"chainlock/internal/argon2"
)

// ErrUnavailable reports a build or machine with no supported GPU.
var ErrUnavailable = errors.New("gpu: no supported GPU in this build")

const (
	chainDispatch = 1 << 13 // hashes a chain advances per dispatch: under a second, however many run
	minChains     = 1 << 10 // the range ChainBatch searches
	maxChains     = 1 << 20

	syncPoints = 4
	blockSize  = 1024 // bytes in an Argon2 block
	maxBytes   = 256  // the most input or salt the kernel copies
)

// blocks is how many blocks an evaluation of p fills, rounded as x/crypto
// rounds them.
func blocks(p argon2.Params) uint32 {
	return max(p.MemoryKiB/syncPoints*syncPoints, 2*syncPoints)
}

// instanceBytes is the memory one evaluation of p holds on the device.
func instanceBytes(p argon2.Params) uint64 { return uint64(blocks(p)) * blockSize }

func check(p argon2.Params, inputLen int) error {
	switch {
	case p.Passes < 1:
		return errors.New("gpu: no passes")
	case p.KeyLen == 0 || p.KeyLen%8 != 0 || p.KeyLen > 64:
		return fmt.Errorf("gpu: key length %d is not a multiple of 8 up to 64", p.KeyLen)
	case len(p.Salt) > maxBytes:
		return fmt.Errorf("gpu: salt of %d bytes is over %d", len(p.Salt), maxBytes)
	case inputLen%4 != 0 || inputLen > maxBytes:
		return fmt.Errorf("gpu: input of %d bytes is not a multiple of 4 up to %d", inputLen, maxBytes)
	}
	return nil
}

// job is chainlock_job_t (kernel.cl) for count inputs of inputLen bytes:
// hashcat's argon2_options_t, then the batch.
func job(p argon2.Params, count, inputLen int) []byte {
	b := blocks(p)
	words := []uint32{
		2,    // type: Argon2id
		0x13, // version 1.3
		p.Passes,
		1,           // parallelism
		p.MemoryKiB, // as given: H0 hashes it before rounding, as x/crypto does
		b / syncPoints,
		b, // lane length: one lane
		b, // blocks
		p.KeyLen,
		uint32(count),
		uint32(inputLen),
		uint32(len(p.Salt)),
	}
	var salt [maxBytes]byte
	copy(salt[:], p.Salt)
	out := make([]byte, 0, 4*len(words)+maxBytes)
	for _, w := range words {
		out = binary.LittleEndian.AppendUint32(out, w)
	}
	return append(out, salt[:]...)
}

//go:embed kernel.cl sha256.cl hashcat/inc_* hashcat/license.txt hashcat/SHA256SUMS
var files embed.FS

// include matches the two forms of #include hashcat's sources use.
var include = regexp.MustCompile(`^\s*#include\s+(?:"([^"]+)"|M2S\(INCLUDE_PATH/([^)]+)\))\s*$`)

// source is kernel.cl with every include expanded in place, once, as one
// compilation unit: Metal compiles from memory and has no include path.
// #line directives keep the compiler's messages pointing into the real files.
func source() (string, error) {
	var b strings.Builder
	done := map[string]bool{}
	var expand func(name, path string) error
	expand = func(name, path string) error {
		if done[name] {
			return nil
		}
		done[name] = true
		data, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "#line 1 \"%s\"\n", name)
		for i, line := range strings.Split(string(data), "\n") {
			m := include.FindStringSubmatch(line)
			if m == nil {
				b.WriteString(line)
				b.WriteByte('\n')
				continue
			}
			inc := m[1] + m[2]
			if err := expand(inc, "hashcat/"+inc); err != nil {
				return fmt.Errorf("%s:%d: %w", name, i+1, err)
			}
			fmt.Fprintf(&b, "#line %d \"%s\"\n", i+2, name)
		}
		return nil
	}
	for _, k := range []string{"kernel.cl", "sha256.cl"} {
		if err := expand(k, k); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// macros are the definitions hashcat's own host passes for a GPU build of
// an Argon2 kernel (src/backend.c, src/modules/argon2_common.c at v8.0.0),
// less those that only a cracking run uses.
func macros(vendorID uint32, appleSilicon bool) map[string]string {
	m := map[string]string{
		"KERNEL_STATIC":         "1",
		"VENDOR_ID":             fmt.Sprint(vendorID),
		"DEVICE_VENDOR_ID":      fmt.Sprint(vendorID),
		"DEVICE_TYPE":           "4", // GPU
		"LOCAL_MEM_TYPE":        "1", // real local memory
		"VECT_SIZE":             "1",
		"CUDA_ARCH":             "0",
		"ATTACK_EXEC":           "10", // outside the kernel: init, loop, comp
		"ATTACK_KERN":           "0",
		"ATTACK_MODE":           "0",
		"KERN_TYPE":             "34000",
		"DGST_R0":               "0", // the digest words hashcat's comparisons read;
		"DGST_R1":               "1", // inc_common.cl names them, nothing here calls them
		"DGST_R2":               "2",
		"DGST_R3":               "3",
		"DGST_ELEM":             "4",
		"FORCED_THREAD_COUNT":   "32",
		"MAX_THREADS_PER_BLOCK": "1024",
		"ARGON2_PARALLELISM":    "1",
	}
	if appleSilicon {
		m["IS_APPLE_SILICON"] = "1"
	}
	return m
}
