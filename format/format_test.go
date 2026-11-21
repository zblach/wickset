package format

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"chainlock/alg"
	"chainlock/chain"
)

// object is a lock object of 0x01 with N+1 = blocks-1 steps, block 0 filled
// with seed. Nothing here evaluates H, so no real chain is needed: the files
// bind to an object's ALG_ID and block 0, and carry it whole.
func object(t *testing.T, seed byte, blocks int) (raw []byte, o *chain.Object) {
	t.Helper()
	raw = append([]byte{byte(alg.Argon2id256M)}, bytes.Repeat([]byte{seed}, blocks*32)...)
	o, err := chain.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, o
}

func key(seed byte) chain.Key { return chain.Key(bytes.Repeat([]byte{seed}, 32)) }

// flip returns a copy of b with one bit of byte i flipped.
func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 1
	return c
}

func TestLockFile(t *testing.T) {
	obj, o := object(t, 1, 5)
	lf := EncodeLockFile(obj)
	if len(lf) != lockFileHeader+len(obj) || !bytes.HasPrefix(lf, []byte("\x00CL-LOCK\x01")) {
		t.Fatalf("lock file header: %x", lf[:lockFileHeader])
	}
	got, wrapped, err := DecodeLock(lf)
	if err != nil || !wrapped || !bytes.Equal(got, obj) {
		t.Fatalf("round trip: wrapped=%v err=%v", wrapped, err)
	}
	if got, wrapped, err := DecodeLock(obj); err != nil || wrapped || !bytes.Equal(got, obj) {
		t.Fatalf("raw object: wrapped=%v err=%v", wrapped, err)
	}

	version2 := append([]byte(nil), lf...)
	version2[8] = 2
	payload, err := SealPayload(key(1), o, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		in   []byte
		want error
	}{
		{"object bit", flip(lf, len(lf)-1), ErrCorrupt},
		{"digest bit", flip(lf, 9), ErrCorrupt},
		{"version 2", version2, ErrFormat},
		{"truncated header", lf[:20], ErrFormat},
		{"payload file", payload, ErrFormat},
		{"unknown 0x00 magic", append([]byte("\x00CL-NOPE\x01"), lf[9:]...), ErrFormat},
	} {
		if _, _, err := DecodeLock(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.want)
		}
	}
}

// TestRawNeverSniffedAsContainer: every possible ALG_ID byte, registered or
// not, leaves a raw object raw (CONTAINER.md §1).
func TestRawNeverSniffedAsContainer(t *testing.T) {
	for id := 1; id < 256; id++ {
		raw := append([]byte{byte(id)}, make([]byte, 2*32)...)
		if _, wrapped, err := DecodeLock(raw); wrapped || err != nil {
			t.Fatalf("id %#x: wrapped=%v err=%v", id, wrapped, err)
		}
	}
}

func TestPayload(t *testing.T) {
	pt := []byte("attack at dawn")
	obj, o := object(t, 7, 6)
	_, other := object(t, 8, 6)
	k := key(7)
	payload, err := SealPayload(k, o, pt)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != payloadOverhead+len(pt) {
		t.Fatalf("payload is %d bytes, want %d", len(payload), payloadOverhead+len(pt))
	}
	if !IsPayload(payload) || IsPayload(EncodeLockFile(obj)) {
		t.Fatal("IsPayload")
	}
	if got, err := OpenPayload(k, payload); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip: %q %v", got, err)
	}

	// What CheckPayload catches, needing no key and no solving.
	version2 := append([]byte(nil), payload...)
	version2[8] = 2
	for _, c := range []struct {
		name    string
		lock    *chain.Object
		payload []byte
		want    error
	}{
		{"own lock", o, payload, nil},
		{"no lock: integrity only", nil, payload, nil},
		{"other lock", other, payload, ErrMismatch},
		{"lock id bit", o, flip(payload, 9), ErrCorrupt},
		{"ciphertext bit", o, flip(payload, payloadHeader+20), ErrCorrupt},
		{"trailer bit", o, flip(payload, len(payload)-1), ErrCorrupt},
		{"version 2", o, version2, ErrFormat},
		{"truncated", o, payload[:payloadOverhead-1], ErrFormat},
		{"lock file", o, EncodeLockFile(obj), ErrFormat},
	} {
		if err := CheckPayload(c.lock, c.payload); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.want)
		}
	}

	// LOCK_ID covers block 0 only: extension rewrites the last block, and the
	// payload still pairs.
	if _, ext := object(t, 7, 6); CheckPayload(ext, payload) != nil {
		t.Error("a lock with the same block 0 does not pair")
	}
	longer, _ := chain.Parse(flip(obj, len(obj)-1))
	if err := CheckPayload(longer, payload); err != nil {
		t.Errorf("last block changed (as extension does): %v", err)
	}

	// A tamperer who also rewrites the trailer gets past CheckPayload; only
	// the GCM tag, after solving, catches it.
	forged := flip(payload, payloadHeader+20)
	forged = forged[:len(forged)-digestLen]
	d := sha256.Sum256(forged)
	forged = append(forged, d[:]...)
	if err := CheckPayload(o, forged); err != nil {
		t.Fatalf("forged trailer failed the pre-check: %v", err)
	}
	if _, err := OpenPayload(k, forged); !errors.Is(err, ErrAuth) {
		t.Errorf("forged trailer: err %v, want ErrAuth", err)
	}
	if _, err := OpenPayload(key(9), payload); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong key: err %v, want ErrAuth", err)
	}

	// The nonce is random: sealing twice under one key never repeats.
	p2, _ := SealPayload(k, o, pt)
	if bytes.Equal(payload, p2) {
		t.Fatal("two seals are identical: nonce not random")
	}
}
