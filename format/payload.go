package format

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"

	"chainlock/chain"
)

// The payload layer is outside the lock format (SPEC.md §9, informative). Its
// file layout is CONTAINER.md §3:
//
//	HEADER ‖ NONCE ‖ CIPHERTEXT ‖ TAG ‖ TRAILER
//	HEADER = MAGIC_PAYL ‖ VERSION ‖ LOCK_ID, the GCM additional data
//	TRAILER = SHA-256 of everything before it
const (
	payloadHeader   = 8 + 1 + digestLen
	payloadOverhead = payloadHeader + 12 + 16 + digestLen // header, nonce, tag, trailer
	domainLockID    = "chainlock/v1/lockid"
)

// lockID fingerprints the lock o (CONTAINER.md §3). It covers ALG_ID and
// block 0, which extension never changes, so a lock and all its extensions
// share one LOCK_ID.
func lockID(o *chain.Object) []byte {
	h := sha256.New()
	h.Write([]byte(domainLockID))
	h.Write([]byte{byte(o.Alg.ID())})
	h.Write(o.Block(0))
	return h.Sum(nil)
}

func gcm(key chain.Key) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, chain.ErrSecretLen
	}
	return cipher.NewGCMWithRandomNonce(b)
}

// SealPayload encrypts plaintext under the lock o's key into a payload file
// bound to o, and to every extension of it.
func SealPayload(key chain.Key, o *chain.Object, plaintext []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, payloadHeader)
	header = append(header, magicPayload...)
	header = append(header, version)
	header = append(header, lockID(o)...)
	out := make([]byte, 0, payloadOverhead+len(plaintext))
	out = append(out, header...)
	// Seal's dst and additional data must not overlap, so header is its own
	// slice. Seal appends nonce ‖ ciphertext ‖ tag.
	out = g.Seal(out, nil, plaintext, header)
	d := sha256.Sum256(out)
	return append(out, d[:]...), nil
}

// IsPayload reports whether b is a payload file (CONTAINER.md §1).
func IsPayload(b []byte) bool { return bytes.HasPrefix(b, magicPayload) }

// CheckPayload verifies everything about payload that needs no key, in
// CONTAINER.md §3 order: magic and version, trailer (ErrCorrupt), then,
// unless o is nil, that it belongs to the lock o or an extension of it
// (ErrMismatch). It needs no solving, so a damaged or mismatched pair fails
// before the delay is spent.
func CheckPayload(o *chain.Object, payload []byte) error {
	switch {
	case bytes.HasPrefix(payload, magicLock):
		return fmt.Errorf("%w: this is a lock file, not a payload", ErrFormat)
	case !bytes.HasPrefix(payload, magicPayload):
		return fmt.Errorf("%w: not a payload file", ErrFormat)
	case len(payload) < payloadOverhead:
		return fmt.Errorf("%w: truncated payload file", ErrFormat)
	case payload[8] != version:
		return fmt.Errorf("%w: payload file version %d (this build reads %d)", ErrFormat, payload[8], version)
	}
	body, trailer := payload[:len(payload)-digestLen], payload[len(payload)-digestLen:]
	if d := sha256.Sum256(body); !bytes.Equal(d[:], trailer) {
		return fmt.Errorf("%w: payload file digest mismatch", ErrCorrupt)
	}
	if o != nil && !bytes.Equal(payload[9:payloadHeader], lockID(o)) {
		return ErrMismatch
	}
	return nil
}

// OpenPayload checks payload (CheckPayload, with no lock) and decrypts it
// with key, the lock's S from solving or a saved key. A wrong key and a
// damaged lock are indistinguishable: both are ErrAuth.
func OpenPayload(key chain.Key, payload []byte) ([]byte, error) {
	if err := CheckPayload(nil, payload); err != nil {
		return nil, err
	}
	g, err := gcm(key)
	if err != nil {
		return nil, ErrAuth
	}
	sealed := payload[payloadHeader : len(payload)-digestLen]
	pt, err := g.Open(nil, nil, sealed, payload[:payloadHeader])
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}
