package format

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"

	"github.com/zblach/wickset/wick"
)

// The payload layer is outside the wick format (SPEC.md §9, informative). Its
// file layout is CONTAINER.md §3:
//
//	HEADER ‖ NONCE ‖ CIPHERTEXT ‖ TAG ‖ TRAILER
//	HEADER = MAGIC_PAYL ‖ VERSION ‖ WICK_ID, the GCM additional data
//	TRAILER = SHA-256 of everything before it
const (
	payloadHeader   = 8 + 1 + digestLen
	payloadOverhead = payloadHeader + 12 + 16 + digestLen // header, nonce, tag, trailer
	domainWickID    = "wickset/v1/wickid"
)

// wickID fingerprints the wick o (CONTAINER.md §3). It covers ALG_ID and
// block 0, which neither extending nor burning changes, so a wick, all its
// extensions and every partly burned copy share one WICK_ID.
func wickID(o *wick.Object) []byte {
	h := sha256.New()
	h.Write([]byte(domainWickID))
	h.Write([]byte{byte(o.Alg.ID())})
	h.Write(o.Block(0))
	return h.Sum(nil)
}

func gcm(key wick.Key) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, wick.ErrSecretLen
	}
	return cipher.NewGCMWithRandomNonce(b)
}

// SealPayload encrypts plaintext under the wick o's key into a payload file
// bound to o, and to every extension of it.
func SealPayload(key wick.Key, o *wick.Object, plaintext []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, payloadHeader)
	header = append(header, magicPayload...)
	header = append(header, version)
	header = append(header, wickID(o)...)
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
// unless o is nil, that it belongs to the wick o or an extension of it
// (ErrMismatch). It needs no solving, so a damaged or mismatched pair fails
// before the delay is spent.
func CheckPayload(o *wick.Object, payload []byte) error {
	switch {
	case bytes.HasPrefix(payload, magicWick):
		return fmt.Errorf("%w: this is a wick file, not a payload", ErrFormat)
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
	if o != nil && !bytes.Equal(payload[9:payloadHeader], wickID(o)) {
		return ErrMismatch
	}
	return nil
}

// OpenPayload checks payload (CheckPayload, with no wick) and decrypts it
// with key, the wick's S from solving or a saved key. A wrong key and a
// damaged wick are indistinguishable: both are ErrAuth.
func OpenPayload(key wick.Key, payload []byte) ([]byte, error) {
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
