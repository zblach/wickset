package chainlock

import (
	"context"

	"chainlock/alg"
	"chainlock/chain"
	"chainlock/format"
)

// SealOpts configures Seal: the algorithm, N, and how the parallel build
// runs.
type SealOpts struct {
	Alg alg.ID
	N   int // the solver performs N+1 sequential steps; N >= 0
	chain.Opts
}

// Seal draws a fresh random S, locks it, and encrypts plaintext under it. lock
// is the raw object (wrap it with format.EncodeLockFile to store it); payload
// is a payload file bound to it (CONTAINER.md §3). key is S, for a holder who
// wants to open the payload later without solving (format.OpenPayload);
// discard it to keep no shortcut.
func Seal(ctx context.Context, plaintext []byte, o SealOpts) (lock, payload []byte, key chain.Key, err error) {
	// The lock comes first: the payload is bound to its block 0.
	lock, key, err = chain.New(ctx, o.Alg, o.N, o.Opts)
	if err != nil {
		return nil, nil, nil, err
	}
	obj, err := chain.Parse(lock)
	if err != nil {
		return nil, nil, nil, err
	}
	if payload, err = format.SealPayload(key, obj, plaintext); err != nil {
		return nil, nil, nil, err
	}
	return lock, payload, key, nil
}

// Open checks that payload is intact and belongs to the lock object lock,
// then solves the lock and decrypts the payload. The checks come first, so a
// damaged or mismatched payload fails before any evaluation of H. key is the
// S that solving recovered, for opening again later with format.OpenPayload.
func Open(ctx context.Context, lock, payload []byte, progress chain.Progress) (plaintext []byte, key chain.Key, err error) {
	o, err := chain.Parse(lock)
	if err != nil {
		return nil, nil, err
	}
	return open(ctx, o, payload, progress)
}

func open(ctx context.Context, o *chain.Object, payload []byte, progress chain.Progress) ([]byte, chain.Key, error) {
	if err := format.CheckPayload(o, payload); err != nil {
		return nil, nil, err
	}
	key, err := chain.Solve(ctx, o, progress)
	if err != nil {
		return nil, nil, err
	}
	pt, err := format.OpenPayload(key, payload)
	if err != nil {
		return nil, nil, err
	}
	return pt, key, nil
}
