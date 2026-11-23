package wickset

import (
	"context"

	"github.com/zblach/wickset/alg"
	"github.com/zblach/wickset/format"
	"github.com/zblach/wickset/wick"
)

// SealOpts configures Seal: the algorithm, N, and how the parallel build
// runs.
type SealOpts struct {
	Alg alg.ID
	N   int // the solver performs N+1 sequential steps; N >= 0
	wick.Opts
}

// Seal draws a fresh random S, hides it behind a wick, and encrypts plaintext
// under it. raw is the wick (wrap it with format.EncodeWickFile to store it);
// payload is a payload file bound to it (CONTAINER.md §3). key is S, for a
// holder who wants to open the payload later without solving
// (format.OpenPayload); discard it to keep no shortcut.
func Seal(ctx context.Context, plaintext []byte, o SealOpts) (raw, payload []byte, key wick.Key, err error) {
	// The wick comes first: the payload is bound to its block 0.
	raw, key, err = wick.New(ctx, o.Alg, o.N, o.Opts)
	if err != nil {
		return nil, nil, nil, err
	}
	obj, err := wick.Parse(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	if payload, err = format.SealPayload(key, obj, plaintext); err != nil {
		return nil, nil, nil, err
	}
	return raw, payload, key, nil
}

// Open checks that payload is intact and belongs to the raw wick obj, then
// burns the wick and decrypts the payload. The checks come first, so a
// damaged or mismatched payload fails before any evaluation of H. key is the
// S that solving recovered, for opening again later with format.OpenPayload.
// report, if set, is told of each step (wick.Solve).
func Open(ctx context.Context, obj, payload []byte, report wick.Report) (plaintext []byte, key wick.Key, err error) {
	o, err := wick.Parse(obj)
	if err != nil {
		return nil, nil, err
	}
	return open(ctx, o, payload, report)
}

func open(ctx context.Context, o *wick.Object, payload []byte, report wick.Report) ([]byte, wick.Key, error) {
	if err := format.CheckPayload(o, payload); err != nil {
		return nil, nil, err
	}
	key, err := wick.Solve(ctx, o, report)
	if err != nil {
		return nil, nil, err
	}
	pt, err := format.OpenPayload(key, payload)
	if err != nil {
		return nil, nil, err
	}
	return pt, key, nil
}
