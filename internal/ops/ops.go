// Package ops runs chainlock's operations on files, for any front end. The
// CLI and the TUI differ only in how they gather arguments and how they
// report: ops never prints, and reports through an Env instead.
package ops

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"chainlock"
	"chainlock/alg"
	"chainlock/chain"
	"chainlock/format"
	"chainlock/internal/store"
)

// SealArgs locks File behind N+1 steps, or, if Delay is set, as many steps
// as Delay takes on this machine.
type SealArgs struct {
	File string
	// Alg is the step function. With a Delay it may be nil, and AlgFor
	// chooses; N counts steps of one particular algorithm, so it needs one.
	Alg     alg.Alg
	N       int
	Delay   time.Duration
	Form    store.Form
	Lock    string // FormFile and FormRaw: lock output (default FILE.lock)
	Payload string // FormFile and FormRaw: payload output (default FILE.payload)
	KeyOut  string // where to save the key, if anywhere; "-" for Stdout
	Workers int
}

// ErrNeedAlg refuses a step count with no algorithm: N counts steps of one
// particular step function, and only a delay can choose one.
var ErrNeedAlg = errors.New("a step count needs an algorithm; give one, or give a delay instead")

func (e *Env) Seal(ctx context.Context, a SealArgs) error {
	// Everything that can fail without sealing fails first: sealing takes as
	// long as the delay's work, and timing the step can take most of a minute.
	if a.Alg == nil && a.Delay <= 0 {
		return ErrNeedAlg
	}
	if err := e.checkKeyOut(a.KeyOut); err != nil {
		return err
	}
	if err := store.Absent(store.SealedPaths(a.File, a.Form, a.Lock, a.Payload)...); err != nil {
		return err
	}
	pt, err := os.ReadFile(a.File)
	if err != nil {
		return err
	}
	if a.Alg == nil {
		a.Alg = AlgFor(a.Delay)
		e.note(Detail, "algorithm %v for a delay of %s (no algorithm given; 0x02 from %s up)", a.Alg.ID(), FormatDelay(a.Delay), FormatDelay(LongDelay))
	}
	steps, err := e.plan(ctx, "sealing", a.Alg, a.N+1, a.Delay, a.Workers)
	if err != nil {
		return err
	}
	n := steps - 1
	lock, payload, key, err := chainlock.Seal(ctx, pt, chainlock.SealOpts{Alg: a.Alg.ID(), N: n, Opts: chain.Opts{
		Workers: a.Workers, Progress: e.progress("sealing"), Activity: e.activity("sealing", steps),
	}})
	if err != nil {
		return err
	}
	w, err := store.WriteSealed(a.File, a.Form, a.Lock, a.Payload, lock, payload)
	if err != nil {
		return err
	}
	e.note(Wrote, "wrote %s (%s, N=%d, %d steps)", w[0].Path, Bytes(int64(w[0].Size)), n, steps)
	if len(w) == 2 {
		e.note(Wrote, "wrote %s (%s, encrypted)", w[1].Path, Bytes(int64(w[1].Size)))
	}
	return e.writeKey(a.KeyOut, key)
}

// OpenArgs solves the lock File and decrypts its payload.
type OpenArgs struct {
	File    string // a lock in any form
	Payload string // default: the archive's own, or FILE.payload
	Out     string // default: FILE, which must not exist
	KeyOut  string // where to save the recovered key, if anywhere; "-" for Stdout
}

func (e *Env) Open(ctx context.Context, a OpenArgs) error {
	// Everything that can fail without solving fails first: the key path and
	// the lock's digest here, the output name below, the payload's digest and
	// pairing in chainlock.Open.
	if err := e.checkKeyOut(a.KeyOut); err != nil {
		return err
	}
	l, err := store.Load(a.File)
	if err != nil {
		return err
	}
	out, err := store.OutputFor(a.Out, a.File, l.Form.Suffix())
	if err != nil {
		return err
	}
	payload, _, err := l.PayloadOf(a.File, a.Payload)
	if err != nil {
		return err
	}
	pt, key, err := chainlock.Open(ctx, l.Obj, payload, e.solveProgress(l.Parsed.N+1))
	if err != nil {
		return err
	}
	if err := store.WriteFile(out, pt); err != nil {
		return err
	}
	e.note(Wrote, "wrote %s", out)
	return e.writeKey(a.KeyOut, key)
}

// BypassArgs decrypts a payload with a saved key, without solving.
type BypassArgs struct {
	File    string // a payload, or a lock to take the payload from
	Key     string // key file; "-" for Stdin
	Payload string // when File is a lock: default the archive's own, or FILE.payload
	Out     string // default: FILE, which must not exist
}

func (e *Env) Bypass(a BypassArgs) error {
	key, err := e.readKey(a.Key)
	if err != nil {
		return err
	}
	payload, suffix, err := store.LoadPayload(a.File, a.Payload)
	if err != nil {
		return err
	}
	out, err := store.OutputFor(a.Out, a.File, suffix)
	if err != nil {
		return err
	}
	pt, err := format.OpenPayload(key, payload)
	if errors.Is(err, format.ErrAuth) {
		return fmt.Errorf("%w: wrong key for this payload", err)
	}
	if err != nil {
		return err
	}
	if err := store.WriteFile(out, pt); err != nil {
		return err
	}
	e.note(Wrote, "wrote %s", out)
	return nil
}

// ExtendArgs adds Add steps to the lock File, or, if Delay is set, as many
// steps as Delay takes on this machine.
type ExtendArgs struct {
	File    string // a lock in any form; it is written back in the same form
	Add     int
	Delay   time.Duration
	Out     string // default: replace File
	Workers int
}

func (e *Env) Extend(ctx context.Context, a ExtendArgs) error {
	// Load verifies the digest, so damage is never sealed under a new one.
	l, err := store.Load(a.File)
	if err != nil {
		return err
	}
	if a.Out != "" && a.Out != a.File { // in place is the point; anything else is kept
		if err := store.Absent(a.Out); err != nil {
			return err
		}
	}
	p := l.Parsed
	add, err := e.plan(ctx, "extending", p.Alg, a.Add, a.Delay, a.Workers)
	if err != nil {
		return err
	}
	ext, err := chain.Extend(ctx, l.Obj, add, chain.Opts{
		Workers: a.Workers, Progress: e.progress("extending"), Activity: e.activity("extending", add),
	})
	if err != nil {
		return err
	}
	out := cmp.Or(a.Out, a.File)
	if err := l.Save(out, ext); err != nil {
		return err
	}
	e.note(Wrote, "wrote %s (N %d → %d)", out, p.N, p.N+add)
	return nil
}

// Info describes a lock and the payload open would use with it.
type Info struct {
	Alg  alg.Alg
	N    int
	Size int // of the SPEC.md object
	Form store.Form
	// PayloadWhere is where the payload was looked for, and PayloadErr why it
	// is unusable: an fs.ErrNotExist if absent, or what the pre-solve check
	// found. Nil means it pairs with this lock and its digest is intact.
	PayloadWhere string
	PayloadErr   error
}

// Describe reads the lock at path and checks its payload without solving: the
// archive's own, or FILE.payload beside FILE.lock.
func Describe(path string) (*Info, error) {
	l, err := store.Load(path)
	if err != nil {
		return nil, err
	}
	in := &Info{Alg: l.Parsed.Alg, N: l.Parsed.N, Size: len(l.Obj), Form: l.Form}
	var payload []byte
	payload, in.PayloadWhere, in.PayloadErr = l.PayloadOf(path, "")
	if in.PayloadErr == nil {
		in.PayloadErr = format.CheckPayload(l.Parsed, payload)
	}
	return in, nil
}

// PayloadMissing reports an Info whose lock has no payload beside it.
func (in *Info) PayloadMissing() bool { return errors.Is(in.PayloadErr, fs.ErrNotExist) }
