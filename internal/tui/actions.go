package tui

import (
	"context"
	"strconv"
	"strings"

	"github.com/zblach/wickset/alg"
	"github.com/zblach/wickset/internal/ops"
	"github.com/zblach/wickset/internal/store"
)

// An action is one of the menu's operations.
type action int

const (
	actSeal action = iota
	actOpen
	actExtend
	actBypass
	actInfo
	actBench
)

// actions are the menu's entries, in its order.
var actions = [...]struct{ name, doing, done, desc string }{
	actSeal:   {"Seal", "Sealing", "Sealed", "Seal a file so it opens only after a delay"},
	actOpen:   {"Open", "Opening", "Opened", "Burn a wick and decrypt its file"},
	actExtend: {"Extend", "Extending", "Extended", "Make a wick take longer to burn"},
	actBypass: {"Bypass", "Decrypting", "Decrypted", "Open a sealed file at once with its saved key"},
	actInfo:   {"Info", "Checking", "Checked", "Show a wick's details and check its files"},
	actBench:  {"Bench", "Timing", "Timed", "Time this machine to see how long wicks take"},
}

// actionKeys opens an action from the menu with one key press. The menu
// shows each key beside its action; this map is the only place they are set.
var actionKeys = map[string]action{
	"1": actSeal,
	"2": actOpen,
	"3": actExtend,
	"4": actBypass,
	"5": actInfo,
	"6": actBench,
}

// menuKey is the key that opens act, or "" if none does.
func menuKey(act action) string {
	for k, a := range actionKeys {
		if a == act {
			return k
		}
	}
	return ""
}

// guess is the action the file given on the command line most likely wants:
// open for either file of a pair, which names the other; seal for any other
// file; with none, bench, which needs no file and shows what wicks take here.
func guess(file string) action {
	switch {
	case file == "":
		return actBench
	case strings.HasSuffix(file, store.WickSuffix), strings.HasSuffix(file, store.PayloadSuffix):
		return actOpen
	}
	return actSeal
}

// inputs holds what a form collects, as typed.
type inputs struct {
	File    string
	Alg     alg.ID
	Steps   string // N or a delay (seal); K or a delay (extend)
	Form    store.Form
	Out     string
	Key     string
	KeyOut  string
	Workers string // seal and extend; empty means every core
	GPU     bool   // GPU mode, from the start: it chooses the suggested algorithm
}

// args turns what a form collected into the arguments of the operation it
// asks for: an ops.SealArgs, ops.OpenArgs, ops.ExtendArgs or ops.BypassArgs,
// a file path (info) or an algorithm (bench). The form's validators have
// already accepted in.
func args(act action, in *inputs) any {
	path := func(s string) string { return expandHome(strings.TrimSpace(s)) }
	file, out, key, keyOut := path(in.File), path(in.Out), path(in.Key), path(in.KeyOut)
	n, d, _ := parseSteps(in.Steps)
	w, _ := strconv.Atoi(strings.TrimSpace(in.Workers)) // empty: 0, every core
	w = max(w, 0)                                       // -1, too
	a, _ := alg.Lookup(in.Alg)
	switch act {
	case actSeal:
		return ops.SealArgs{File: file, Alg: a, N: n, Delay: d, Form: in.Form, KeyOut: keyOut, Workers: w}
	case actOpen:
		return ops.OpenArgs{File: file, Out: out, KeyOut: keyOut}
	case actExtend:
		return ops.ExtendArgs{File: file, Add: n, Delay: d, Out: out, Workers: w}
	case actBypass:
		return ops.BypassArgs{File: file, Key: key, Out: out}
	case actInfo:
		return file
	}
	return a
}

// operation is the op that args describes.
func operation(act action, in *inputs) op {
	switch a := args(act, in).(type) {
	case ops.SealArgs:
		return func(ctx context.Context, env *ops.Env) (any, error) { return nil, env.Seal(ctx, a) }
	case ops.OpenArgs:
		return func(ctx context.Context, env *ops.Env) (any, error) { return nil, env.Open(ctx, a) }
	case ops.ExtendArgs:
		return func(ctx context.Context, env *ops.Env) (any, error) { return nil, env.Extend(ctx, a) }
	case ops.BypassArgs:
		return func(_ context.Context, env *ops.Env) (any, error) { return nil, env.Bypass(a) }
	case string:
		return func(context.Context, *ops.Env) (any, error) { return ops.Describe(a) }
	case alg.Alg:
		return func(ctx context.Context, env *ops.Env) (any, error) { return env.Bench(ctx, a) }
	}
	panic("tui: no operation for " + actions[act].name)
}
