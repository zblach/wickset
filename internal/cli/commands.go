package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"charm.land/lipgloss/v2"

	"chainlock/internal/ops"
	"chainlock/internal/store"
	"chainlock/internal/tui"
)

const delayHelp = `--delay is converted to steps using this machine's measured step time. The
real delay is hardware-relative: bench on the slowest legitimate solver, and
expect an attacker to be faster.`

type sealCmd struct {
	File    string    `arg:"" type:"existingfile" help:"Plaintext to lock."`
	Alg     algFlag   `help:"Algorithm id or name: ${algs}. Required with -n; with --delay, chosen by it if not given."`
	N       *int      `name:"n" short:"n" xor:"steps" placeholder:"N" help:"N >= 0: the solver performs N+1 sequential steps."`
	Delay   delayFlag `short:"d" xor:"steps" placeholder:"DELAY" help:"Instead of -n: a target delay on this machine, such as 8h, 3d, 2w, 6M (months; m is minutes), 1y or \"1w 3d\"."`
	Raw     bool      `xor:"form" help:"Write the lock as the bare SPEC.md object, with no header or digest."`
	Archive bool      `xor:"form,lockout,payloadout" help:"Write lock and payload together as FILE.chainlock.tar."`
	Lock    string    `xor:"lockout" type:"path" placeholder:"PATH" help:"Lock output (default FILE.lock)."`
	Payload string    `xor:"payloadout" type:"path" placeholder:"PATH" help:"Payload output (default FILE.payload)."`
	KeyOut  string    `placeholder:"PATH" help:"Also save the key, which opens the payload without solving ('-' for stdout)."`
	workersFlag
}

func (*sealCmd) Help() string {
	return "N is SPEC.md's N: the solver performs N+1 sequential steps (-n 0 is one step).\n\n" +
		"The lock file carries a digest and the payload names its lock, so damage or a\n" +
		"mixed-up pair is caught before solving (CONTAINER.md).\n\n" +
		"--key-out saves the lock's secret, so its holder can open the payload at once\n" +
		"with bypass, however far the lock is later extended. It is the whole delay in\n" +
		"one line: keep it apart from the lock and payload.\n\n" +
		"Without --alg, --delay chooses: 0x01 below a day, 0x02 (a step about 40×\n" +
		"as long, so a smaller lock) from a day up. -n counts steps of one\n" +
		"algorithm, so it needs --alg.\n\n" + delayHelp
}

// Validate requires one of -n and --delay, the xor tag forbidding both, and an
// algorithm with -n. (A required tag would do the first too, but kong would
// then list both flags as required in the synopsis.)
func (c *sealCmd) Validate() error {
	switch {
	case c.N == nil && c.Delay == 0:
		return errors.New("give -n or --delay")
	case c.N != nil && c.Alg.Alg == nil:
		return errors.New("-n needs --alg: N counts steps of one algorithm (or give --delay to choose one)")
	}
	return nil
}

func (c *sealCmd) Run(ctx context.Context, env *ops.Env) error {
	a := ops.SealArgs{
		File: c.File, Alg: c.Alg.Alg, Delay: time.Duration(c.Delay), Form: store.FormFile,
		Lock: c.Lock, Payload: c.Payload, KeyOut: c.KeyOut, Workers: c.Workers,
	}
	if c.N != nil {
		a.N = *c.N
	}
	switch {
	case c.Raw:
		a.Form = store.FormRaw
	case c.Archive:
		a.Form = store.FormArchive
	}
	return env.Seal(ctx, a)
}

type openCmd struct {
	File    string `arg:"" name:"lock" type:"existingfile" help:"FILE.lock, or FILE.chainlock.tar with its payload inside."`
	Payload string `type:"existingfile" placeholder:"PATH" help:"Payload to decrypt (default FILE.payload; not with an archive)."`
	Out     string `type:"path" placeholder:"PATH" help:"Plaintext output, replaced if present (default FILE, which must not exist)."`
	KeyOut  string `placeholder:"PATH" help:"Also save the key that solving recovers, to reopen later with bypass ('-' for stdout)."`
}

func (c *openCmd) Run(ctx context.Context, env *ops.Env) error {
	return env.Open(ctx, ops.OpenArgs{File: c.File, Payload: c.Payload, Out: c.Out, KeyOut: c.KeyOut})
}

type bypassCmd struct {
	File    string `arg:"" name:"file" type:"existingfile" help:"FILE.payload, or a lock (FILE.lock, FILE.chainlock.tar) to take the payload from."`
	Key     string `required:"" placeholder:"PATH" help:"Key file from seal or open --key-out; '-' reads standard input."`
	Payload string `type:"existingfile" placeholder:"PATH" help:"Payload, when FILE is a lock (default FILE.payload; not with an archive)."`
	Out     string `type:"path" placeholder:"PATH" help:"Plaintext output, replaced if present (default FILE, which must not exist)."`
}

func (*bypassCmd) Help() string {
	return "Decrypts with a key saved by seal --key-out or open --key-out, without solving,\n" +
		"however far the lock has since been extended. Give the payload alone, or a lock\n" +
		"(whose pairing with the payload is then checked too).\n\n" +
		"The key is read from a file or standard input, never from the command line,\n" +
		"where it would land in shell history and process listings."
}

func (c *bypassCmd) Run(env *ops.Env) error {
	return env.Bypass(ops.BypassArgs{File: c.File, Key: c.Key, Payload: c.Payload, Out: c.Out})
}

type extendCmd struct {
	File  string    `arg:"" name:"lock" type:"existingfile" help:"Lock to extend, in any form; it is written back in the same form."`
	Add   int       `short:"a" xor:"steps" placeholder:"K" help:"K >= 1 sequential steps to add."`
	Delay delayFlag `short:"d" xor:"steps" placeholder:"DELAY" help:"Instead of --add: delay to add on this machine, as for seal: 2h, 1w, 1M."`
	Out   string    `type:"path" placeholder:"PATH" help:"Write the extended lock here, a new file, instead of replacing FILE.lock."`
	workersFlag
}

func (*extendCmd) Help() string {
	return "--add K adds K steps, so N becomes N+K. Anyone holding a lock can extend it\n" +
		"before passing it on, and those downstream must solve the longer chain. Anyone\n" +
		"who kept the shorter version can still open that in its original steps.\n\n" +
		"Replacing FILE.lock in place does not scrub the shorter version from disk,\n" +
		"snapshots, backups or synced folders. Keep it out of downstream reach.\n\n" + delayHelp
}

// Validate requires one of --add and --delay, as sealCmd.Validate.
func (c *extendCmd) Validate() error {
	if c.Add == 0 && c.Delay == 0 {
		return errors.New("give --add or --delay")
	}
	return nil
}

func (c *extendCmd) Run(ctx context.Context, env *ops.Env) error {
	return env.Extend(ctx, ops.ExtendArgs{File: c.File, Add: c.Add, Delay: time.Duration(c.Delay), Out: c.Out, Workers: c.Workers})
}

type infoCmd struct {
	File string `arg:"" name:"lock" type:"existingfile" help:"Lock to describe, in any form."`
}

// Run describes the lock and checks its payload, as open would before
// solving. A payload that fails the check fails the command.
func (c *infoCmd) Run() error {
	in, err := ops.Describe(c.File)
	if err != nil {
		return err
	}
	payload := "pairs with this lock, digest ok"
	switch {
	case in.PayloadMissing():
		payload = "not found"
	case in.PayloadErr != nil:
		payload = in.PayloadErr.Error()
	}
	lipgloss.Println(tui.Columns(tui.KeyColumn).Rows(
		[]string{"alg", fmt.Sprintf("%v (B = %d)", in.Alg.ID(), in.Alg.BlockSize())},
		[]string{"N", fmt.Sprintf("%d (%d sequential steps)", in.N, in.N+1)},
		[]string{"object", ops.Bytes(int64(in.Size))},
		[]string{"form", in.Form.String()},
		[]string{"payload", in.PayloadWhere + ": " + payload},
	))
	if in.PayloadMissing() {
		return nil
	}
	return in.PayloadErr
}

type benchCmd struct {
	Alg algFlag `default:"1" help:"Algorithm id or name: ${algs}."`
}

func (c *benchCmd) Run(ctx context.Context, env *ops.Env) error {
	b, err := env.Bench(ctx, c.Alg.Alg)
	if err != nil {
		return err
	}
	fmt.Printf("%v: %v a step on this machine (one core, fastest of 3)\n\n", b.Alg.ID(), b.Step.Round(time.Millisecond))
	lipgloss.Println(tui.BenchTable(b))
	fmt.Printf("\nsealing on all %d cores; they share memory bandwidth, so it takes longer\n", b.Cores)
	return nil
}

type tuiCmd struct {
	File string `arg:"" optional:"" help:"File to start with: a plaintext to seal, or a lock or payload to open."`
}

func (c *tuiCmd) Run(ctx context.Context) error {
	return tui.Run(ctx, c.File)
}
