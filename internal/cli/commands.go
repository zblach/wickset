package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"wickset/internal/ops"
	"wickset/internal/store"
	"wickset/internal/tui"
)

const delayHelp = `--delay is converted to steps using this machine's measured step time. The
real delay is hardware-relative: bench on the slowest legitimate solver, and
expect an attacker to be faster.`

type sealCmd struct {
	File    string    `arg:"" type:"existingfile" predictor:"file" help:"Plaintext to seal."`
	Alg     algFlag   `predictor:"alg" help:"Algorithm id or name: ${algs}. Required with -n; with --delay, chosen by it if not given."`
	N       *int      `name:"n" short:"n" xor:"steps" placeholder:"N" help:"N >= 0: the solver performs N+1 sequential steps."`
	Delay   delayFlag `short:"d" xor:"steps" placeholder:"DELAY" help:"Instead of -n: a target delay on this machine, such as 8h, 3d, 2w, 6M (months; m is minutes), 1y or \"1w 3d\"."`
	Raw     bool      `help:"Write the bare SPEC.md wick, with no header or digest."`
	Wick    string    `type:"outfile" predictor:"file" placeholder:"PATH" help:"Wick output (default FILE.wick)."`
	Payload string    `type:"outfile" predictor:"file" placeholder:"PATH" help:"Payload output (default FILE.payload)."`
	KeyOut  string    `type:"keyfile" predictor:"file" placeholder:"PATH" help:"Also save the key, which opens the payload without solving ('-' for stdout)."`
	workersFlag
}

func (*sealCmd) Help() string {
	return "N is SPEC.md's N: the solver performs N+1 sequential steps (-n 0 is one step).\n\n" +
		"The wick file carries a digest and the payload names its wick, so damage or a\n" +
		"mixed-up pair is caught before burning (CONTAINER.md).\n\n" +
		"--key-out saves the wick's secret, so its holder can open the payload at once\n" +
		"with bypass, however far the wick is later extended. It is the whole delay in\n" +
		"one line: keep it apart from the wick and payload.\n\n" +
		"Each family has a short step and a long one (a smaller wick for the same\n" +
		"delay): 0x01/0x02 Argon2id, memory-hard; 0x03/0x04 iterated SHA-256, which\n" +
		"seals far faster on a GPU (docs/parameters.md). Without --alg, --delay\n" +
		"chooses the short step below a day and the long one from a day up: SHA-256\n" +
		"on the GPU, Argon2id on the CPU (--cpu, or no GPU). -n counts steps of one\n" +
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
		Wick: c.Wick, Payload: c.Payload, KeyOut: c.KeyOut, Workers: c.Workers,
	}
	if c.N != nil {
		a.N = *c.N
	}
	if c.Raw {
		a.Form = store.FormRaw
	}
	return env.Seal(ctx, a)
}

type openCmd struct {
	File    string `arg:"" name:"file" type:"existingfile" predictor:"either" help:"FILE.wick or FILE.payload: either names the pair."`
	Wick    string `type:"existingfile" predictor:"wick" placeholder:"PATH" help:"Wick to burn, when FILE is a payload (default FILE.wick)."`
	Payload string `type:"existingfile" predictor:"payload" placeholder:"PATH" help:"Payload to decrypt, when FILE is a wick (default FILE.payload)."`
	Out     string `type:"outfile" predictor:"file" placeholder:"PATH" help:"Plaintext output, replaced if present (default FILE, which must not exist); /dev/null checks it opens."`
	KeyOut  string `type:"keyfile" predictor:"file" placeholder:"PATH" help:"Also save the key that solving recovers, to reopen later with bypass ('-' for stdout)."`
}

// Validate names the pair, so a missing wick is a usage error before any
// work; ops checks it again, for every front end.
func (c *openCmd) Validate() error {
	_, _, err := store.Pair(c.File, c.Wick, c.Payload)
	return err
}

func (c *openCmd) Run(ctx context.Context, env *ops.Env) error {
	return env.Open(ctx, ops.OpenArgs{File: c.File, Wick: c.Wick, Payload: c.Payload, Out: c.Out, KeyOut: c.KeyOut})
}

type bypassCmd struct {
	File    string `arg:"" name:"file" type:"existingfile" predictor:"either" help:"FILE.payload, or its wick FILE.wick to find the payload by."`
	Key     string `required:"" predictor:"key" placeholder:"PATH" help:"Key file from seal or open --key-out; '-' reads standard input."`
	Payload string `type:"existingfile" predictor:"payload" placeholder:"PATH" help:"Payload, when FILE is a wick (default FILE.payload)."`
	Out     string `type:"outfile" predictor:"file" placeholder:"PATH" help:"Plaintext output, replaced if present (default FILE, which must not exist)."`
}

func (*bypassCmd) Help() string {
	return "Decrypts with a key saved by seal --key-out or open --key-out, without solving,\n" +
		"however far the wick has since been extended. Give the payload alone, or a wick\n" +
		"(whose pairing with the payload is then checked too).\n\n" +
		"The key is read from a file or standard input, never from the command line,\n" +
		"where it would land in shell history and process listings."
}

func (c *bypassCmd) Run(env *ops.Env) error {
	return env.Bypass(ops.BypassArgs{File: c.File, Key: c.Key, Payload: c.Payload, Out: c.Out})
}

type extendCmd struct {
	File  string    `arg:"" name:"wick" type:"existingfile" predictor:"wick" help:"Wick to extend, in any form; it is written back in the same form."`
	Add   int       `short:"a" xor:"steps" placeholder:"K" help:"K >= 1 sequential steps to add."`
	Delay delayFlag `short:"d" xor:"steps" placeholder:"DELAY" help:"Instead of --add: delay to add on this machine, as for seal: 2h, 1w, 1M."`
	Out   string    `type:"outfile" predictor:"file" placeholder:"PATH" help:"Write the extended wick here, a new file, instead of replacing FILE.wick."`
	workersFlag
}

func (*extendCmd) Help() string {
	return "--add K adds K steps, so N becomes N+K. Anyone holding a wick can extend it\n" +
		"before passing it on, and those downstream must burn the longer wick. Anyone\n" +
		"who kept the shorter version can still open that in its original steps.\n\n" +
		"Replacing FILE.wick in place does not scrub the shorter version from disk,\n" +
		"snapshots, backups or synced folders. Keep it out of downstream reach.\n\n" + delayHelp
}

// Validate requires one of --add and --delay, as sealCmd.Validate.
func (c *extendCmd) Validate() error {
	if c.Add == 0 && c.Delay == 0 {
		return errors.New("give --add or --delay")
	}
	return store.NotPayload(c.File, "extend")
}

func (c *extendCmd) Run(ctx context.Context, env *ops.Env) error {
	return env.Extend(ctx, ops.ExtendArgs{File: c.File, Add: c.Add, Delay: time.Duration(c.Delay), Out: c.Out, Workers: c.Workers})
}

type infoCmd struct {
	File string `arg:"" name:"file" type:"existingfile" predictor:"either" help:"Wick to describe, in any form, or its payload."`
}

// Validate names the pair before anything is read in full.
func (c *infoCmd) Validate() error {
	_, _, err := store.Pair(c.File, "", "")
	return err
}

// Run describes the wick and checks its payload, as open would before
// burning. A payload that fails the check fails the command.
func (c *infoCmd) Run() error {
	in, err := ops.Describe(c.File)
	if err != nil {
		return err
	}
	payload := "pairs with this wick, digest ok"
	switch {
	case in.PayloadMissing():
		payload = "not found"
	case in.PayloadErr != nil:
		payload = unprefixed(in.PayloadErr).Error()
	}
	lipgloss.Println(tui.Columns(tui.KeyColumn).Rows(
		[]string{"alg", fmt.Sprintf("%v (B = %d)", in.Alg.ID(), in.Alg.BlockSize())},
		[]string{"N", fmt.Sprintf("%d (%d sequential steps)", in.N, in.N+1)},
		[]string{"wick", ops.Bytes(int64(in.Size))},
		[]string{"form", in.Form.String()},
		[]string{"payload", in.PayloadWhere + ": " + payload},
	))
	if in.PayloadMissing() {
		return nil
	}
	return in.PayloadErr
}

type benchCmd struct {
	Alg    algFlag `default:"1" predictor:"alg" help:"Algorithm id or name: ${algs}."`
	CSV    bool    `name:"csv" xor:"out" help:"Print a row for benchmarks/scores.csv, with its header, instead of the table."`
	Submit bool    `xor:"out" help:"Bench every algorithm, on the CPU and on the GPU if there is one (several minutes), and print the rows with a link that proposes them as a pull request."`
}

func (*benchCmd) Help() string {
	return "--submit adds this machine to benchmarks/scores.csv: it prints the rows, then a\n" +
		"link to GitHub's new-file page with them filled in. Nothing is sent unless\n" +
		"you follow it; GitHub then makes you a fork and opens the pull request.\n" +
		"Run it with nothing else heavy going on, and on mains power."
}

func (c *benchCmd) Run(ctx context.Context, env *ops.Env) error {
	if c.Submit {
		bs, err := benchAll(ctx, env)
		if err != nil {
			return err
		}
		var rows strings.Builder
		if err := writeBenchCSV(&rows, bs...); err != nil {
			return err
		}
		fmt.Printf("%s\nTo submit these rows as a pull request, open:\n\n%s\n", rows.String(), submitLink(rows.String()))
		return nil
	}
	b, err := env.Bench(ctx, c.Alg.Alg)
	if err != nil {
		return err
	}
	if c.CSV {
		return writeBenchCSV(os.Stdout, b)
	}
	fmt.Printf("%v: %v a step on one core %s\n\n", b.Alg.ID(), b.Step.Round(time.Millisecond), b.StepNote())
	lipgloss.Println(tui.BenchTable(b))
	fmt.Printf("\n%s\n%s\n", b.SpeedUpLine(), b.Sealing())
	return nil
}

type tuiCmd struct {
	File string `arg:"" optional:"" predictor:"file" help:"File to start with: a plaintext to seal, or a wick or payload to open."`
}

func (c *tuiCmd) Run(ctx context.Context, env *ops.Env) error {
	return tui.Run(ctx, c.File, env.GPU, env.GPUMemory)
}
