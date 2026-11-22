// Package cli is wickset's command line: kong parses the arguments into a
// command struct, whose Run hands them to package ops and reports on
// standard error. The tui command starts package tui instead.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/willabides/kongplete"

	"wickset/internal/ops"
)

// cli is the command tree. Each command is a struct in commands.go whose
// fields are its arguments and flags and whose Run method executes it. The
// descriptions match the TUI's menu, with the file names added.
type cli struct {
	Seal   sealCmd   `cmd:"" help:"Seal a file so it opens only after a delay: FILE.wick and FILE.payload."`
	Open   openCmd   `cmd:"" help:"Burn a wick and decrypt its file into FILE."`
	Extend extendCmd `cmd:"" help:"Make a wick take longer to burn, in place, without its key."`
	Bypass bypassCmd `cmd:"" help:"Open a sealed file at once with its saved key."`
	Info   infoCmd   `cmd:"" help:"Show a wick's details and check its files, without burning it."`
	Bench  benchCmd  `cmd:"" help:"Time this machine to see how long wicks take."`
	TUI    tuiCmd    `cmd:"" name:"tui" help:"Do any of the above interactively."`

	Completion completionCmd `cmd:"" help:"Print what makes a shell complete wickset's commands and files."`

	Version versionFlag `help:"Print the version and what this build can do, and exit."`

	CPU       bool       `name:"cpu" help:"Seal and extend on CPU workers. Without it they run on the GPU (macOS: Metal) where it is faster for the run, one step of each batch checked on the CPU; a few steps are faster on the CPU."`
	GPUMemory budgetFlag `name:"gpu-memory" placeholder:"SIZE" help:"GPU memory Argon2id batches may hold: a size such as 8G, or a share such as 25% (default 50% of what the GPU may use)."`
}

// exitUsage is the conventional status for a bad invocation; kong's own is 80.
const exitUsage = 2

// Main runs the command line in os.Args and exits.
func Main() {
	if ops.TestBuild() {
		fmt.Fprintln(os.Stderr, ops.TestBuildWarning)
	}
	// Ctrl-C, or a kill or service manager's TERM, stops the work mid-step.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	term := newTerminal()
	env := term.env()
	var c cli
	parser := kong.Must(&c,
		kong.Name("wickset"),
		kong.Description("Encrypt a file so it can be opened only after a delay (SPEC.md)."),
		kong.Vars{"algs": algList()},
		kong.UsageOnError(),
		kong.NamedMapper("outfile", outputMapper(false)),
		kong.NamedMapper("keyfile", outputMapper(true)),
		kong.BindTo(ctx, (*context.Context)(nil)),
		kong.Bind(env),
		kong.Exit(func(code int) {
			stop()
			if code == 80 {
				code = exitUsage
			}
			os.Exit(code)
		}),
	)
	// A shell asking for completions (completionCmd) is answered here, and
	// the process exits; any other run goes on.
	kongplete.Complete(parser, kongplete.WithPredictors(predictors()))
	k, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(unprefixed(err))
	// The GPU is the program's, for whatever it does: used wherever there is
	// one, unless asked for the CPU.
	env.GPU = !c.CPU && ops.GPUName() != ""
	env.GPUMemory = ops.Budget(c.GPUMemory)
	err = k.Run()
	term.close() // a cancelled run leaves its line open
	k.FatalIfErrorf(unprefixed(err))
}

// unprefixed is err without the "wickset: " its package errors carry for a
// library's callers: the CLI already says whose error it is. It unwraps to
// err, so kong still finds a usage error in it.
func unprefixed(err error) error {
	if err == nil {
		return nil
	}
	return prefixless{err}
}

type prefixless struct{ error }

func (p prefixless) Error() string { return strings.ReplaceAll(p.error.Error(), "wickset: ", "") }
func (p prefixless) Unwrap() error { return p.error }
