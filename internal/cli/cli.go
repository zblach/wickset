// Package cli is wickset's command line: kong parses the arguments into a
// command struct, whose Run hands them to package ops and reports on
// standard error. The tui command starts package tui instead.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"

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

	GPU bool `name:"gpu" help:"Seal and extend on the GPU (macOS: Metal) instead of CPU workers; one step of each batch is checked on the CPU."`
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
	k := kong.Parse(&c,
		kong.Name("wickset"),
		kong.Description("Encrypt a file so it can be opened only after a delay (SPEC.md)."),
		kong.Vars{"algs": algList()},
		kong.UsageOnError(),
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
	// The GPU is the program's, for whatever it does: refused at once where
	// there is none, not when a seal reaches it.
	if c.GPU && ops.GPUName() == "" {
		k.Fatalf("--gpu: no GPU in this build or on this machine")
	}
	env.GPU = c.GPU
	err := k.Run()
	term.close() // a cancelled run leaves its line open
	k.FatalIfErrorf(err)
}
