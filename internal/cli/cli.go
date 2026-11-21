// Package cli is chainlock's command line: kong parses the arguments into a
// command struct, whose Run hands them to package ops and reports on
// standard error. The tui command starts package tui instead.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/alecthomas/kong"

	"chainlock/internal/ops"
)

// cli is the command tree. Each command is a struct in commands.go whose
// fields are its arguments and flags and whose Run method executes it. The
// descriptions match the TUI's menu, with the file names added.
type cli struct {
	Seal   sealCmd   `cmd:"" help:"Lock a file so it opens only after a delay: FILE.lock and FILE.payload."`
	Open   openCmd   `cmd:"" help:"Wait out a lock and decrypt its file into FILE."`
	Extend extendCmd `cmd:"" help:"Make a lock take longer to open, in place, without its key."`
	Bypass bypassCmd `cmd:"" help:"Open a locked file at once with its saved key."`
	Info   infoCmd   `cmd:"" help:"Show a lock's details and check its files, without solving."`
	Bench  benchCmd  `cmd:"" help:"Time this machine to see how long locks take."`
	TUI    tuiCmd    `cmd:"" name:"tui" help:"Do any of the above interactively."`
}

// exitUsage is the conventional status for a bad invocation; kong's own is 80.
const exitUsage = 2

// Main runs the command line in os.Args and exits.
func Main() {
	if ops.TestBuild() {
		fmt.Fprintln(os.Stderr, ops.TestBuildWarning)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	term := newTerminal()
	k := kong.Parse(&cli{},
		kong.Name("chainlock"),
		kong.Description("Encrypt a file so it can be opened only after a delay (SPEC.md)."),
		kong.Vars{"algs": algList()},
		kong.UsageOnError(),
		kong.BindTo(ctx, (*context.Context)(nil)),
		kong.Bind(term.env()),
		kong.Exit(func(code int) {
			stop()
			if code == 80 {
				code = exitUsage
			}
			os.Exit(code)
		}),
	)
	err := k.Run()
	term.close() // a cancelled run leaves its line open
	k.FatalIfErrorf(err)
}
