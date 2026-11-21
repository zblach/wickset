package cli

import (
	"strings"
	"testing"

	"chainlock/internal/ops"
)

// TestTerminalLine: on a terminal a run keeps one line, a note interrupts
// it on a line of its own, and the run's end leaves the line finished.
func TestTerminalLine(t *testing.T) {
	var buf strings.Builder
	term := &terminal{w: &buf, tty: true}
	progress, activity := term.progress("solving"), term.activity("solving", 2)
	activity(0, 0)
	term.note(ops.Note{Kind: ops.Warning, Text: "careful"})
	progress(1, 2)
	activity(0, 1)
	progress(2, 2)
	out := buf.String()
	for _, s := range []string{"\r\x1b[Kwarning: careful\n", "solving 0/2 steps", "solving 2/2 steps (100.00%)"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%q", s, out)
		}
	}
	if !strings.HasSuffix(out, "\n") || term.run != nil {
		t.Errorf("the run's line was left open:\n%q", out)
	}
	term.close() // nothing on the line: prints nothing
	if buf.String() != out {
		t.Errorf("close after the run printed %q", buf.String()[len(out):])
	}
}

// TestPlainLines: off a terminal, a line per finished step, for logs.
func TestPlainLines(t *testing.T) {
	var buf strings.Builder
	term := &terminal{w: &buf}
	if term.env().Activity != nil {
		t.Error("activity off a terminal")
	}
	p := term.progress("sealing")
	p(1, 2)
	p(2, 2)
	if got := buf.String(); got != "sealing (1/2)\nsealing (2/2)\n" {
		t.Errorf("got %q", got)
	}
}
