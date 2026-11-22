package cli

import (
	"strings"
	"testing"

	"chainlock/chain"
	"chainlock/internal/ops"
)

// events is a solve of two steps, as ops reports one.
func events() []ops.Event {
	step := func(kind chain.EventKind, first int) ops.Event {
		return ops.Event{Stage: "solving", Kind: ops.StepEvent, Step: chain.Event{Kind: kind, First: first, N: 1}}
	}
	return []ops.Event{
		{Stage: "solving", Kind: ops.StageBegan, Total: 2},
		step(chain.Began, 0),
		{Stage: "solving", Kind: ops.StepEvent, Step: chain.Event{Kind: chain.Partway, N: 1, Part: 1, OfParts: 2}},
		step(chain.Finished, 0),
		step(chain.Began, 1),
		step(chain.Finished, 1),
		step(chain.Idle, 0),
	}
}

// TestTerminalLine: on a terminal a run keeps one line, a note interrupts
// it on a line of its own, and the run's end leaves the line finished.
func TestTerminalLine(t *testing.T) {
	var buf strings.Builder
	term := &terminal{w: &buf, tty: true}
	for i, e := range events() {
		if i == 2 {
			term.note(ops.Note{Kind: ops.Warning, Text: "careful"})
		}
		term.event(e)
	}
	out := buf.String()
	for _, s := range []string{"\r\x1b[Kwarning: careful\n", "solving 0/2 steps", "solving 2/2 steps (100.00%)"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%q", s, out)
		}
	}
	if !strings.HasSuffix(out, "\n") || term.stop != nil {
		t.Errorf("the run's line was left open:\n%q", out)
	}
	term.close() // nothing on the line: prints nothing
	if buf.String() != out {
		t.Errorf("close after the run printed %q", buf.String()[len(out):])
	}
}

// TestPlainLines: off a terminal, a line per finished step, for logs, and
// nothing for a step partway.
func TestPlainLines(t *testing.T) {
	var buf strings.Builder
	term := &terminal{w: &buf}
	for _, e := range events() {
		term.event(e)
	}
	if got := buf.String(); got != "solving (1/2)\nsolving (2/2)\n" {
		t.Errorf("got %q", got)
	}
}
