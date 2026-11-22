package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"chainlock/chain"
	"chainlock/internal/ops"
)

// terminal reports an operation on standard error. Off a terminal (a log, a
// pipe) it prints a line per finished step. On one it keeps the run under
// way on one line, rewritten twice a second, so that a step of many seconds
// shows as moving: the count, the step in flight or the workers, the time
// elapsed and the estimate, as the TUI's run screen does.
type terminal struct {
	w   io.Writer
	tty bool

	mu   sync.Mutex
	run  ops.Run       // the run under way, as its events tell it
	stop chan struct{} // ends its line's redraws; nil with no line
}

func newTerminal() *terminal {
	fi, err := os.Stderr.Stat()
	return &terminal{w: os.Stderr, tty: err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

// env reports on the process's own streams: notes and progress on standard
// error, and a key given as "-" on standard input or output.
func (t *terminal) env() *ops.Env {
	return &ops.Env{Note: t.note, Events: t.event, Stdin: os.Stdin, Stdout: os.Stdout}
}

// note prints a note on a line of its own, then the run's line again below it.
func (t *terminal) note(n ops.Note) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stop != nil {
		fmt.Fprint(t.w, "\r\x1b[K")
	}
	fmt.Fprintln(t.w, n)
	if t.stop != nil {
		t.draw()
	}
}

func (t *terminal) event(e ops.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e.Kind == ops.StageBegan {
		t.end()
	}
	t.run = t.run.Apply(e)
	switch {
	case !t.tty:
		// A line per finished step; nothing partway, which comes many times
		// a second.
		if e.Kind == ops.StepEvent && e.Step.Kind == chain.Finished {
			fmt.Fprintf(t.w, "%s (%d/%d)\n", t.run.Stage, t.run.Done, t.run.Total)
		}
	case e.Kind == ops.StageBegan:
		t.begin()
	case t.run.Done == t.run.Total && e.Step.Kind == chain.Finished:
		t.end()
	}
}

// begin puts the run on the line, redrawn until end. Called with t.mu held.
func (t *terminal) begin() {
	stop := make(chan struct{})
	t.stop = stop
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				t.mu.Lock()
				if t.stop == stop {
					t.draw()
				}
				t.mu.Unlock()
			}
		}
	}()
	t.draw()
}

// end finishes the run on the line, if any: drawn a last time, and left
// above whatever is printed next. Called with t.mu held.
func (t *terminal) end() {
	if t.stop == nil {
		return
	}
	t.draw()
	fmt.Fprintln(t.w)
	close(t.stop)
	t.stop = nil
}

// close ends the line before the process prints its result or error.
func (t *terminal) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.end()
}

// draw rewrites the line. Called with t.mu held.
func (t *terminal) draw() {
	r := t.run
	line := fmt.Sprintf("%s %d/%d steps (%.2f%%) · elapsed %s", r.Stage, r.Done, r.Total,
		100*r.Fraction(), ops.Span(time.Since(r.Start)))
	switch {
	case r.Batch > 0:
		line += fmt.Sprintf(" · GPU, batches of %d", r.Batch)
	case len(r.Workers) > 1:
		line += fmt.Sprintf(" · %d workers", len(r.Workers))
	case len(r.Workers) == 1 && r.Workers[0].First >= 0:
		line += fmt.Sprintf(" · step %d: %.1fs", r.Workers[0].First+1, time.Since(r.Workers[0].Since).Seconds())
	}
	if r.Done > 0 && r.Done < r.Total {
		line += " · eta " + ops.Span(r.ETA)
	}
	fmt.Fprint(t.w, "\r\x1b[K"+line)
}
