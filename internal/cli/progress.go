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

	mu  sync.Mutex
	run *run // the run on the line, if any
}

// run is one labelled run of steps: measuring, timing, sealing, solving or
// extending.
type run struct {
	label       string
	start       time.Time
	done, total int
	workers     int           // the most seen at once; a solve or a timing is one
	stepStart   time.Time     // when the one worker's step under way began
	eta         time.Duration // as of the last finished step, as the TUI keeps it
	stop        chan struct{} // ends the redraws
}

func newTerminal() *terminal {
	fi, err := os.Stderr.Stat()
	return &terminal{w: os.Stderr, tty: err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

// env reports on the process's own streams: notes and progress on standard
// error, and a key given as "-" on standard input or output.
func (t *terminal) env() *ops.Env {
	e := &ops.Env{Note: t.note, Progress: t.progress, Stdin: os.Stdin, Stdout: os.Stdout}
	if t.tty {
		e.Activity = t.activity
	}
	return e
}

// note prints a note on a line of its own, then the run's line again below it.
func (t *terminal) note(n ops.Note) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.run != nil {
		fmt.Fprint(t.w, "\r\x1b[K")
	}
	fmt.Fprintln(t.w, n)
	if t.run != nil {
		t.draw()
	}
}

func (t *terminal) progress(label string) chain.Progress {
	if !t.tty {
		return func(done, total int) { fmt.Fprintf(t.w, "%s (%d/%d)\n", label, done, total) }
	}
	return func(done, total int) {
		t.mu.Lock()
		defer t.mu.Unlock()
		r := t.runFor(label, total)
		r.done = done
		if el := time.Since(r.start); done > 0 {
			r.eta = el / time.Duration(done) * time.Duration(total-done)
		}
		if done == total {
			t.end()
		}
	}
}

func (t *terminal) activity(label string, total int) chain.Activity {
	t.mu.Lock()
	r := t.runFor(label, total)
	t.mu.Unlock()
	return func(w, i int) {
		t.mu.Lock()
		defer t.mu.Unlock()
		r.workers = max(r.workers, w+1)
		if i >= 0 {
			r.stepStart = time.Now()
		}
	}
}

// runFor is the run named label on the line, starting it, and its redraws,
// if another or none is there. Called with t.mu held.
func (t *terminal) runFor(label string, total int) *run {
	if r := t.run; r != nil && r.label == label {
		return r
	}
	t.end()
	r := &run{label: label, start: time.Now(), total: total, stop: make(chan struct{})}
	t.run = r
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-tick.C:
				t.mu.Lock()
				if t.run == r {
					t.draw()
				}
				t.mu.Unlock()
			}
		}
	}()
	t.draw()
	return r
}

// end finishes the run on the line, if any: drawn a last time, and left
// above whatever is printed next. Called with t.mu held.
func (t *terminal) end() {
	if t.run == nil {
		return
	}
	t.draw()
	fmt.Fprintln(t.w)
	close(t.run.stop)
	t.run = nil
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
	line := fmt.Sprintf("%s %d/%d steps (%.2f%%) · elapsed %s", r.label, r.done, r.total,
		100*float64(r.done)/float64(max(r.total, 1)), ops.Span(time.Since(r.start)))
	switch {
	case r.workers > 1:
		line += fmt.Sprintf(" · %d workers", r.workers)
	case !r.stepStart.IsZero() && r.done < r.total:
		line += fmt.Sprintf(" · step %d: %.1fs", r.done+1, time.Since(r.stepStart).Seconds())
	}
	if r.done > 0 && r.done < r.total {
		line += " · eta " + ops.Span(r.eta)
	}
	fmt.Fprint(t.w, "\r\x1b[K"+line)
}
