package ops

import (
	"fmt"
	"io"

	"chainlock/alg"
	"chainlock/chain"
)

// Env is how an operation reaches its front end. Every field may be nil.
type Env struct {
	// Note receives the operation's commentary, a line at a time.
	Note func(Note)
	// Progress returns the progress callback for a run named label
	// ("sealing", "solving", "extending").
	Progress func(label string) chain.Progress
	// Activity returns the per-worker callback for the parallel run named
	// label, which makes total evaluations (sealing and extending only).
	Activity func(label string, total int) chain.Activity
	// Stdin and Stdout serve a key path of "-". A front end that owns the
	// terminal leaves them nil, and "-" is then refused.
	Stdin  io.Reader
	Stdout io.Writer
	// GPU has seal and extend compute on the GPU (GPUName) instead of the
	// workers: chosen when the program starts, for all it does.
	GPU bool
}

// A Note is one line of an operation's commentary, of one Kind, so a front
// end can tell what happened from how and from what needs attention.
type Note struct {
	Kind NoteKind
	Text string
}

// NoteKind is what a Note tells.
type NoteKind int

const (
	Detail  NoteKind = iota // how it went: what was chosen, measured or estimated
	Warning                 // what the user may want to change, or to know
	Wrote                   // a file it wrote; the outcome
)

// String is the note as a line of plain text: a warning says so.
func (n Note) String() string {
	if n.Kind == Warning {
		return "warning: " + n.Text
	}
	return n.Text
}

// TestBuild reports a binary built with -tags chainlock_testalgs, whose
// private-use algorithms make locks with no real delay.
func TestBuild() bool {
	for _, a := range alg.All() {
		if a.ID().IsPrivateUse() {
			return true
		}
	}
	return false
}

// TestBuildWarning is what a front end shows when TestBuild is true.
const TestBuildWarning = "warning: test build (chainlock_testalgs): private-use algorithms are enabled and their locks have no real delay"

func (e *Env) note(kind NoteKind, format string, args ...any) {
	if e.Note != nil {
		e.Note(Note{kind, fmt.Sprintf(format, args...)})
	}
}

func (e *Env) progress(label string) chain.Progress {
	if e.Progress == nil {
		return nil
	}
	return e.Progress(label)
}

func (e *Env) activity(label string, total int) chain.Activity {
	if e.Activity == nil {
		return nil
	}
	return e.Activity(label, total)
}

// solveProgress is the progress callback for a solve of steps sequential
// steps. A solve is one worker, so it is reported as one to Activity too,
// moving to each next step as the last finishes: a step can take ~16 s, and
// this shows it under way from the outset.
func (e *Env) solveProgress(steps int) chain.Progress {
	progress, activity := e.progress("solving"), e.activity("solving", steps)
	if activity == nil {
		return progress
	}
	activity(0, 0, 1)
	return func(done, total int) {
		if progress != nil {
			progress(done, total)
		}
		if done < total {
			activity(0, done, 1)
		} else {
			activity(0, -1, 0)
		}
	}
}
