package ops

import (
	"fmt"
	"io"
	"sync"

	"github.com/zblach/wickset/alg"
)

// Env is how an operation reaches its front end. Every field may be nil.
type Env struct {
	// Note receives the operation's commentary, a line at a time.
	Note func(Note)
	// Events receives the work as it goes (Event), one at a time; Run
	// keeps what they tell. It should return promptly: the workers wait.
	Events func(Event)
	// Stdin and Stdout serve a key path of "-". A front end that owns the
	// terminal leaves them nil, and "-" is then refused.
	Stdin  io.Reader
	Stdout io.Writer
	// GPU lets seal and extend compute on the GPU (GPUName) instead of the
	// workers: chosen when the program starts, for all it does, and set
	// wherever there is a GPU unless the user asks for the CPU. A run goes to
	// the GPU only where it would finish sooner there (place); where the GPU
	// turns out slower or unable, the workers do the work, with a note.
	GPU bool
	// GPUMemory is how much of the GPU's memory a run's Argon2id batches
	// may hold; the zero Budget is DefaultShare of it.
	GPUMemory Budget

	mu sync.Mutex // serializes Events
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

// TestBuild reports a binary built with -tags wickset_testalgs, whose
// private-use algorithms make wicks with no real delay.
func TestBuild() bool {
	for _, a := range alg.All() {
		if a.ID().IsPrivateUse() {
			return true
		}
	}
	return false
}

// TestBuildWarning is what a front end shows when TestBuild is true.
const TestBuildWarning = "warning: test build (wickset_testalgs): private-use algorithms are enabled and their wicks have no real delay"

func (e *Env) note(kind NoteKind, format string, args ...any) {
	if e.Note != nil {
		e.Note(Note{kind, fmt.Sprintf(format, args...)})
	}
}
