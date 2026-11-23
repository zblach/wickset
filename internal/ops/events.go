package ops

import (
	"slices"
	"time"

	"github.com/zblach/wickset/wick"
)

// An Event is one thing an operation's work did, stamped with when it did
// it: all a front end hears of the work under way. The work comes as runs of
// steps, one after another, each named by its Stage: "measuring", "measuring
// the GPU", "timing one step", "timing 10 at once", "sealing", "solving",
// "extending".
type Event struct {
	At    time.Time
	Stage string
	Kind  EventKind
	// StageBegan: how many steps the run has, and how long one is expected
	// to take alone, if measuring found out (0 if not).
	Total  int
	Expect time.Duration
	// StepEvent: what one of the run's workers did.
	Step wick.Event
}

// EventKind is what an Event tells.
type EventKind int

const (
	StageBegan EventKind = iota // a run of steps begins
	StepEvent                   // one of its workers did something (Step)
)

// emit stamps ev and passes it on, one at a time: workers report
// concurrently, and a front end sees their events in the order stamped.
func (e *Env) emit(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ev.At = time.Now()
	e.Events(ev)
}

// stage begins the run named label, of total steps, expected to take about
// expect each, and returns the wick.Report its workers' steps go to; nil if
// nothing listens.
func (e *Env) stage(label string, total int, expect time.Duration) wick.Report {
	if e.Events == nil {
		return nil
	}
	e.emit(Event{Stage: label, Kind: StageBegan, Total: total, Expect: expect})
	return func(s wick.Event) { e.emit(Event{Stage: label, Kind: StepEvent, Step: s}) }
}

// Run is the run of steps under way, as its events tell it, for a front end
// to draw. Apply takes every time from the events, never from the clock, so
// any sequence of events, real or written out, gives the same Run.
type Run struct {
	Stage       string
	Start       time.Time // when the stage began
	Done, Total int
	Workers     []Worker      // each as it first reports; a solve is one, and so is a GPU
	Claimed     int           // steps begun so far: those below are under way or finished
	Batch       int           // the largest batch begun, on a GPU; 0 for none
	StepAvg     time.Duration // recent time of one step alone, from those finished or what the stage expected
	BatchAvg    time.Duration // recent time of a GPU's batch, its steps side by side
	Rate        float64       // steps a second in this stage, as of the last finished; 0 before
	ETA         time.Duration // the stage's remaining time, as of the last finished step
}

// Worker is one worker of a Run: the N steps from First it has under way,
// since when, and how far through them it has said it is.
type Worker struct {
	First, N int // First is -1 with none under way
	Since    time.Time
	Part     float64 // 0 to 1; 0 if it has said nothing
	Idle     bool    // done for this run
}

// Busy reports whether w has a step from [lo, hi) under way.
func (w Worker) Busy(lo, hi int) bool { return w.First >= 0 && w.First < hi && w.First+w.N > lo }

// Fraction is how much of the run is done, 0 to 1.
func (r Run) Fraction() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.Done) / float64(r.Total)
}

// Apply is r after ev. The averages are recomputed as steps finish, not as
// time passes: between steps they would only drift with the clock.
func (r Run) Apply(ev Event) Run {
	if ev.Kind == StageBegan {
		return Run{Stage: ev.Stage, Start: ev.At, Total: ev.Total, StepAvg: ev.Expect}
	}
	s := ev.Step
	r.Workers = slices.Clone(r.Workers) // r's caller keeps its own
	for len(r.Workers) <= s.Worker {
		r.Workers = append(r.Workers, Worker{First: -1})
	}
	w := &r.Workers[s.Worker]
	switch s.Kind {
	case wick.Began:
		*w = Worker{First: s.First, N: s.N, Since: ev.At}
		r.Claimed = max(r.Claimed, s.First+s.N)
		if s.N > 1 {
			r.Batch = max(r.Batch, s.N)
		}
	case wick.Partway:
		if s.OfParts > 0 {
			w.Part = float64(s.Part) / float64(s.OfParts)
		}
	case wick.Finished:
		// A batch's steps run side by side and finish together: its time is
		// its own, not one step's.
		avg := &r.StepAvg
		if s.N > 1 {
			avg = &r.BatchAvg
		}
		if d := ev.At.Sub(w.Since); *avg == 0 {
			*avg = d
		} else {
			*avg = (4**avg + d) / 5
		}
		*w = Worker{First: -1}
		r.Done += s.N
		if el := ev.At.Sub(r.Start); el > 0 {
			r.Rate = float64(r.Done) / el.Seconds()
			r.ETA = time.Duration(float64(r.Total-r.Done) / r.Rate * float64(time.Second))
		}
	case wick.Idle:
		*w = Worker{First: -1, Idle: true}
	}
	return r
}
