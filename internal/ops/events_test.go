package ops

import (
	"testing"
	"time"

	"chainlock/chain"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// at is a step event at t0 plus s seconds.
func at(s float64, kind chain.EventKind, worker, first, n int) Event {
	return Event{At: t0.Add(time.Duration(s * float64(time.Second))), Kind: StepEvent,
		Step: chain.Event{Kind: kind, Worker: worker, First: first, N: n}}
}

func apply(r Run, events ...Event) Run {
	for _, e := range events {
		r = r.Apply(e)
	}
	return r
}

// TestRunWorkers: two workers on four steps, told only by events: what is
// under way, done, its pace, and the time of a step.
func TestRunWorkers(t *testing.T) {
	r := apply(Run{},
		Event{At: t0, Kind: StageBegan, Stage: "sealing", Total: 4},
		at(0, chain.Began, 0, 0, 1),
		at(0, chain.Began, 1, 1, 1),
	)
	if r.Done != 0 || r.Claimed != 2 || !r.Workers[0].Busy(0, 1) || !r.Workers[1].Busy(1, 2) || r.Rate != 0 {
		t.Fatalf("both under way: %+v", r)
	}
	r = apply(r, at(2, chain.Finished, 0, 0, 1), at(2, chain.Began, 0, 2, 1))
	if r.Done != 1 || r.StepAvg != 2*time.Second || r.Rate != 0.5 || r.ETA != 6*time.Second || r.Claimed != 3 {
		t.Fatalf("one done in 2 s: %+v", r)
	}
	r = apply(r, at(4, chain.Finished, 1, 1, 1), at(4, chain.Idle, 1, 0, 0))
	if r.StepAvg != (4*2*time.Second+4*time.Second)/5 || !r.Workers[1].Idle || r.Workers[1].Busy(0, 4) {
		t.Fatalf("a 4 s step averages in, and worker 1 is idle: %+v", r)
	}
	if r.Fraction() != 0.5 {
		t.Fatalf("fraction %v", r.Fraction())
	}
}

// TestRunBatch: a GPU's batch is one worker with many steps, timed as a
// batch, not as a step; partway reports move it on.
func TestRunBatch(t *testing.T) {
	r := apply(Run{},
		Event{At: t0, Kind: StageBegan, Stage: "sealing", Total: 30, Expect: 11 * time.Second},
		at(0, chain.Began, 0, 0, 12),
	)
	partway := at(10, chain.Partway, 0, 0, 12)
	partway.Step.Part, partway.Step.OfParts = 1, 4
	r = apply(r, partway)
	if r.Batch != 12 || r.Workers[0].Part != 0.25 || r.StepAvg != 11*time.Second {
		t.Fatalf("a quarter through a batch of 12: %+v", r)
	}
	r = apply(r, at(40, chain.Finished, 0, 0, 12))
	if r.Done != 12 || r.BatchAvg != 40*time.Second || r.StepAvg != 11*time.Second || r.Workers[0].Part != 0 {
		t.Fatalf("a batch of 12 in 40 s: %+v", r)
	}
}

// TestRunStages: a new stage starts over, keeping nothing of the last but
// what it says to expect; Apply never changes the Run it was given.
func TestRunStages(t *testing.T) {
	measured := apply(Run{},
		Event{At: t0, Kind: StageBegan, Stage: "measuring", Total: 3},
		at(0, chain.Began, 0, 0, 1),
		at(1, chain.Finished, 0, 0, 1),
	)
	before := measured.Workers[0]
	sealing := measured.Apply(Event{At: t0.Add(5 * time.Second), Kind: StageBegan, Stage: "sealing", Total: 100, Expect: time.Second})
	if sealing.Done != 0 || sealing.Workers != nil || sealing.StepAvg != time.Second || !sealing.Start.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("sealing begins: %+v", sealing)
	}
	measured.Apply(at(2, chain.Began, 0, 1, 1))
	if measured.Workers[0] != before {
		t.Fatal("Apply changed its receiver's workers")
	}
}

// TestRunCancelled: a run cancelled mid-step ends with the step begun and
// never finished, which a Run takes as it comes.
func TestRunCancelled(t *testing.T) {
	r := apply(Run{},
		Event{At: t0, Kind: StageBegan, Stage: "solving", Total: 5},
		at(0, chain.Began, 0, 0, 1),
		at(3, chain.Idle, 0, 0, 0),
	)
	if r.Done != 0 || r.Claimed != 1 || r.Workers[0].First != -1 || r.Rate != 0 {
		t.Fatalf("cancelled: %+v", r)
	}
}
