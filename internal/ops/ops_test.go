package ops

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"

	"wickset/alg"
	"wickset/wick"
)

// fakeAlg is a free step, enough for code that only times or counts steps.
type fakeAlg struct{ alg.Alg }

func (fakeAlg) BlockSize() int    { return 32 }
func (fakeAlg) H(x []byte) []byte { return x }
func (fakeAlg) ID() alg.ID        { return 0xF0 }
func (fakeAlg) Name() string      { return "fake" }
func (fakeAlg) MemBytes() int     { return 0 }

// record is an Env that keeps every event, and the events as lines.
func record() (*Env, *[]Event) {
	var events []Event
	return &Env{Events: func(e Event) { events = append(events, e) }}, &events
}

// script writes events as lines: "measuring of 3", "began 0 #0", ...
func script(events []Event) string {
	var lines []string
	for _, e := range events {
		s := e.Step
		switch {
		case e.Kind == StageBegan:
			lines = append(lines, fmt.Sprintf("%s of %d", e.Stage, e.Total))
		case s.Kind == wick.Began:
			lines = append(lines, fmt.Sprintf("began %d #%d+%d", s.Worker, s.First, s.N))
		case s.Kind == wick.Finished:
			lines = append(lines, fmt.Sprintf("finished %d #%d+%d", s.Worker, s.First, s.N))
		case s.Kind == wick.Idle:
			lines = append(lines, fmt.Sprintf("idle %d", s.Worker))
		}
	}
	return strings.Join(lines, ", ")
}

// TestStepTimeReports: timing a step, which is seconds per sample for the
// long algorithms, reports each sample as it runs, as a solve reports steps.
func TestStepTimeReports(t *testing.T) {
	e, events := record()
	k, expect, err := e.plan(context.Background(), "sealing", fakeAlg{}, 0, time.Second, 1, nil, 0)
	if err != nil || k < 1 || expect < 0 {
		t.Fatalf("steps %d, expect %v, %v", k, expect, err)
	}
	want := "measuring of 3, began 0 #0+1, finished 0 #0+1, began 0 #1+1, finished 0 #1+1, began 0 #2+1, finished 0 #2+1, idle 0"
	if got := script(*events); got != want {
		t.Fatalf("events\n got %s\nwant %s", got, want)
	}
	for i := 1; i < len(*events); i++ {
		if (*events)[i].At.Before((*events)[i-1].At) {
			t.Fatal("events stamped out of order")
		}
	}
}

// TestBench: bench times one step on one core, then rounds of half the cores
// and all of them side by side; a solve takes the steps one after another,
// and a seal runs at the best round's measured pace.
func TestBench(t *testing.T) {
	// Each stage, as its events tell it, ends with every step done.
	var labels []string
	var run Run
	ended := func() {
		if run.Stage != "" && run.Done != run.Total {
			t.Errorf("%s ended at %d of %d", run.Stage, run.Done, run.Total)
		}
	}
	e := &Env{Events: func(ev Event) {
		if ev.Kind == StageBegan {
			ended()
			labels = append(labels, ev.Stage)
		}
		run = run.Apply(ev)
	}}
	defer ended()
	b, err := e.Bench(context.Background(), slowAlg{})
	if err != nil {
		t.Fatal(err)
	}
	cores := runtime.GOMAXPROCS(0)
	want := []string{"timing one step"}
	if cores/2 >= 2 {
		want = append(want, fmt.Sprintf("timing %d at once", cores/2))
	}
	if cores >= 2 {
		want = append(want, fmt.Sprintf("timing %d at once", cores))
	}
	if fmt.Sprint(labels) != fmt.Sprint(want) || b.SealOn != "" || len(b.Rounds) != len(want)-1 {
		t.Fatalf("runs %q sealing on %q, rounds %v; want runs %q", labels, b.SealOn, b.Rounds, want)
	}
	best := 1 / b.Step.Seconds()
	for _, r := range b.Rounds {
		best = max(best, r.Rate)
	}
	for _, r := range b.Rows {
		seal := max(time.Duration(float64(r.N+1)/best*float64(time.Second)), b.Step)
		if r.Solve != time.Duration(r.N+1)*b.Step || r.Seal != seal {
			t.Errorf("N=%d: solve %v, seal %v; step %v, best %.1f steps/s", r.N, r.Solve, r.Seal, b.Step, best)
		}
	}
	if s := b.Sealing(); !strings.HasPrefix(s, "sealing:") {
		t.Errorf("Sealing() = %q", s)
	}
	// The speed-up is the seal's pace against one step at a time: what a
	// seal of many steps takes, against the solve.
	if got, want := b.SpeedUp(), best*b.Step.Seconds(); got != want || got < 1 {
		t.Errorf("SpeedUp %v, want %v (best %.1f steps/s, step %v)", got, want, best, b.Step)
	}
	if last := b.Rows[len(b.Rows)-1]; math.Abs(last.Solve.Seconds()/last.Seal.Seconds()-b.SpeedUp()) > 0.01*b.SpeedUp() {
		t.Errorf("a million steps open in %v and seal in %v: not ×%.1f", last.Solve, last.Seal, b.SpeedUp())
	}
}

// slowAlg is fakeAlg at 2ms a step, so rounds side by side have a pace.
type slowAlg struct{ fakeAlg }

func (slowAlg) H(x []byte) []byte { time.Sleep(2 * time.Millisecond); return x }

func TestParseDelay(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90s":                 90 * time.Second,
		"8h":                  8 * time.Hour,
		"1h30m":               90 * time.Minute,
		"3d":                  3 * Day,
		"2w":                  14 * Day,
		"1w3d":                10 * Day,
		"1w 3d":               10 * Day,
		"1.5d":                36 * time.Hour,
		"1m":                  time.Minute, // m is a minute,
		"1M":                  Month,       // M a month (systemd.time)
		"6M":                  6 * Month,
		"1y":                  Year,
		"1y 6M":               Year + 6*Month,
		"2 weeks":             14 * Day,
		"2 weeks 3 days":      17 * Day,
		"90 min":              90 * time.Minute,
		"1 hour 30 minutes":   90 * time.Minute,
		"1 month":             Month,
		" 2w ":                14 * Day,
		"2ms":                 2 * time.Millisecond,
		".5h":                 30 * time.Minute,
		"100y":                100 * Year,
		"1d12h30m":            36*time.Hour + 30*time.Minute,
		"1 year 2 months 3 d": Year + 2*Month + 3*Day,
	} {
		if got, err := ParseDelay(in); err != nil || got != want {
			t.Errorf("ParseDelay(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if Month != 2629800*time.Second || Year != 31557600*time.Second {
		t.Error("month and year are not systemd's 30.44 and 365.25 days")
	}
	for _, in := range []string{"", "8", "h", "0s", "-1h", "3x", "1d-2h", "300y", "1.2.3d", "1mo", "2 Weeks", "1D"} {
		if got, err := ParseDelay(in); err == nil {
			t.Errorf("ParseDelay(%q) = %v, want an error", in, got)
		}
	}
}

func TestFormatDelay(t *testing.T) {
	for d, want := range map[time.Duration]string{
		2 * time.Millisecond:           "2ms",
		90 * time.Second:               "1m 30s",
		8 * time.Hour:                  "8h",
		14 * Day:                       "2w",
		10*Day + 3*time.Hour:           "1w 3d 3h",
		45 * Day:                       "6w 3d",
		Year + 2*Day:                   "1y 2d",
		LongDelay:                      "1d",
		12*time.Hour + time.Nanosecond: "12h",
	} {
		if got := FormatDelay(d); got != want {
			t.Errorf("FormatDelay(%v) = %q, want %q", d, got, want)
		}
		if back, err := ParseDelay(FormatDelay(d)); err != nil || back.Round(time.Second) != d.Round(time.Second) && d >= time.Minute {
			t.Errorf("FormatDelay(%v) = %q does not parse back: %v, %v", d, FormatDelay(d), back, err)
		}
	}
}

func TestAlgFor(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		gpu  bool
		want alg.ID
	}{
		{time.Minute, false, alg.Argon2idShort},
		{LongDelay - time.Second, false, alg.Argon2idShort},
		{LongDelay, false, alg.Argon2idLong},
		{14 * 24 * time.Hour, false, alg.Argon2idLong},
		{time.Minute, true, alg.SHA256Short},
		{LongDelay - time.Second, true, alg.SHA256Short},
		{LongDelay, true, alg.SHA256Long},
		{14 * 24 * time.Hour, true, alg.SHA256Long},
	} {
		if got := AlgFor(c.d, c.gpu).ID(); got != c.want {
			t.Errorf("AlgFor(%v, gpu %v) = %v, want %v", c.d, c.gpu, got, c.want)
		}
	}
}

// TestSealNeedsAlg: N with no algorithm is refused before anything is read
// or measured.
func TestSealNeedsAlg(t *testing.T) {
	err := (&Env{}).Seal(context.Background(), SealArgs{File: "/nonexistent", N: 3})
	if !errors.Is(err, ErrNeedAlg) {
		t.Fatalf("err %v, want ErrNeedAlg", err)
	}
}
