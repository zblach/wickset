package ops

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"chainlock/alg"
	"chainlock/chain"
)

// fakeAlg is a free step, enough for code that only times or counts steps.
type fakeAlg struct{ alg.Alg }

func (fakeAlg) BlockSize() int    { return 32 }
func (fakeAlg) H(x []byte) []byte { return x }
func (fakeAlg) ID() alg.ID        { return 0xF0 }
func (fakeAlg) MemBytes() int     { return 0 }

// TestStepTimeReports: timing a step, which is seconds per sample for the
// long algorithm, reports each sample as it runs, as a solve reports steps.
func TestStepTimeReports(t *testing.T) {
	var events []string
	e := &Env{
		Progress: func(label string) chain.Progress {
			return func(done, total int) { events = append(events, fmt.Sprintf("%s %d/%d", label, done, total)) }
		},
		Activity: func(label string, total int) chain.Activity {
			events = append(events, fmt.Sprintf("%s of %d", label, total))
			return func(w, i, _ int) { events = append(events, fmt.Sprintf("w%d #%d", w, i)) }
		},
	}
	if k, err := e.plan(context.Background(), "sealing", fakeAlg{}, 0, time.Second, 1, nil, 0); err != nil || k < 1 {
		t.Fatalf("steps %d", k)
	}
	want := "measuring of 3, w0 #0, measuring 1/3, w0 #1, measuring 2/3, w0 #2, measuring 3/3, w0 #-1"
	if got := strings.Join(events, ", "); got != want {
		t.Fatalf("events\n got %s\nwant %s", got, want)
	}
}

// TestBench: bench times one step on one core, then rounds of half the cores
// and all of them side by side; a solve takes the steps one after another,
// and a seal runs at the best round's measured pace.
func TestBench(t *testing.T) {
	var labels []string
	e := &Env{Progress: func(label string) chain.Progress {
		labels = append(labels, label)
		return nil
	}}
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
		want alg.ID
	}{
		{time.Minute, alg.Argon2id256M},
		{LongDelay - time.Second, alg.Argon2id256M},
		{LongDelay, alg.Argon2id1GT30},
		{14 * 24 * time.Hour, alg.Argon2id1GT30},
	} {
		if got := AlgFor(c.d).ID(); got != c.want {
			t.Errorf("AlgFor(%v) = %v, want %v", c.d, got, c.want)
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
