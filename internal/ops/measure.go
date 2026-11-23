package ops

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/zblach/wickset/alg"
	"github.com/zblach/wickset/internal/sodium"
	"github.com/zblach/wickset/wick"
)

// LongDelay is the delay from which a seal with no algorithm given uses the
// long step rather than the short (docs/parameters.md).
const LongDelay = 24 * time.Hour

// AlgFor is the algorithm a seal of the given delay uses when none is given:
// on the GPU, iterated SHA-256, which it seals far faster than it opens;
// otherwise Argon2id, which keeps memory-hardness where the GPU's speed is
// not on offer (docs/parameters.md).
func AlgFor(delay time.Duration, gpu bool) alg.Alg {
	short, long := alg.Argon2idShort, alg.Argon2idLong
	if gpu {
		short, long = alg.SHA256Short, alg.SHA256Long
	}
	id := short
	if delay >= LongDelay {
		id = long
	}
	a, _ := alg.Lookup(id)
	return a
}

// stepSamples is how many steps a timing takes; it reports the fastest.
const stepSamples = 3

// slice is the most of an iterated SHA-256 step a timing runs on one core,
// under a second. A longer step is timed by its first slice hashes and
// scaled up, as every hash of a step costs the same.
const slice = 1 << 24

// cpuPart runs a's step on x on this goroutine, for a timing: whole, or for
// an iterated SHA-256 step longer than slice, its first slice hashes. It returns the
// share of a step it ran.
func cpuPart(ctx context.Context, a alg.Alg, x []byte, partway alg.Partway) (float64, error) {
	if c, ok := alg.SHA256IterOf(a); ok && c.K > slice {
		_, err := c.Run(ctx, c.Start(x), slice-1, func(done uint64) { partway(done+1, slice) })
		return float64(slice) / float64(c.K), err
	}
	_, err := alg.EvalPartway(ctx, a, x, partway)
	return 1, err
}

// argon2Lead is how much faster libsodium runs an Argon2id step than
// x/crypto does: the most measured on any machine (benchmarks/scores.csv),
// 0x02's on an AMD EPYC 7763. The lead varies by machine and step (×1.23 to
// ×1.72 measured; the long step's is always the larger), and a delay is
// timed against the fastest opener, so the largest is taken: a lead set too
// high makes a delay longer than it need be, one set too low lets an opener
// in early. A build with libsodium times its steps directly instead.
const argon2Lead = 1.72

// openTiming says how openPart times a's step, where it is not simply as
// this build runs it; "" where it is.
func openTiming(a alg.Alg) string {
	switch _, sha := alg.SHA256IterOf(a); {
	case sha:
		return "at this core's full SHA-256 rate"
	case sodium.Built:
		if _, ok := alg.Argon2idParams(a); ok {
			return "on libsodium " + sodium.Version()
		}
	default:
		if _, ok := alg.Argon2idParams(a); ok {
			return fmt.Sprintf("as libsodium runs it, %.2f× ours", argon2Lead)
		}
	}
	return ""
}

// openPart is cpuPart as the fastest opener runs it, for timing the delay a
// step makes. For iterated SHA-256 that is not our loop (sha256iter) but this
// core's raw compression rate, timed by hashing a buffer, whose blocks follow
// one another as a step's hashes do: a loop that keeps its state in registers
// approaches it, and ours runs about 1.4× slower. Timing the rate, a delay
// holds against such an opener; an honest one with wickset takes a little
// longer to open. Any other step is timed as cpuPart runs it.
//
// Argon2id the same: libsodium runs it faster than x/crypto's, which is pure
// Go on arm64 (its assembly is amd64's). Built with libsodium (-tags
// libsodium), a step runs on it (argon2.Params.Key) and is timed as it
// runs; otherwise our time is divided by the largest lead libsodium has
// been measured to have, argon2Lead.
func openPart(ctx context.Context, a alg.Alg, x []byte, partway alg.Partway) (float64, error) {
	if _, ok := alg.Argon2idParams(a); ok && !sodium.Built {
		share, err := cpuPart(ctx, a, x, partway)
		return share * argon2Lead, err
	}
	c, ok := alg.SHA256IterOf(a)
	if !ok {
		return cpuPart(ctx, a, x, partway)
	}
	const block, bufBlocks = 64, 1 << 14 // 1 MiB a hash
	buf := make([]byte, block*bufBlocks)
	copy(buf, x)
	hashes := min(c.K, slice)
	for done := uint64(0); done < hashes; done += bufBlocks {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		sha256.Sum256(buf)
		if done%(64*bufBlocks) == 0 {
			partway(done+bufBlocks, hashes)
		}
	}
	return float64(hashes) / float64(c.K), nil
}

// stepTime measures one step of a, alone, as the fastest solver runs it: on
// b (the GPU) if b is set, else on one core (openPart). It is the fastest of
// stepSamples, reported as the run named label. Cancelling ctx stops it
// mid-sample.
//
// The fastest, not the median: a process's first step runs cold, up to ~20%
// slower, and anything else on the machine only slows a step. A seal turns
// this time into steps, and a slow estimate would make too few, opening the
// wick early; the fastest errs, if at all, toward more.
func (e *Env) stepTime(ctx context.Context, a alg.Alg, label string, b *batcher) (time.Duration, error) {
	send := sender(e.stage(label, stepSamples, 0))
	defer send(wick.Event{Kind: wick.Idle})
	x := make([]byte, a.BlockSize())
	fastest := time.Duration(math.MaxInt64)
	for i := range stepSamples {
		send(wick.Event{Kind: wick.Began, First: i, N: 1})
		x[0] = byte(i)
		t := time.Now()
		var el time.Duration
		var share float64
		var err error
		if b != nil {
			el, share, err = b.sample(ctx, a, [][]byte{x})
		} else {
			share, err = openPart(ctx, a, x, partway(send, 0, i, 1))
			el = time.Since(t)
		}
		if err != nil {
			return 0, err
		}
		fastest = min(fastest, time.Duration(float64(el)/share))
		send(wick.Event{Kind: wick.Finished, First: i, N: 1})
	}
	return fastest, nil
}

// sender is report, or with none, a report that does nothing.
func sender(report wick.Report) wick.Report {
	if report == nil {
		return func(wick.Event) {}
	}
	return report
}

// partway reports through send how far worker is through its n steps from
// first.
func partway(send wick.Report, worker, first, n int) alg.Partway {
	return func(done, total uint64) {
		send(wick.Event{Kind: wick.Partway, Worker: worker, First: first, N: n, Part: done, OfParts: total})
	}
}

// roundRate measures how fast a seal runs: n steps at once, as n workers or
// one batch on b, timed together, in steps a second. Running side by side,
// they share memory bandwidth, so this is slower than n single steps. A
// long iterated SHA-256 step runs only in part, as stepTime's do.
func (e *Env) roundRate(ctx context.Context, a alg.Alg, label string, n int, b *batcher) (float64, error) {
	send := sender(e.stage(label, n, 0))
	xs := make([][]byte, n)
	for i := range xs {
		xs[i] = make([]byte, a.BlockSize())
		xs[i][0], xs[i][1], xs[i][2] = byte(i), byte(i>>8), byte(i>>16)
	}
	if b != nil {
		// The round is one batch, begun and finished together, however much
		// of each step it ran.
		defer send(wick.Event{Kind: wick.Idle})
		send(wick.Event{Kind: wick.Began, First: 0, N: n})
		el, share, err := b.sample(ctx, a, xs)
		if err != nil {
			return 0, err
		}
		send(wick.Event{Kind: wick.Finished, First: 0, N: n})
		return float64(n) * share / el.Seconds(), nil
	}
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, n)
	shares := make([]float64, n)
	for w := range n {
		wg.Go(func() {
			defer send(wick.Event{Kind: wick.Idle, Worker: w})
			send(wick.Event{Kind: wick.Began, Worker: w, First: w, N: 1})
			if shares[w], errs[w] = cpuPart(ctx, a, xs[w], partway(send, w, w, 1)); errs[w] == nil {
				send(wick.Event{Kind: wick.Finished, Worker: w, First: w, N: 1})
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return 0, err
		}
	}
	return float64(n) * shares[0] / time.Since(start).Seconds(), nil
}

// plan sizes the parallel run named label: steps evaluations of a, or, with
// a delay, as many as the delay takes a solver here (at least one). A solver
// runs one step at a time, on one core or, slower, on a GPU: in GPU mode both
// are timed, and the faster sets the steps, so the delay holds against
// either. expect is a step's measured time on one core, as a worker runs it;
// 0 if not measured. Where the run goes is place's to decide, after.
func (e *Env) plan(ctx context.Context, a alg.Alg, steps int, delay time.Duration, b *batcher) (n int, expect time.Duration, err error) {
	if delay > 0 {
		if expect, err = e.stepTime(ctx, a, "measuring", nil); err != nil {
			return 0, 0, err
		}
		st := expect
		on := fmt.Sprintf("one core %v", st.Round(time.Millisecond))
		if how := openTiming(a); how != "" {
			on += ", " + how
		}
		if b != nil {
			gt, err := e.stepTime(ctx, a, "measuring the GPU", b)
			if err != nil {
				return 0, 0, err
			}
			on += fmt.Sprintf(", the GPU %v", gt.Round(time.Millisecond))
			st = min(st, gt)
		}
		st = max(st, time.Nanosecond) // a cheap step can measure as 0
		steps = max(int((delay+st-1)/st), 1)
		e.note(Detail, "measured a step (%s) → %d sequential steps for %s on this machine", on, steps, FormatDelay(delay))
	}
	return steps, expect, nil
}

// workerCount is how many workers a parallel run of evals evaluations uses.
func workerCount(workers, evals int) int {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	return min(workers, evals)
}

// warnMemory notes the peak memory of a run on workers CPU workers when it
// reaches 1 GiB: a working set per worker. (A run on the GPU says its own,
// noteGPU.)
func (e *Env) warnMemory(a alg.Alg, held int) {
	total := int64(held) * int64(a.MemBytes())
	if total < 1<<30 {
		return
	}
	e.note(Warning, "%s uses %s per evaluation; %d parallel workers need %s (set fewer workers to lower)",
		a.Name(), Bytes(int64(a.MemBytes())), held, Bytes(total))
}

// Bench is what a's steps take on this machine, measured: one alone on one
// core, as a solve runs them, and rounds side by side, as a seal does; and
// the solve and seal times they predict.
type Bench struct {
	Alg    alg.Alg
	Step   time.Duration // one step alone, on one core, as the fastest opener runs it (openPart)
	SealOn string        // where the rounds ran: "" for the CPU, or the GPU
	Rounds []BenchRound  // steps side by side
	Rows   []BenchRow
}

// StepNote says how Step was timed, for a front end to put beside it:
// "(fastest of 3)", and how, where not as this build runs a step.
func (b Bench) StepNote() string {
	if how := b.StepTiming(); how != "" {
		return "(fastest of 3, " + how + ")"
	}
	return "(fastest of 3)"
}

// StepTiming says how Step was timed where not as this build runs a step,
// or "".
func (b Bench) StepTiming() string { return openTiming(b.Alg) }

// BenchRound is a seal's pace with At steps at once.
type BenchRound struct {
	At   int
	Rate float64 // steps a second
}

func (r BenchRound) String() string { return fmt.Sprintf("%d at once %.1f steps/s", r.At, r.Rate) }

// Sealing says how the rounds went, for a front end: "sealing: 5 at once
// 9.8 steps/s · 10 at once 12.0 steps/s", or "sealing on the Apple M5 GPU:
// 48 at once 24.8 steps/s".
func (b Bench) Sealing() string {
	s := "sealing:"
	if b.SealOn != "" {
		s = "sealing on " + b.SealOn + ":"
	}
	for i, r := range b.Rounds {
		if i > 0 {
			s += " ·"
		}
		s += " " + r.String()
	}
	if len(b.Rounds) == 0 {
		s += " one step at a time"
	}
	return s
}

// rate is a seal's pace, in steps a second: the best round's, or with no
// rounds (one core), one step at a time. A round is never set against Step:
// Step is the fastest opener's, which this build's sealing may not match,
// and a speed-up under 1 says so.
func (b Bench) rate() float64 {
	if r, ok := b.Best(); ok {
		return r.Rate
	}
	return 1 / b.Step.Seconds()
}

// Best is the fastest round, if any ran.
func (b Bench) Best() (BenchRound, bool) {
	var best BenchRound
	for _, r := range b.Rounds {
		if r.Rate > best.Rate {
			best = r
		}
	}
	return best, len(b.Rounds) > 0
}

// SpeedUp is how many times faster a wick seals here than it opens: the
// seal's pace against the solver's, one step at a time on one core. It is
// the algorithm's worth for sealing on this machine (docs/parameters.md).
func (b Bench) SpeedUp() float64 { return b.rate() * b.Step.Seconds() }

// SpeedUpLine says SpeedUp for a front end.
func (b Bench) SpeedUpLine() string {
	return fmt.Sprintf("speed-up ×%.1f: a wick seals here %.1f times faster than it opens", b.SpeedUp(), b.SpeedUp())
}

// BenchRow is what Bench predicts for one N.
type BenchRow struct {
	N     int
	Solve time.Duration // N+1 steps, one after another
	Seal  time.Duration // the same steps at the best round's pace
	Size  int           // of the wick, in bytes
}

// Bench times a's steps as this Env runs them: one alone on one core, as
// opening always runs, and rounds as sealing does: one full batch on the GPU
// in GPU mode, otherwise half the cores and all of them side by side.
func (e *Env) Bench(ctx context.Context, a alg.Alg) (Bench, error) {
	b, n, err := e.gpuBatcher(a)
	if err != nil {
		return Bench{}, err
	}
	out := Bench{Alg: a}
	rounds := []int{runtime.GOMAXPROCS(0) / 2, runtime.GOMAXPROCS(0)}
	if b != nil {
		out.SealOn, rounds = "the "+GPUName()+" GPU", []int{n}
		e.noteGPU(a, b, n)
	}
	if out.Step, err = e.stepTime(ctx, a, "timing one step", nil); err != nil {
		return Bench{}, err
	}
	for _, at := range rounds {
		if at < 2 || (len(out.Rounds) > 0 && out.Rounds[len(out.Rounds)-1].At == at) {
			continue
		}
		rate, err := e.roundRate(ctx, a, fmt.Sprintf("timing %d at once", at), at, b)
		if err != nil {
			return Bench{}, err
		}
		out.Rounds = append(out.Rounds, BenchRound{at, rate})
	}
	best := out.rate()
	for _, n := range []int{0, 999, 9_999, 99_999, 999_999} {
		seal := time.Duration(float64(n+1) / best * float64(time.Second))
		out.Rows = append(out.Rows, BenchRow{
			N: n, Solve: time.Duration(n+1) * out.Step,
			Seal: max(seal, out.Step), // never under one step, however many run at once
			Size: wick.Size(a, n),
		})
	}
	return out, nil
}
