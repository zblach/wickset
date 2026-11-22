package tui

import (
	"context"
	"slices"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"

	"chainlock/chain"
	"chainlock/internal/ops"
)

// A job is one operation running off the UI goroutine. The operation reports
// through the job's Env, which only records; the UI reads the record as a
// snapshot on each redraw. Nothing the operation calls ever waits on the UI,
// so the progress callback, which chainlock calls under its own lock,
// returns at once.
type job struct {
	title  string
	start  time.Time
	cancel context.CancelFunc
	run    func() tea.Msg // the operation; its result is a doneMsg

	mu  sync.Mutex
	rec snapshot // guarded by mu
}

// snapshot is a job's record, as of one instant when it is a copy.
type snapshot struct {
	stage       string    // progress label: "measuring", "sealing", "solving", "extending"
	stageStart  time.Time // when the stage began
	done, total int
	notes       []ops.Note
	cancelled   bool
	workers     []worker      // one per worker, as each starts; a solve is one worker, and so is a GPU
	claimed     int           // steps begun so far: those below that are in progress or finished
	stepAvg     time.Duration // recent time of one step, from those finished; 0 until one is
	batchAvg    time.Duration // recent time of a GPU's batch: the time of each step in it, side by side
	rate        float64       // steps a second in this stage, as of the last finished step; 0 before
	eta         time.Duration // the stage's remaining time, as of the last finished step
}

// worker is one worker of a run: the steps it is running, from first on (n
// of them: one, or a GPU's batch), and since when. Each step is opaque, so
// that is all there is to show.
type worker struct {
	first, n int       // first is -1 once it has finished for good
	since    time.Time // when it began those steps, or finished
}

// busy reports whether w is running a step in [lo, hi).
func (w worker) busy(lo, hi int) bool { return w.first >= 0 && w.first < hi && w.first+w.n > lo }

// doneMsg ends a job: value is the operation's result, if it has one.
type doneMsg struct {
	value any
	err   error
}

// op is an operation as a job runs it. The TUI owns the terminal, so its Env
// has no Stdin or Stdout and a key path of "-" is refused.
type op func(ctx context.Context, env *ops.Env) (any, error)

func newJob(parent context.Context, title string, f op, gpu bool) *job {
	ctx, cancel := context.WithCancel(parent)
	j := &job{title: title, start: time.Now(), cancel: cancel}
	env := &ops.Env{Note: j.note, Progress: j.progress, Activity: j.activity, GPU: gpu}
	j.run = func() tea.Msg {
		defer cancel()
		v, err := f(ctx, env)
		return doneMsg{v, err}
	}
	return j
}

func (j *job) note(n ops.Note) {
	j.mu.Lock()
	j.rec.notes = append(j.rec.notes, n)
	j.mu.Unlock()
}

// progress records each finished step, and recomputes the pace and eta then
// rather than on every redraw: between steps they would only drift with the
// clock, telling nothing new.
func (j *job) progress(label string) chain.Progress {
	return func(done, total int) {
		j.mu.Lock()
		defer j.mu.Unlock()
		r := &j.rec
		if r.stageStart.IsZero() {
			r.stageStart = time.Now()
		}
		r.stage, r.done, r.total = label, done, total
		if el := time.Since(r.stageStart); done > 0 && el > 0 {
			r.rate = float64(done) / el.Seconds()
			r.eta = time.Duration(float64(total-done) / r.rate * float64(time.Second))
		}
	}
}

// activity records the run named label, of total evaluations, from its
// outset: the run shows as under way before its first evaluation ends. The
// step-time average carries over from one stage to the next, so a seal by
// delay starts with what measuring found.
func (j *job) activity(label string, total int) chain.Activity {
	j.mu.Lock()
	r := &j.rec
	r.stage, r.stageStart, r.done, r.total, r.workers, r.claimed, r.rate, r.eta = label, time.Now(), 0, total, nil, 0, 0, 0
	j.mu.Unlock()
	return func(w, first, n int) {
		j.mu.Lock()
		defer j.mu.Unlock()
		for len(r.workers) <= w {
			r.workers = append(r.workers, worker{first: -1})
		}
		ws := &r.workers[w]
		now := time.Now()
		if ws.first >= 0 && !ws.since.IsZero() {
			// A worker moves on only when its steps are finished. A batch's
			// steps run side by side and finish together, so its time is
			// its own, not one step's on a core.
			avg := &r.stepAvg
			if ws.n > 1 {
				avg = &r.batchAvg
			}
			if d := now.Sub(ws.since); *avg == 0 {
				*avg = d
			} else {
				*avg = (4**avg + d) / 5
			}
		}
		ws.first, ws.n, ws.since = first, n, now
		if first >= 0 {
			r.claimed = max(r.claimed, first+n)
		}
	}
}

// snapshot is a copy of the job's record, safe to read as the job runs on.
func (j *job) snapshot() snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := j.rec
	s.notes, s.workers = slices.Clone(s.notes), slices.Clone(s.workers)
	return s
}

// stop cancels the operation. Its workers return at once (alg.Eval), and
// its doneMsg ends the job.
func (j *job) stop() {
	j.mu.Lock()
	j.rec.cancelled = true
	j.mu.Unlock()
	j.cancel()
}

func (s snapshot) fraction() float64 {
	if s.total == 0 {
		return 0
	}
	return float64(s.done) / float64(s.total)
}
