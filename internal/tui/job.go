package tui

import (
	"context"
	"slices"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"

	"wickset/internal/ops"
)

// A job is one operation running off the UI goroutine. The operation reports
// through the job's Env, which only records; the UI reads the record as a
// snapshot on each redraw. Nothing the operation calls ever waits on the UI,
// so the event callback, which package wick calls under its own mutex,
// returns at once.
type job struct {
	title  string
	start  time.Time
	cancel context.CancelFunc
	run    func() tea.Msg // the operation; its result is a doneMsg

	mu  sync.Mutex
	rec snapshot // guarded by mu
}

// snapshot is a job's record, as of one instant when it is a copy: the run
// under way, as its events tell it (ops.Run), and what else the job heard.
type snapshot struct {
	ops.Run
	notes     []ops.Note
	cancelled bool
}

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
	env := &ops.Env{Note: j.note, Events: j.event, GPU: gpu}
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

// event records what the operation's work did. It only records: Apply is a
// few assignments, so the workers, which wait on it, barely do.
func (j *job) event(e ops.Event) {
	j.mu.Lock()
	j.rec.Run = j.rec.Run.Apply(e)
	j.mu.Unlock()
}

// snapshot is a copy of the job's record, safe to read as the job runs on.
// Apply never changes a Run's workers in place, so they need no copy.
func (j *job) snapshot() snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := j.rec
	s.notes = slices.Clone(s.notes)
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
