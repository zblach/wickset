//go:build chainlock_testalgs

// Tests of the TUI's model, driven through Update and View directly against
// the cheap private-use algorithms:
//
//	go test -tags chainlock_testalgs ./internal/tui
package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"chainlock/alg"
	"chainlock/chain"
	"chainlock/internal/ops"
	"chainlock/internal/store"
)

func press(m *model, k tea.KeyPressMsg) {
	m.Update(k)
}

var (
	ctrlC = tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	keyY  = tea.KeyPressMsg{Code: 'y', Text: "y"}
	enter = tea.KeyPressMsg{Code: tea.KeyEnter}
)

// view is the screen as text, without styling.
func view(m *model) string { return ansi.Strip(m.View().Content) }

// submit runs act's operation over in to completion, as the form's submit
// would, and returns the result screen.
func submit(t *testing.T, m *model, act action, in *inputs) string {
	t.Helper()
	m.act, m.in, m.page = act, in, pages(act)-1 // the last page, whose submit runs it
	m.Update(submitMsg{})
	if m.screen != runScreen || m.job == nil {
		t.Fatalf("submit did not start a job (screen %v)", m.screen)
	}
	if v := view(m); !strings.Contains(v, actions[act].doing) {
		t.Errorf("running view lacks %q:\n%s", actions[act].doing, v)
	}
	m.Update(m.job.run())
	if m.screen != resultScreen {
		t.Fatalf("job did not finish (screen %v)", m.screen)
	}
	return view(m)
}

func TestSealOpenBypass(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	keyFile := filepath.Join(dir, "plain.key")
	os.WriteFile(plain, []byte("attack at dawn"), 0o600)
	m := newModel(context.Background(), "")

	v := submit(t, m, actSeal, &inputs{File: plain, Alg: 0xFE, Steps: "4", Form: store.FormArchive, KeyOut: keyFile})
	if m.res.err != nil || !strings.Contains(v, "✓ Sealed") || !strings.Contains(v, "✓ "+plain+".chainlock.tar") {
		t.Fatalf("seal: %v\n%s", m.res.err, v)
	}
	// CONTAINER.md §5: the key is saved, never shown.
	key, _, err := store.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v, key.Encode()[len("chainlock-key-v1:"):]) {
		t.Fatalf("the key appears on screen:\n%s", v)
	}

	press(m, enter)
	if m.screen != menuScreen {
		t.Fatalf("enter on a result: screen %v, want the menu", m.screen)
	}

	out := filepath.Join(dir, "opened")
	v = submit(t, m, actOpen, &inputs{File: plain + ".chainlock.tar", Out: out})
	if got, _ := os.ReadFile(out); m.res.err != nil || string(got) != "attack at dawn" {
		t.Fatalf("open: %v, wrote %q\n%s", m.res.err, got, v)
	}

	out = filepath.Join(dir, "bypassed")
	submit(t, m, actBypass, &inputs{File: plain + ".chainlock.tar", Key: keyFile, Out: out})
	if got, _ := os.ReadFile(out); m.res.err != nil || string(got) != "attack at dawn" {
		t.Fatalf("bypass: %v, wrote %q", m.res.err, got)
	}

	v = submit(t, m, actInfo, &inputs{File: plain + ".chainlock.tar"})
	if !strings.Contains(v, "5 to open (N = 4)") || !strings.Contains(v, "belongs to this lock, undamaged") || !strings.Contains(v, "one archive") {
		t.Fatalf("info:\n%s", v)
	}
}

// TestRefusals: what the CLI refuses before solving, the TUI refuses too.
func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	os.WriteFile(plain, []byte("x"), 0o600)
	m := newModel(context.Background(), "")
	submit(t, m, actSeal, &inputs{File: plain, Alg: 0xFE, Steps: "1", Form: store.FormFile})

	// The default output, plain, exists.
	if v := submit(t, m, actOpen, &inputs{File: plain + ".lock"}); !strings.Contains(v, "already exists") {
		t.Fatalf("open over an existing file:\n%s", v)
	}
	// Standard streams belong to the TUI.
	if v := submit(t, m, actOpen, &inputs{File: plain + ".lock", Out: filepath.Join(dir, "o"), KeyOut: "-"}); !strings.Contains(v, "not available here") {
		t.Fatalf("key to '-':\n%s", v)
	}
	for _, s := range []string{"-", "chainlock-key-v1:AAAA", ""} {
		if keyPath(true)(s) == nil {
			t.Errorf("key path %q accepted", s)
		}
	}
	if keyPath(false)("") != nil {
		t.Error("an optional key path refused empty")
	}
}

// TestWorkers: the worker count reaches the operations that take one, and
// empty means every core, as the CLI's default 0 does.
func TestWorkers(t *testing.T) {
	in := &inputs{File: " f ", Steps: "2h", Workers: "3", Alg: 0xFE}
	if a := args(actSeal, in).(ops.SealArgs); a.Workers != 3 || a.File != "f" || a.Delay.Hours() != 2 {
		t.Errorf("seal args %+v", a)
	}
	in.Workers = ""
	if a := args(actExtend, in).(ops.ExtendArgs); a.Workers != 0 {
		t.Errorf("extend args %+v", a)
	}
	if workersValidator("-1") != nil || args(actSeal, &inputs{Workers: "-1", Steps: "1h"}).(ops.SealArgs).Workers != 0 {
		t.Error("-1 is not one per core")
	}
	for _, s := range []string{"-2", "x", "1.5", "all"} {
		if workersValidator(s) == nil {
			t.Errorf("workers %q accepted", s)
		}
	}
}

// TestSealPages: seal asks for the delay first, and its second page offers
// the algorithm that delay suits, saying why; a step count keeps a pick.
func TestSealPages(t *testing.T) {
	m := newModel(context.Background(), "")
	m.pick(actSeal)
	if v := view(m); !strings.Contains(v, "Delay") || strings.Contains(v, "Algorithm") || !strings.Contains(v, "(1 of 2)") {
		t.Fatalf("page 1:\n%s", v)
	}
	for _, c := range []struct {
		steps string
		want  alg.ID
		why   string
	}{
		{"8h", alg.Argon2idShort, "Suggested for a 8h delay: 0x01 (argon2id-m128M-t5-p1)."},
		{"36h", alg.Argon2idLong, "Suggested for a 1d 12h delay: 0x02 (argon2id-m128M-t192-p1)."},
		{"2 weeks", alg.Argon2idLong, "Suggested for a 2w delay: 0x02"},
		{"6M", alg.Argon2idLong, "0x02"},
		{"336h", alg.Argon2idLong, "0x02"},
	} {
		m.in.Steps = c.steps
		m.Update(submitMsg{})
		v := view(m)
		if m.page != 1 || m.in.Alg != c.want || !strings.Contains(v, c.why) || !strings.Contains(v, "(2 of 2)") {
			t.Fatalf("%s: page %d alg %v\n%s", c.steps, m.page, m.in.Alg, v)
		}
		m.Update(backMsg{})
		if m.page != 0 || m.screen != formScreen || m.in.Steps != c.steps {
			t.Fatalf("esc on page 2: page %d screen %v steps %q", m.page, m.screen, m.in.Steps)
		}
	}
	// N keeps whatever was picked (here: 0x02, from 336h).
	m.in.Steps = "5"
	m.Update(submitMsg{})
	if m.in.Alg != alg.Argon2idLong || !strings.Contains(view(m), "N = 5: 6 steps") {
		t.Fatalf("N: alg %v\n%s", m.in.Alg, view(m))
	}
	if a := args(actSeal, m.in).(ops.SealArgs); a.Alg == nil || a.N != 5 || a.Delay != 0 {
		t.Fatalf("seal args %+v", a)
	}
	if d := defaultAlg(&inputs{Steps: "5"}); d != alg.Argon2idShort {
		t.Fatalf("fresh N defaults to %v", d)
	}
}

// TestHelpPanel: ? opens the details on any seal page, where nothing is
// being typed, and closes them; in a field with text it is typed instead.
func TestHelpPanel(t *testing.T) {
	m := newModel(context.Background(), "")
	m.pick(actSeal)
	question := tea.KeyPressMsg{Code: '?', Text: "?"}
	press(m, question) // the file field is empty and focused
	if v := view(m); !m.details || !strings.Contains(v, "Sealing does as much work as the wait") || !strings.Contains(v, "? or esc close") {
		t.Fatalf("? on page 1:\n%s", v)
	}
	press(m, tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.details || m.screen != formScreen {
		t.Fatalf("esc did not close the panel only: help %v screen %v", m.details, m.screen)
	}

	m.in.Steps = "1h"
	m.Update(submitMsg{})
	v := view(m)
	if !strings.Contains(v, "Suggested for a 1h delay: 0x01") || !strings.Contains(v, "? details") {
		t.Fatalf("page 2:\n%s", v)
	}
	press(m, question) // the algorithm select is focused
	if v := view(m); !m.details || !strings.Contains(v, "0x04  SHA-256 chain, long step") {
		t.Fatalf("? on page 2:\n%s", v)
	}
	press(m, question)
	if m.details {
		t.Fatal("? did not close the panel")
	}
	for _, l := range strings.Split(helpText(actSeal, 1)+"\n"+helpText(actSeal, 0), "\n") {
		if n := len([]rune(l)); n > 76 {
			t.Errorf("help line of %d columns: %q", n, l)
		}
	}
}

// stage and step script a job's events, at t0 plus s seconds.
func stage(s float64, label string, total int) ops.Event {
	return ops.Event{At: t0.Add(secs(s)), Stage: label, Kind: ops.StageBegan, Total: total}
}

func step(s float64, kind chain.EventKind, worker, first, n int) ops.Event {
	return ops.Event{At: t0.Add(secs(s)), Kind: ops.StepEvent, Step: chain.Event{Kind: kind, Worker: worker, First: first, N: n}}
}

func secs(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// scripted is a job told only events, as its operation would tell it.
func scripted(events ...ops.Event) *job {
	j := newJob(context.Background(), "x", nil, false)
	for _, e := range events {
		j.event(e)
	}
	return j
}

// TestFineProgress: a long run shows movement every step, not every percent:
// fine percentages, and, one worker at a time, the step under way, filling
// over the time of the last.
func TestFineProgress(t *testing.T) {
	if p := percent(68.0 / 109636); p != "0.06%" {
		t.Errorf("percent %s", p)
	}
	s := scripted(
		stage(0, "solving", 1000),
		step(0, chain.Began, 0, 0, 1),
		step(2, chain.Finished, 0, 0, 1),
		step(2, chain.Began, 0, 1, 1),
	).snapshot()
	if s.Done != 1 || s.StepAvg != 2*time.Second || s.Rate != 0.5 || s.Workers[0].First != 1 {
		t.Fatalf("one step in 2 s: %+v", s.Run)
	}
	lay := newBarLayout(100, s.Run)
	if f, _ := inFlight(time.Second, s.StepAvg); f != 0.5 || stepView(lay, s.Workers[0], s.StepAvg, t0.Add(3*time.Second)) == "" {
		t.Fatalf("1 s into a 2 s step: fill %v", f)
	}
}

// TestWorkBar: a parallel run shows its steps under way before any
// finishes, and, once finished, as finished.
func TestWorkBar(t *testing.T) {
	j := scripted(
		stage(0, "sealing", 5),
		step(0, chain.Began, 0, 0, 1),
		step(0, chain.Began, 1, 1, 1),
		step(0, chain.Began, 2, 2, 1),
	)
	if got := fmt.Sprint(workCells(5, j.snapshot().Run)); got != fmt.Sprint([]int{cellBusy, cellBusy, cellBusy, cellPending, cellPending}) {
		t.Errorf("before any step ends, cells %s", got)
	}
	for _, e := range []ops.Event{
		step(1, chain.Finished, 0, 0, 1),
		step(1, chain.Began, 0, 3, 1),
		step(1, chain.Finished, 1, 1, 1),
		step(1, chain.Idle, 1, 0, 0),
	} {
		j.event(e)
	}
	if got := fmt.Sprint(workCells(5, j.snapshot().Run)); got != fmt.Sprint([]int{cellDone, cellDone, cellBusy, cellBusy, cellPending}) {
		t.Errorf("after moves, cells %s", got)
	}
}

// TestCancel: cancelling asks first, then stops the operation, which reports
// as cancelled rather than failed.
func TestCancel(t *testing.T) {
	m := newModel(context.Background(), "")
	started := make(chan struct{})
	m.start("Solving forever", func(ctx context.Context, env *ops.Env) (any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	done := make(chan tea.Msg)
	go func() { done <- m.job.run() }()
	<-started

	press(m, ctrlC)
	if !m.confirm || m.job.snapshot().cancelled {
		t.Fatal("ctrl+c did not ask, or cancelled without asking")
	}
	press(m, tea.KeyPressMsg{Code: 'n', Text: "n"})
	if m.confirm || m.job.snapshot().cancelled {
		t.Fatal("n did not keep going")
	}
	press(m, ctrlC)
	press(m, keyY)
	m.Update(<-done)
	if m.screen != resultScreen || !m.res.cancelled {
		t.Fatalf("after y: screen %v, cancelled %v", m.screen, m.res.cancelled)
	}
}

// choose opens act from the menu by its key in menuKeys.
func choose(t *testing.T, m *model, act action) {
	t.Helper()
	k := menuKey(act)
	press(m, tea.KeyPressMsg{Code: []rune(k)[0], Text: k})
	if m.screen != formScreen || m.act != act {
		t.Fatalf("key %s: screen %v act %v, want %s", k, m.screen, m.act, actions[act].name)
	}
}

// toMenu leaves a form for the menu, a page at a time, as esc does.
func toMenu(t *testing.T, m *model) {
	t.Helper()
	for range m.page + 1 {
		m.Update(backMsg{})
	}
	if m.screen != menuScreen {
		t.Fatalf("back: screen %v, want the menu", m.screen)
	}
}

func TestMenu(t *testing.T) {
	m := newModel(context.Background(), "x"+store.PayloadSuffix)
	if m.cursor != actBypass {
		t.Fatalf("a payload preselects %v", actions[m.cursor].name)
	}
	v := view(m)
	for _, s := range []string{"Seal", "Bypass", "test build", "file: x.payload"} {
		if !strings.Contains(v, s) {
			t.Errorf("menu lacks %q:\n%s", s, v)
		}
	}
	// enter takes the preselected action.
	press(m, enter)
	if m.screen != formScreen || m.act != actBypass {
		t.Fatalf("enter: screen %v act %v", m.screen, m.act)
	}
	toMenu(t, m)

	// Each action's menu key opens it, and every action with a file field
	// starts from the file given, whether or not it suits (Bench has none).
	for act := range action(len(actions)) {
		choose(t, m, act)
		if act != actBench && m.in.File != "x.payload" {
			t.Errorf("%s started with %q, not the file given", actions[act].name, m.in.File)
		}
		toMenu(t, m)
	}
	choose(t, m, actBench)
	if !strings.Contains(view(m), "Algorithm") {
		t.Fatalf("bench has no algorithm field:\n%s", view(m))
	}
	if _, ok := alg.Lookup(m.in.Alg); !ok {
		t.Fatalf("default alg %v undefined", m.in.Alg)
	}
}
