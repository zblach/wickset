//go:build wickset_testalgs

// Tests of the TUI's model, driven through Update and View directly against
// the cheap private-use algorithms:
//
//	go test -tags wickset_testalgs ./internal/tui
package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"wickset/alg"
	"wickset/internal/ops"
	"wickset/internal/store"
	"wickset/wick"
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
	if _, err := os.Stat(plain + store.ArchiveSuffix); m.res.err != nil || err != nil {
		t.Fatalf("seal: %v; the archive: %v", m.res.err, err)
	}
	// CONTAINER.md §5: the key is saved, never shown.
	key, _, err := store.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v, key.Encode()[len("wickset-key-v1:"):]) {
		t.Fatalf("the key appears on screen:\n%s", v)
	}

	press(m, enter)
	if m.screen != menuScreen {
		t.Fatalf("enter on a result: screen %v, want the menu", m.screen)
	}

	out := filepath.Join(dir, "opened")
	v = submit(t, m, actOpen, &inputs{File: plain + store.ArchiveSuffix, Out: out})
	if got, _ := os.ReadFile(out); m.res.err != nil || string(got) != "attack at dawn" {
		t.Fatalf("open: %v, wrote %q\n%s", m.res.err, got, v)
	}

	out = filepath.Join(dir, "bypassed")
	submit(t, m, actBypass, &inputs{File: plain + store.ArchiveSuffix, Key: keyFile, Out: out})
	if got, _ := os.ReadFile(out); m.res.err != nil || string(got) != "attack at dawn" {
		t.Fatalf("bypass: %v, wrote %q", m.res.err, got)
	}

	submit(t, m, actInfo, &inputs{File: plain + store.ArchiveSuffix})
	if in, ok := m.res.value.(*ops.Info); m.res.err != nil || !ok || in.N != 4 || in.PayloadErr != nil || in.Form != store.FormArchive {
		t.Fatalf("info: %v, %+v", m.res.err, m.res.value)
	}
}

// TestRefusals: what the CLI refuses before solving, the TUI refuses too.
func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	os.WriteFile(plain, []byte("x"), 0o600)
	m := newModel(context.Background(), "")
	submit(t, m, actSeal, &inputs{File: plain, Alg: 0xFE, Steps: "1", Form: store.FormFile})

	// The default output, plain, exists, and is left as it was.
	submit(t, m, actOpen, &inputs{File: plain + store.WickSuffix})
	if got, _ := os.ReadFile(plain); m.res.err == nil || string(got) != "x" {
		t.Fatalf("open over an existing file: %v, which now holds %q", m.res.err, got)
	}
	// Standard streams belong to the TUI: refused before anything is written.
	out := filepath.Join(dir, "o")
	submit(t, m, actOpen, &inputs{File: plain + store.WickSuffix, Out: out, KeyOut: "-"})
	if _, err := os.Stat(out); m.res.err == nil || err == nil {
		t.Fatalf("key to '-': %v, and the output was written", m.res.err)
	}
	for _, s := range []string{"-", "wickset-key-v1:AAAA", ""} {
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
// the algorithm ops.AlgFor picks for that delay, with the GPU or without,
// naming it; esc goes back keeping the delay, and a step count keeps a pick.
func TestSealPages(t *testing.T) {
	for _, gpu := range []bool{false, true} {
		m := newModel(context.Background(), "")
		m.gpu = gpu
		m.pick(actSeal)
		var want alg.ID
		for _, steps := range []string{"8h", "36h", "2 weeks", "6M", "336h"} {
			m.in.Steps = steps
			m.Update(submitMsg{})
			_, d, _ := parseSteps(steps)
			want = ops.AlgFor(d, gpu).ID()
			if m.page != 1 || m.in.Alg != want || !strings.Contains(view(m), want.String()) {
				t.Fatalf("gpu %v, %s: page %d, alg %v, want %v named\n%s", gpu, steps, m.page, m.in.Alg, want, view(m))
			}
			m.Update(backMsg{})
			if m.page != 0 || m.screen != formScreen || m.in.Steps != steps {
				t.Fatalf("esc on page 2: page %d screen %v steps %q", m.page, m.screen, m.in.Steps)
			}
		}
		m.in.Steps = "5"
		m.Update(submitMsg{})
		if m.in.Alg != want {
			t.Fatalf("gpu %v: N changed the pick to %v from %v", gpu, m.in.Alg, want)
		}
		if a := args(actSeal, m.in).(ops.SealArgs); a.Alg == nil || a.N != 5 || a.Delay != 0 {
			t.Fatalf("seal args %+v", a)
		}
		if d, short := defaultAlg(&inputs{Steps: "5", GPU: gpu}), ops.AlgFor(0, gpu).ID(); d != short {
			t.Fatalf("gpu %v: a fresh N defaults to %v, not the short step %v", gpu, d, short)
		}
	}
}

// TestHelpPanel: ? opens each seal page's own help where nothing is being
// typed, offering a way to close it; ? or esc closes it, leaving the form
// as it was. In a field with text, ? is typed instead.
func TestHelpPanel(t *testing.T) {
	m := newModel(context.Background(), "")
	m.pick(actSeal)
	question := tea.KeyPressMsg{Code: '?', Text: "?"}
	closeHelp := newHelp().ShortHelpView([]key.Binding{formKeys.Close})
	for page, close := range []tea.KeyPressMsg{{Code: tea.KeyEscape}, question} {
		if page > 0 {
			m.in.Steps = "1h"
			m.Update(submitMsg{})
		}
		press(m, question) // nothing typed in the focused field
		first, _, _ := strings.Cut(helpText(actSeal, page), "\n")
		if v := view(m); !m.details || !strings.Contains(v, first) || !strings.Contains(v, ansi.Strip(closeHelp)) {
			t.Fatalf("? on page %d: help %v\n%s", page+1, m.details, v)
		}
		press(m, close)
		if m.details || m.screen != formScreen || m.page != page {
			t.Fatalf("closing on page %d: help %v, screen %v, page %d", page+1, m.details, m.screen, m.page)
		}
	}

	m.pick(actSeal) // the file field, focused
	for _, k := range []tea.KeyPressMsg{{Code: 'a', Text: "a"}, question} {
		press(m, k)
	}
	if got, _ := m.form.GetFocusedField().GetValue().(string); m.details || got != "a?" {
		t.Fatalf("? in a field with text: help %v, field %q", m.details, got)
	}

	for page := range pages(actSeal) {
		for _, l := range strings.Split(helpText(actSeal, page), "\n") {
			if n := len([]rune(l)); n > 76 {
				t.Errorf("help line of %d columns: %q", n, l)
			}
		}
	}
}

// stage and step script a job's events, at t0 plus s seconds.
func stage(s float64, label string, total int) ops.Event {
	return ops.Event{At: t0.Add(secs(s)), Stage: label, Kind: ops.StageBegan, Total: total}
}

func step(s float64, kind wick.EventKind, worker, first, n int) ops.Event {
	return ops.Event{At: t0.Add(secs(s)), Kind: ops.StepEvent, Step: wick.Event{Kind: kind, Worker: worker, First: first, N: n}}
}

func secs(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// scripted is a job told only events, as its operation would tell it.
func scripted(events ...ops.Event) *job {
	j := newJob(context.Background(), "x", nil, false, ops.Budget{})
	for _, e := range events {
		j.event(e)
	}
	return j
}

// TestFineProgress: a long run shows movement every step, not every percent:
// fine percentages, and, one worker at a time, the step under way, against
// the time of the last until it reports how far it is.
func TestFineProgress(t *testing.T) {
	if p := percent(68.0 / 109636); p != "0.06%" {
		t.Errorf("percent %s", p)
	}
	j := scripted(
		stage(0, "solving", 1000),
		step(0, wick.Began, 0, 0, 1),
		step(2, wick.Finished, 0, 0, 1),
		step(2, wick.Began, 0, 1, 1),
	)
	s := j.snapshot()
	if s.Done != 1 || s.StepAvg != 2*time.Second || s.Rate != 0.5 || s.Workers[0].First != 1 {
		t.Fatalf("one step in 2 s: %+v", s.Run)
	}
	estimated := flightView(s.Run, t0.Add(3*time.Second))
	partway := step(4, wick.Partway, 0, 1, 1)
	partway.Step.Part, partway.Step.OfParts = 1, 4
	j.event(partway)
	reported := flightView(j.snapshot().Run, t0.Add(4*time.Second))
	if estimated == "" || reported == "" || estimated == reported {
		t.Fatalf("in flight, estimated %q, then reported %q", estimated, reported)
	}
	if flightView(scripted(stage(0, "sealing", 10), step(0, wick.Began, 0, 0, 1), step(0, wick.Began, 1, 1, 1)).snapshot().Run, t0) != "" {
		t.Fatal("many workers: a line in flight, not the bar alone")
	}
}

// TestWorkBar: a parallel run shows its steps under way before any
// finishes, and, once finished, as finished.
func TestWorkBar(t *testing.T) {
	j := scripted(
		stage(0, "sealing", 5),
		step(0, wick.Began, 0, 0, 1),
		step(0, wick.Began, 1, 1, 1),
		step(0, wick.Began, 2, 2, 1),
	)
	if got := fmt.Sprint(workCells(5, j.snapshot().Run)); got != fmt.Sprint([]int{cellBusy, cellBusy, cellBusy, cellPending, cellPending}) {
		t.Errorf("before any step ends, cells %s", got)
	}
	for _, e := range []ops.Event{
		step(1, wick.Finished, 0, 0, 1),
		step(1, wick.Began, 0, 3, 1),
		step(1, wick.Finished, 1, 1, 1),
		step(1, wick.Idle, 1, 0, 0),
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
	want := []string{m.initial, "test build"} // the file given, and the test build's banner
	for _, a := range actions {
		want = append(want, a.name)
	}
	for _, s := range want {
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
	if _, ok := alg.Lookup(m.in.Alg); !ok {
		t.Fatalf("default alg %v undefined", m.in.Alg)
	}
}
