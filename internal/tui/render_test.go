package tui

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"chainlock/alg"
	"chainlock/internal/ops"
	"chainlock/internal/store"
)

var update = flag.Bool("update", false, "rewrite the rendered screens in testdata/")

// t0 is the synthetic instant every frame here is drawn at.
var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// solving is an Open of a long-step lock, 3 s into step 3 of 219.
func solving(total, done int) snapshot {
	return snapshot{
		stage: "solving", stageStart: t0.Add(-35 * time.Second), done: done, total: total,
		workers: []worker{{first: done, n: 1, since: t0.Add(-3 * time.Second)}},
		claimed: done + 1,
		stepAvg: 16500 * time.Millisecond, rate: 1 / 16.5, eta: time.Duration(total-done) * 16500 * time.Millisecond,
	}
}

// busy is n workers, each part way through one step, from step first on.
func busy(n, first int) []worker {
	ws := make([]worker, n)
	for i := range ws {
		ws[i] = worker{first: first + i, n: 1, since: t0.Add(-time.Duration(i*29%19) * 100 * time.Millisecond)}
	}
	return ws
}

// frames are synthetic run screens: any state, drawn without running anything.
var frames = map[string]runFrame{
	"open-long":     {title: "Opening notes.chainlock.tar", start: t0.Add(-35 * time.Second), now: t0, run: solving(219, 2)},
	"open-millions": {title: "Opening big.lock", start: t0.Add(-35 * time.Second), now: t0, run: solving(3_000_000, 1_234_567)},
	// Ten workers on 120 steps: the work under way shows as its own span.
	"seal-ten": {title: "Sealing notes.txt", start: t0.Add(-20 * time.Second), now: t0, run: snapshot{
		stage: "sealing", stageStart: t0.Add(-18 * time.Second), done: 40, total: 120, claimed: 50,
		workers: busy(10, 40), stepAvg: 4 * time.Second, rate: 2.2, eta: 36 * time.Second,
	}},
	"seal-many": {title: "Sealing notes.txt", start: t0.Add(-20 * time.Second), now: t0, run: snapshot{
		stage: "sealing", stageStart: t0.Add(-18 * time.Second), done: 300, total: 1000, claimed: 364,
		workers: busy(64, 300), stepAvg: 2500 * time.Millisecond, rate: 25, eta: 28 * time.Second,
	}},
	// Four workers on 76001 steps: the work under way is a cell.
	"seal-long": {title: "Sealing notes.txt", start: t0.Add(-90 * time.Second), now: t0, run: snapshot{
		stage: "sealing", stageStart: t0.Add(-40 * time.Second), done: 8, total: 76001, claimed: 12,
		workers: busy(4, 8), stepAvg: 16500 * time.Millisecond, rate: 0.2, eta: 4*24*time.Hour + 9*time.Hour,
	}},
	// The GPU, 12 steps at a time on 30: the batch under way, and its bar.
	"seal-gpu": {title: "Sealing notes.txt", start: t0.Add(-60 * time.Second), now: t0, run: snapshot{
		stage: "sealing", stageStart: t0.Add(-55 * time.Second), done: 12, total: 30, claimed: 24,
		workers:  []worker{{first: 12, n: 12, since: t0.Add(-15 * time.Second)}},
		batchAvg: 40 * time.Second, rate: 0.3, eta: time.Minute,
	}},
	"seal-quick": {title: "Sealing notes.txt", start: t0.Add(-20 * time.Second), now: t0, run: snapshot{
		stage: "sealing", stageStart: t0.Add(-18 * time.Second), done: 144, total: 113693, claimed: 147,
		workers: append(busy(3, 144), worker{first: -1, since: t0.Add(-time.Second)}),
		stepAvg: 480 * time.Millisecond, rate: 8, eta: 3*time.Hour + 56*time.Minute,
		notes: []ops.Note{
			{Kind: ops.Detail, Text: "measured step 380ms → 113693 sequential steps for 12h on this machine"},
			{Kind: ops.Warning, Text: "argon2id-m256M-t3-p1 uses 256 MiB per evaluation; 4 parallel workers need 1 GiB (set fewer workers to lower)"},
		},
	}},
	"measuring-confirm": {title: "Sealing notes.txt", start: t0.Add(-6 * time.Second), now: t0, confirm: true, run: snapshot{
		stage: "measuring", stageStart: t0.Add(-6 * time.Second), total: 3,
		workers: []worker{{first: 0, n: 1, since: t0.Add(-6 * time.Second)}}, claimed: 1,
	}},
}

// results are synthetic result screens.
var results = map[string]*result{
	"info": {title: "Checking notes.txt.lock", act: actInfo, elapsed: 7 * time.Millisecond, value: &ops.Info{
		Alg: mustAlg(alg.Argon2id1GT30), N: 76000, Size: 1 + 76002*32, Form: store.FormFile,
		PayloadWhere: "notes.txt.payload",
	}},
	"bench": {title: "Timing 0x01 (argon2id-m256M-t3-p1)", act: actBench, elapsed: 1100 * time.Millisecond, value: ops.Bench{
		Alg: mustAlg(alg.Argon2id256M), Step: 353 * time.Millisecond,
		Rounds: []ops.BenchRound{{At: 2, Rate: 4.8}, {At: 4, Rate: 7.5}},
		Rows: []ops.BenchRow{
			{N: 0, Solve: 353 * time.Millisecond, Seal: 353 * time.Millisecond, Size: 65},
			{N: 9_999, Solve: 3530 * time.Second, Seal: 1333 * time.Second, Size: 320033},
			{N: 999_999, Solve: 353000 * time.Second, Seal: 133333 * time.Second, Size: 32000033},
		},
	}},
	"failed": {title: "Opening notes.txt.lock", act: actOpen, elapsed: 3 * time.Millisecond,
		err: errors.New("notes.txt already exists; give --out to choose where the plaintext goes")},
	"cancelled": {title: "Sealing notes.txt", act: actSeal, cancelled: true, err: context.Canceled},
	// Bench and Info return their zero value with an error: no panel, no panic.
	"bench-cancelled": {title: "Timing 0x02 (argon2id-m1G-t30-p1)", act: actBench, cancelled: true,
		err: context.Canceled, value: ops.Bench{}},
	"info-failed": {title: "Checking notes.txt", act: actInfo, err: errors.New("notes.txt: chainlock: malformed object"),
		value: (*ops.Info)(nil)},
	"sealed": {title: "Sealing notes.txt", act: actSeal, elapsed: 3*time.Hour + 2*time.Minute, notes: []ops.Note{
		{Kind: ops.Detail, Text: "algorithm 0x01 (argon2id-m256M-t3-p1) for a delay of 12h (no algorithm given; 0x02 from 1d up)"},
		{Kind: ops.Detail, Text: "measured step 380ms → 113693 sequential steps for 12h on this machine"},
		{Kind: ops.Warning, Text: "argon2id-m256M-t3-p1 uses 256 MiB per evaluation; 4 parallel workers need 1 GiB (set fewer workers to lower)"},
		{Kind: ops.Detail, Text: "sealing computes all 113693 steps, the solver's whole work, split 4 ways: at least 3h0m0s here"},
		{Kind: ops.Wrote, Text: "wrote notes.txt.lock (3.5 MiB, N=113692, 113693 steps)"},
		{Kind: ops.Wrote, Text: "wrote notes.txt.payload (108 B, encrypted)"},
		{Kind: ops.Wrote, Text: "wrote key to notes.key: it opens the encrypted file at once, without solving"},
	}},
}

// TestMenuKeys: every action has exactly one key in actionKeys, and none is
// a key the menu already uses.
func TestMenuKeys(t *testing.T) {
	count := map[action]int{}
	others := []key.Binding{menuKeys.Up, menuKeys.Down, menuKeys.Pick, menuKeys.Quit}
	for k, a := range actionKeys {
		count[a]++
		press := tea.KeyPressMsg{Code: []rune(k)[0], Text: k}
		if key.Matches(press, others...) {
			t.Errorf("menu key %q opens %s but already means something else", k, actions[a].name)
		}
	}
	for act := range action(len(actions)) {
		if count[act] != 1 {
			t.Errorf("%s has %d menu keys, want 1", actions[act].name, count[act])
		}
	}
}

func mustAlg(id alg.ID) alg.Alg {
	a, _ := alg.Lookup(id)
	return a
}

// TestRenderedScreens compares each synthetic screen, as text at 100
// columns, with testdata/NAME.txt; -update rewrites them. Reading those
// files is the quick way to see a change to any screen.
func TestRenderedScreens(t *testing.T) {
	if ops.TestBuild() {
		t.Skip("the screens are drawn for the default build, without the test algorithms and their banner")
	}
	// The same machine everywhere: 4 cores.
	oldCores := cores
	defer func() { cores = oldCores }()
	cores = 4
	screens := map[string]string{}
	h := newHelp()
	for name, f := range frames {
		screens["run-"+name] = chrome(100, false, false, []string{renderRun(100, f)}, h.ShortHelpView([]key.Binding{runKeys.Cancel}))
	}
	for name, r := range results {
		screens["result-"+name] = chrome(100, false, false, []string{renderResult(r)}, h.ShortHelpView([]key.Binding{resultKeys.Menu, resultKeys.Quit}))
	}
	m := newModel(context.Background(), "notes.txt")
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	screens["menu"] = m.View().Content
	m.gpu = true
	screens["menu-gpu"] = m.View().Content
	m.gpu = false
	for act := range action(len(actions)) {
		for page := range pages(act) {
			m.screen, m.act, m.page, m.in = formScreen, act, page, &inputs{Steps: "12h", Alg: alg.Argon2id256M}
			if page > 0 {
				m.in.File = "notes.txt" // as page 1 collected it
			}
			m.openForm()
			screens[fmt.Sprintf("form-%s-%d", strings.ToLower(actions[act].name), page+1)] = m.View().Content
		}
	}
	for name, s := range screens {
		got := ansi.Strip(s)
		got = strings.Join(trimRight(strings.Split(got, "\n")), "\n") + "\n"
		path := filepath.Join("testdata", name+".txt")
		if *update {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run with -update to create)", err)
		}
		if got != string(want) {
			t.Errorf("%s changed (run with -update to accept):\n%s", name, got)
		}
	}
}

func trimRight(lines []string) []string {
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return lines
}

// TestBarLayout: the two bars line up, keep their place and width from the
// first step to the last however many digits the total has, and fit.
func TestBarLayout(t *testing.T) {
	for _, total := range []int{13, 219, 3_000_000} {
		for _, width := range []int{70, 100, 160} {
			var shape string
			for _, done := range []int{0, 1, total / 2, total - 1} {
				lines := strings.Split(ansi.Strip(renderRun(width, runFrame{start: t0, now: t0, run: solving(total, done)})), "\n")
				main, step := lines[1], lines[2]
				barAt := strings.IndexAny(main, "▌░")
				if s := strings.IndexAny(step, "▌░"); s != barAt {
					t.Fatalf("total %d width %d done %d: bars start at %d and %d\n%s\n%s", total, width, done, barAt, s, main, step)
				}
				if w := ansi.StringWidth(main) + 4; w > width {
					t.Fatalf("total %d done %d: %d columns in a %d window\n%s", total, done, w, width, main)
				}
				s := strings.Repeat("x", barAt) + "|" + strings.Repeat("x", ansi.StringWidth(main))
				if shape == "" {
					shape = s
				} else if s != shape {
					t.Fatalf("total %d width %d: layout moved at done %d\n%s", total, width, done, main)
				}
			}
		}
	}
}
