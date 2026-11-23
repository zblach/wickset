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

	"github.com/zblach/wickset/alg"
	"github.com/zblach/wickset/internal/ops"
	"github.com/zblach/wickset/internal/store"
)

var dump = flag.String("screens", "", "write every synthetic screen to this directory, to read a change by")

// t0 is the synthetic instant every frame here is drawn at.
var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// solving is an Open of a long-step wick, 3 s into step 3 of 219.
func solving(total, done int) snapshot {
	return snapshot{Run: ops.Run{
		Stage: "solving", Start: t0.Add(-35 * time.Second), Done: done, Total: total,
		Workers: []ops.Worker{{First: done, N: 1, Since: t0.Add(-3 * time.Second)}},
		Claimed: done + 1,
		StepAvg: 16500 * time.Millisecond, Rate: 1 / 16.5, ETA: time.Duration(total-done) * 16500 * time.Millisecond,
	}}
}

// busy is n workers, each part way through one step, from step first on.
func busy(n, first int) []ops.Worker {
	ws := make([]ops.Worker, n)
	for i := range ws {
		ws[i] = ops.Worker{First: first + i, N: 1, Since: t0.Add(-time.Duration(i*29%19) * 100 * time.Millisecond)}
	}
	return ws
}

// frames are synthetic run screens: any state, drawn without running anything.
var frames = map[string]runFrame{
	"open-long":     {title: "Opening notes.wick", start: t0.Add(-35 * time.Second), now: t0, run: solving(219, 2)},
	"open-millions": {title: "Opening big.wick", start: t0.Add(-35 * time.Second), now: t0, run: solving(3_000_000, 1_234_567)},
	// Ten workers on 120 steps: the work under way shows as its own span.
	"seal-ten": {title: "Sealing notes.txt", start: t0.Add(-20 * time.Second), now: t0, run: snapshot{Run: ops.Run{
		Stage: "sealing", Start: t0.Add(-18 * time.Second), Done: 40, Total: 120, Claimed: 50,
		Workers: busy(10, 40), StepAvg: 4 * time.Second, Rate: 2.2, ETA: 36 * time.Second,
	}}},
	"seal-many": {title: "Sealing notes.txt", start: t0.Add(-20 * time.Second), now: t0, run: snapshot{Run: ops.Run{
		Stage: "sealing", Start: t0.Add(-18 * time.Second), Done: 300, Total: 1000, Claimed: 364,
		Workers: busy(64, 300), StepAvg: 2500 * time.Millisecond, Rate: 25, ETA: 28 * time.Second,
	}}},
	// Four workers on 76001 steps: the work under way is a cell.
	"seal-long": {title: "Sealing notes.txt", start: t0.Add(-90 * time.Second), now: t0, run: snapshot{Run: ops.Run{
		Stage: "sealing", Start: t0.Add(-40 * time.Second), Done: 8, Total: 76001, Claimed: 12,
		Workers: busy(4, 8), StepAvg: 16500 * time.Millisecond, Rate: 0.2, ETA: 4*24*time.Hour + 9*time.Hour,
	}}},
	// The GPU, 12 steps at a time on 30: the batch under way, and its bar.
	"seal-gpu": {title: "Sealing notes.txt", start: t0.Add(-60 * time.Second), now: t0, run: snapshot{Run: ops.Run{
		Stage: "sealing", Start: t0.Add(-55 * time.Second), Done: 12, Total: 30, Claimed: 24, Batch: 12,
		Workers:  []ops.Worker{{First: 12, N: 12, Since: t0.Add(-15 * time.Second)}},
		BatchAvg: 40 * time.Second, Rate: 0.3, ETA: time.Minute,
	}}},
	"seal-quick": {title: "Sealing notes.txt", start: t0.Add(-20 * time.Second), now: t0, run: snapshot{
		Run: ops.Run{
			Stage: "sealing", Start: t0.Add(-18 * time.Second), Done: 144, Total: 113693, Claimed: 147,
			Workers: append(busy(3, 144), ops.Worker{First: -1, Idle: true}),
			StepAvg: 480 * time.Millisecond, Rate: 8, ETA: 3*time.Hour + 56*time.Minute,
		},
		notes: []ops.Note{
			{Kind: ops.Detail, Text: "measured step 380ms → 113693 sequential steps for 12h on this machine"},
			{Kind: ops.Warning, Text: "argon2id-m128M-t5-p1 uses 128 MiB per evaluation; 8 parallel workers need 1 GiB (set fewer workers to lower)"},
		},
	}},
	"measuring-confirm": {title: "Sealing notes.txt", start: t0.Add(-6 * time.Second), now: t0, confirm: true, run: snapshot{Run: ops.Run{
		Stage: "measuring", Start: t0.Add(-6 * time.Second), Total: 3,
		Workers: []ops.Worker{{First: 0, N: 1, Since: t0.Add(-6 * time.Second)}}, Claimed: 1,
	}}},
}

// results are synthetic result screens.
var results = map[string]*result{
	"info": {title: "Checking notes.txt.wick", act: actInfo, elapsed: 7 * time.Millisecond, value: &ops.Info{
		Alg: mustAlg(alg.Argon2idLong), N: 76000, Size: 1 + 76002*32, Form: store.FormFile,
		PayloadWhere: "notes.txt.payload",
	}},
	"bench": {title: "Timing 0x01 (argon2id-m128M-t5-p1)", act: actBench, elapsed: 1100 * time.Millisecond, value: ops.Bench{
		Alg: mustAlg(alg.Argon2idShort), Step: 353 * time.Millisecond,
		Rounds: []ops.BenchRound{{At: 2, Rate: 4.8}, {At: 4, Rate: 7.5}},
		Rows: []ops.BenchRow{
			{N: 0, Solve: 353 * time.Millisecond, Seal: 353 * time.Millisecond, Size: 65},
			{N: 9_999, Solve: 3530 * time.Second, Seal: 1333 * time.Second, Size: 320033},
			{N: 999_999, Solve: 353000 * time.Second, Seal: 133333 * time.Second, Size: 32000033},
		},
	}},
	"failed": {title: "Opening notes.txt.wick", act: actOpen, elapsed: 3 * time.Millisecond,
		err: errors.New("notes.txt already exists; give --out to choose where the plaintext goes")},
	"cancelled": {title: "Sealing notes.txt", act: actSeal, cancelled: true, err: context.Canceled},
	// Bench and Info return their zero value with an error: no panel, no panic.
	"bench-cancelled": {title: "Timing 0x02 (argon2id-m128M-t192-p1)", act: actBench, cancelled: true,
		err: context.Canceled, value: ops.Bench{}},
	"info-failed": {title: "Checking notes.txt", act: actInfo, err: errors.New("notes.txt: wickset: malformed wick"),
		value: (*ops.Info)(nil)},
	"sealed": {title: "Sealing notes.txt", act: actSeal, elapsed: 3*time.Hour + 2*time.Minute, notes: []ops.Note{
		{Kind: ops.Detail, Text: "algorithm 0x01 (argon2id-m128M-t5-p1) for a delay of 12h (no algorithm given; the long step from 1d up)"},
		{Kind: ops.Detail, Text: "measured step 380ms → 113693 sequential steps for 12h on this machine"},
		{Kind: ops.Warning, Text: "argon2id-m128M-t5-p1 uses 128 MiB per evaluation; 8 parallel workers need 1 GiB (set fewer workers to lower)"},
		{Kind: ops.Detail, Text: "sealing computes all 113693 steps, the solver's whole work, split 4 ways: at least 3h0m0s here"},
		{Kind: ops.Wrote, Text: "wrote notes.txt.wick (3.5 MiB, N=113692, 113693 steps)"},
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

// drawn is one synthetic screen: its text, unstyled, and the help line it
// should end with.
type drawn struct {
	text, help string
	result     *result // for a result screen
}

// screens draws every synthetic screen at width columns: each run frame and
// result, the menu with and without the GPU, and each page of each form.
func screens(width int) map[string]drawn {
	out := map[string]drawn{}
	h := newHelp()
	runHelp := h.ShortHelpView([]key.Binding{runKeys.Cancel})
	for name, f := range frames {
		out["run-"+name] = drawn{text: chrome(width, false, false, []string{renderRun(width, f)}, runHelp), help: runHelp}
	}
	resHelp := h.ShortHelpView([]key.Binding{resultKeys.Menu, resultKeys.Quit})
	for name, r := range results {
		out["result-"+name] = drawn{text: chrome(width, false, false, []string{renderResult(r)}, resHelp), help: resHelp, result: r}
	}
	m := newModel(context.Background(), "notes.txt")
	m.Update(tea.WindowSizeMsg{Width: width, Height: 40})
	for _, gpu := range []bool{false, true} {
		m.gpu = gpu
		name := "menu"
		if gpu {
			name += "-gpu"
		}
		out[name] = drawn{text: m.View().Content, help: m.helpLine()}
	}
	m.gpu = false
	for act := range action(len(actions)) {
		for page := range pages(act) {
			m.screen, m.act, m.page, m.in = formScreen, act, page, &inputs{Steps: "12h", Alg: alg.Argon2idShort}
			if page > 0 {
				m.in.File = "notes.txt" // as page 1 collected it
			}
			m.openForm()
			out[fmt.Sprintf("form-%s-%d", strings.ToLower(actions[act].name), page+1)] = drawn{text: m.View().Content, help: m.helpLine()}
		}
	}
	for name, s := range out {
		s.text = strings.Join(trimRight(strings.Split(ansi.Strip(s.text), "\n")), "\n") + "\n"
		s.help = ansi.Strip(s.help)
		out[name] = s
	}
	return out
}

// TestScreens draws every synthetic screen and holds it to what any wording
// must keep: it fits the window, has the title and its help line, has no
// formatting slip, and a failed or cancelled result shows no panel. With
// -screens DIR it also writes each to DIR/NAME.txt, to read a change by.
func TestScreens(t *testing.T) {
	if ops.TestBuild() {
		t.Skip("the screens are drawn for the default build, without the test algorithms and their banner")
	}
	// The same machine everywhere: 4 cores.
	oldCores := cores
	defer func() { cores = oldCores }()
	cores = 4
	const width = 100
	for name, s := range screens(width) {
		if *dump != "" {
			if err := os.WriteFile(filepath.Join(*dump, name+".txt"), []byte(s.text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for i, l := range strings.Split(s.text, "\n") {
			if w := ansi.StringWidth(l); w > width {
				t.Errorf("%s line %d: %d columns in a %d-column window\n%s", name, i+1, w, width, l)
			}
		}
		if !strings.Contains(s.text, "wickset") || !strings.Contains(s.text, s.help) || strings.Contains(s.text, "%!") {
			t.Errorf("%s: no title, no help line %q, or a formatting slip:\n%s", name, s.help, s.text)
		}
		if r := s.result; r != nil && r.err != nil && strings.Contains(s.text, "╭") {
			t.Errorf("%s: a panel for a result that failed:\n%s", name, s.text)
		}
	}
}

func trimRight(lines []string) []string {
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return lines
}

// TestBarLayout: the bar keeps its place and width from the first step to
// the last however many digits the total has, and fits; what is in flight
// is written under it, from its first column.
func TestBarLayout(t *testing.T) {
	for _, total := range []int{13, 219, 3_000_000} {
		for _, width := range []int{70, 100, 160} {
			var shape string
			for _, done := range []int{0, 1, total / 2, total - 1} {
				lines := strings.Split(ansi.Strip(renderRun(width, runFrame{start: t0, now: t0, run: solving(total, done)})), "\n")
				main, flight := lines[1], lines[2]
				barAt := ansi.StringWidth(main[:strings.IndexAny(main, "█▓░")])
				if at := len(flight) - len(strings.TrimLeft(flight, " ")); at != barAt {
					t.Fatalf("total %d width %d done %d: the bar at %d, what's in flight at %d\n%s\n%s", total, width, done, barAt, at, main, flight)
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
