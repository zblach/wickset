package tui

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"

	"wickset/internal/ops"
	"wickset/internal/store"
)

// Rendering here is pure: a screen is a function of the window width and a
// value describing what to show, including the instant shown. The model
// builds those values from its live state; tests and previews build them by
// hand (render_test.go), so any state can be drawn without running anything.

// chrome frames a screen: the title, wickset[gpu] when the GPU computes,
// the test-build banner if testBuild, the parts with a blank line between
// each, and the help line (styled by its maker, help.Model), within margins.
func chrome(width int, testBuild, gpu bool, parts []string, help string) string {
	title := "wickset"
	if gpu {
		title += "[gpu]"
	}
	all := []string{titleStyle.Render(title)}
	if testBuild {
		b := bannerStyle
		if width > 0 {
			b = b.Width(min(width-4, 84)) // within the margins; wraps the text
		}
		all = append(all, b.Render(ops.TestBuildWarning))
	}
	all = append(all, parts...)
	all = append(all, help)
	frame := lipgloss.NewStyle().Margin(1, 2)
	if width > 0 {
		frame = frame.Width(width - 2) // wraps long paths and errors within the margins
	}
	return frame.Render(lipgloss.JoinVertical(lipgloss.Left, join(all)...))
}

// join puts a blank line between parts.
func join(parts []string) []string {
	var out []string
	for i, p := range parts {
		if i > 0 {
			out = append(out, "")
		}
		out = append(out, p)
	}
	return out
}

// runFrame is the run screen at one instant.
type runFrame struct {
	title   string
	spinner string    // the spinner's frame
	start   time.Time // when the job began
	now     time.Time // the instant shown; every elapsed time runs to it
	run     snapshot
	confirm bool // asking whether to cancel
}

// renderRun draws the run screen's body for a window width columns wide.
func renderRun(width int, f runFrame) string {
	s := f.run
	el := f.now.Sub(f.start)
	lines := []string{f.spinner + headStyle.Render(f.title)}
	switch {
	case s.cancelled:
		lines = append(lines, warnStyle.Render("cancelling: stopping every worker mid-step…"))
	case s.Total == 0:
		lines = append(lines, subtleStyle.Render(fmt.Sprintf("preparing…  %v", el.Round(time.Second))))
	default:
		// Long runs move the bar a cell every few minutes, so the numbers
		// beside it are fine enough to move every step.
		pace, eta := "estimating", "estimating"
		if r := s.Rate; r > 0 {
			eta = ops.Span(s.ETA)
			if r >= 1 {
				pace = fmt.Sprintf("%.1f steps/s", r)
			} else {
				pace = fmt.Sprintf("%.1fs a step", 1/r)
			}
		}
		if s.Stage == "measuring" {
			lines = append(lines, warnStyle.Render("Not sealing yet: timing the step on one core, as the solver runs it, to turn the\n"+
				"delay into a step count. Sealing then starts, on the GPU or every core."))
		}
		// Every width is set by the total, not the count so far, so nothing
		// shifts or shrinks as the count gains digits.
		lay := newBarLayout(width, s.Run)
		count := fmt.Sprintf("%d/%d steps", s.Done, s.Total) // padded to its widest, below
		lines = append(lines, fmt.Sprintf("%-*s %s %-6s %-*s",
			lay.label, s.Stage, workBar(lay.width, s.Run), percent(s.Fraction()), 2*digits(s.Total)+len("/ steps"), count))
		if l := flightView(s.Run, f.now); l != "" { // under the bar, from its first column
			lines = append(lines, strings.Repeat(" ", lay.label+1)+subtleStyle.Render(l))
		}
		batch := 0 // the GPU's batch, if the run is on one
		if len(s.Workers) == 1 {
			batch = s.Batch
		}
		stats := []string{"elapsed " + el.Round(time.Second).String()}
		switch {
		case batch > 1:
			stats = append(stats, fmt.Sprintf("GPU, batches of %d", batch))
		case len(s.Workers) > 1:
			stats = append(stats, fmt.Sprintf("%d workers", len(s.Workers)))
		}
		stats = append(stats, pace, "eta "+eta)
		lines = append(lines, subtleStyle.Render(strings.Join(stats, " · ")))
	}
	if len(s.notes) > 0 {
		lines = append(lines, "", notesView(s.notes))
	}
	if f.confirm {
		lines = append(lines, "", confirmStyle.Render(
			badStyle.Render("Cancel?")+" The work so far is discarded; nothing resumes it.\n"+
				keyStyle.Render("y")+" cancel  "+keyStyle.Render("n")+" keep going"))
	}
	return strings.Join(lines, "\n")
}

// renderResult draws the result screen's body for a finished job.
func renderResult(r *result) string {
	var head string
	switch {
	case r.cancelled:
		head = warnStyle.Render("■ Cancelled: ") + r.title + subtleStyle.Render(" (nothing was written)")
	case r.err != nil:
		head = badStyle.Render("✗ ") + r.title + badStyle.Render(" failed") + "\n" + badStyle.Render(plainError(r.err))
	default:
		head = okStyle.Render("✓ "+actions[r.act].done) + " " + strings.TrimPrefix(r.title, actions[r.act].doing+" ") +
			subtleStyle.Render(" in "+ops.Span(r.elapsed))
	}
	parts := []string{head}
	if len(r.notes) > 0 {
		parts = append(parts, notesView(r.notes))
	}
	if r.err != nil {
		// A failed or cancelled operation's value is its zero, an empty
		// Bench or a nil *Info: there is nothing to show.
		return strings.Join(parts, "\n\n")
	}
	switch v := r.value.(type) {
	case *ops.Info:
		parts = append(parts, panelStyle.Render(infoView(v)))
	case ops.Bench:
		parts = append(parts, panelStyle.Render(benchView(v)))
	}
	return strings.Join(parts, "\n\n")
}

// plainError is err as the TUI says it. ops and store name the CLI's flags
// where a different choice would help; here those are form fields.
func plainError(err error) string {
	return strings.NewReplacer(
		"give --out to choose where the plaintext goes", `choose another name under "Save as"`,
		"give --out", `fill in "Save as"`,
	).Replace(err.Error())
}

// notesView groups an operation's notes by kind, apart: what it wrote, the
// outcome, first and plain; then warnings; then how it went, dimmed.
func notesView(notes []ops.Note) string {
	var wrote, warned, detail []string
	for _, n := range notes {
		switch n.Kind {
		case ops.Wrote:
			wrote = append(wrote, okStyle.Render("✓ ")+strings.TrimPrefix(n.Text, "wrote "))
		case ops.Warning:
			warned = append(warned, warnStyle.Render("⚠ "+n.Text))
		default:
			detail = append(detail, subtleStyle.Render("· "+n.Text))
		}
	}
	var blocks []string
	for _, b := range [][]string{wrote, warned, detail} {
		if len(b) > 0 {
			blocks = append(blocks, strings.Join(b, "\n"))
		}
	}
	return strings.Join(blocks, "\n\n")
}

// storedAs says how a wick is stored, in the seal form's words.
func storedAs(f store.Form) string {
	return [...]string{
		store.FormFile:    "two files, damage check passed",
		store.FormRaw:     "raw files, no damage check",
		store.FormArchive: "one archive, damage check passed",
	}[f]
}

func infoView(in *ops.Info) string {
	encrypted := okStyle.Render("belongs to this wick, undamaged")
	switch {
	case in.PayloadMissing():
		encrypted = subtleStyle.Render("not found")
	case in.PayloadErr != nil:
		encrypted = badStyle.Render(in.PayloadErr.Error())
	}
	return Columns(KeyColumn).Rows(
		[]string{"Algorithm", in.Alg.ID().String()},
		[]string{"Steps", fmt.Sprintf("%d to open (N = %d)", in.N+1, in.N)},
		[]string{"Wick size", ops.Bytes(int64(in.Size))},
		[]string{"Stored as", storedAs(in.Form)},
		[]string{"Encrypted file", in.PayloadWhere + ": " + encrypted},
	).String()
}

func benchView(b ops.Bench) string {
	return strings.Join([]string{
		fmt.Sprintf("%v: %s a step on one core %s", b.Alg.ID(),
			headStyle.Render(b.Step.Round(time.Millisecond).String()), subtleStyle.Render("(fastest of 3)")),
		"",
		BenchTable(b).String(),
		"",
		headStyle.Render(b.SpeedUpLine()),
		subtleStyle.Render(b.Sealing()),
	}, "\n")
}

// BenchTable is bench's predictions as a table, for the CLI as well.
func BenchTable(b ops.Bench) *table.Table {
	t := Columns(HeaderRow).Headers("steps", "opens in ≈", "seals in ≈", "wick size")
	for _, r := range b.Rows {
		t.Row(strconv.Itoa(r.N+1), ops.Span(r.Solve), ops.Span(r.Seal), ops.Bytes(int64(r.Size)))
	}
	return t
}

// Columns is a table laid out by lipgloss, borderless, with two spaces
// between columns and the cells bold picks in bold. The CLI uses it too,
// printing through lipgloss, which drops the styling off a terminal.
func Columns(bold func(row, col int) bool) *table.Table {
	return table.New().
		Border(lipgloss.HiddenBorder()).
		BorderTop(false).BorderBottom(false).BorderLeft(false).BorderRight(false).
		BorderHeader(false).BorderColumn(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			s := lipgloss.NewStyle()
			if col > 0 {
				s = s.PaddingLeft(2) // not right of the last: no trailing spaces
			}
			if bold(row, col) {
				s = s.Inherit(headStyle)
			}
			return s
		})
}

// HeaderRow and KeyColumn bold a table's header, or its first column.
func HeaderRow(row, _ int) bool { return row == table.HeaderRow }
func KeyColumn(_, col int) bool { return col == 0 }

// workBar draws a run's steps in width cells, each finished, in progress or
// pending: the run's one bar, with the work under way in a second color and
// shade, so how much runs at once shows at a glance, on one worker or many.
// A cell holding any step in progress shows in progress; the steps begun are
// claimed in order, so below r.Claimed the rest are finished.
func workBar(width int, r ops.Run) string {
	var b strings.Builder
	cells := workCells(width, r)
	for i := 0; i < len(cells); {
		j := i
		for j < len(cells) && cells[j] == cells[i] {
			j++
		}
		b.WriteString(cellStyles[cells[i]].Render(strings.Repeat(cellGlyphs[cells[i]], j-i)))
		i = j
	}
	return b.String()
}

// workCells is the state of each of a workBar's width cells.
func workCells(width int, r ops.Run) []int {
	cells := make([]int, width)
	for c := range cells {
		lo := c * r.Total / width
		hi := max((c+1)*r.Total/width, lo+1)
		switch {
		case slices.ContainsFunc(r.Workers, func(w ops.Worker) bool { return w.Busy(lo, hi) }):
			cells[c] = cellBusy
		case hi <= r.Claimed:
			cells[c] = cellDone
		default:
			cells[c] = cellPending
		}
	}
	return cells
}

// The states of a workBar cell.
const (
	cellDone = iota
	cellBusy
	cellPending
)

var cellGlyphs = [...]string{cellDone: "█", cellBusy: "▓", cellPending: "░"}

// flightView says, in a line, what is in flight when one worker runs: a
// solve's step, a timing's sample or a GPU's batch, and how far it is: as
// it reported, or else against the recent time of one. Many workers show
// in the bar alone.
func flightView(r ops.Run, now time.Time) string {
	if len(r.Workers) != 1 || r.Workers[0].First < 0 {
		return ""
	}
	w := r.Workers[0]
	what, avg := fmt.Sprintf("step %d of %d", w.First+1, r.Total), r.StepAvg
	if w.N > 1 {
		what, avg = fmt.Sprintf("batch %d of %d", w.First/w.N+1, (r.Total+w.N-1)/w.N), r.BatchAvg
	}
	el := now.Sub(w.Since)
	switch {
	case w.Part > 0: // reported: how far, and what that leaves at this pace
		left := time.Duration(float64(el) * (1 - w.Part) / w.Part)
		return fmt.Sprintf("%s · %.0f%% · %s in, ~%s left", what, 100*w.Part, short(el), short(left))
	case avg > 0:
		return fmt.Sprintf("%s · %s of ~%s", what, short(el), short(avg))
	default:
		return fmt.Sprintf("%s · %s, timing the first", what, short(el))
	}
}

// short is a time in flight: tenths of a second under a minute, else a span.
func short(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return ops.Span(d)
}

// barLayout is the run bar's geometry: the label column and a bar sized to
// what the window leaves, both fixed for the run by its total.
type barLayout struct {
	label int
	width int // of the bar, in cells
}

func newBarLayout(width int, r ops.Run) barLayout {
	label := len(r.Stage)
	right := len("100.0%  ") + 2*digits(r.Total) + len("/ steps")
	bar := 40
	if width > 0 {
		// margins (2+2), the spaces either side of the bar, and the 1-column
		// slack lipgloss keeps at the right edge
		bar = min(max(width-4-label-2-right-1, 10), 50)
	}
	return barLayout{label, bar}
}

// digits is how many decimal digits n has.
func digits(n int) int { return len(strconv.Itoa(n)) }

// percent formats a fraction finely enough to change on a long run.
func percent(f float64) string {
	switch {
	case f >= 1:
		return "100%"
	case f >= 0.1:
		return fmt.Sprintf("%.1f%%", 100*f)
	}
	return fmt.Sprintf("%.2f%%", 100*f)
}
