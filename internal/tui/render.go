package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"

	"chainlock/internal/ops"
	"chainlock/internal/store"
)

// Rendering here is pure: a screen is a function of the window width and a
// value describing what to show, including the instant shown. The model
// builds those values from its live state; tests and previews build them by
// hand (render_test.go), so any state can be drawn without running anything.

// chrome frames a screen: the title, the test-build banner if testBuild, the
// parts with a blank line between each, and the help line (styled by its
// maker, help.Model), within margins.
func chrome(width int, testBuild bool, parts []string, help string) string {
	all := []string{titleStyle.Render("chainlock") + "  " + subtleStyle.Render("sequential-delay lock")}
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
	scroll  int  // the first worker bar shown
	rows    int  // how many worker bars show at once
}

// renderRun draws the run screen's body for a window width columns wide.
func renderRun(width int, f runFrame) string {
	s := f.run
	el := f.now.Sub(f.start)
	lines := []string{f.spinner + headStyle.Render(f.title)}
	switch {
	case s.cancelled:
		lines = append(lines, warnStyle.Render("cancelling: stopping every worker mid-step…"))
	case s.total == 0:
		lines = append(lines, subtleStyle.Render(fmt.Sprintf("preparing…  %v", el.Round(time.Second))))
	default:
		// Long runs move the bar a cell every few minutes, so the numbers
		// beside it are fine enough to move every step.
		pace, eta := "estimating", "estimating"
		if r := s.rate; r > 0 {
			eta = ops.Span(s.eta)
			if r >= 1 {
				pace = fmt.Sprintf("%.1f steps/s", r)
			} else {
				pace = fmt.Sprintf("%.1fs a step", 1/r)
			}
		}
		if s.stage == "measuring" {
			lines = append(lines, warnStyle.Render("Not sealing yet: timing the step on one core, as the solver runs it, to turn the\n"+
				"delay into a step count. Sealing then starts on every worker."))
		}
		// Every width is set by the total, not the count so far, so nothing
		// shifts or shrinks as the count gains digits.
		lay := newBarLayout(width, s)
		// The text right of every bar starts in one column.
		count := fmt.Sprintf("%d/%d steps", s.done, s.total) // padded to its widest, below
		lines = append(lines, fmt.Sprintf("%-*s %s %-6s %-*s",
			lay.label, s.stage, lay.bar.ViewAs(s.fraction()), percent(s.fraction()), 2*digits(s.total)+len("/ steps"), count))
		if len(s.workers) == 1 { // a solve, or timing: one step at a time
			if l := stepView(lay, s.workers[0], s.stepAvg, f.now); l != "" {
				lines = append(lines, l)
			}
		}
		stats := []string{"elapsed " + el.Round(time.Second).String()}
		if len(s.workers) > 1 {
			stats = append(stats, fmt.Sprintf("%d workers", len(s.workers)))
		}
		stats = append(stats, pace, "eta "+eta)
		lines = append(lines, subtleStyle.Render(strings.Join(stats, " · ")))
		// Each worker's own bar, set apart and in its own color, but only for
		// steps long enough to watch (barStep): quicker ones would only
		// repeat the run's bar.
		if len(s.workers) > 1 && (s.stepAvg == 0 || s.stepAvg >= barStep) {
			lines = append(lines, "")
			lines = append(lines, workerRows(lay, s.workers, s.stepAvg, f.now, f.scroll, f.rows)...)
		}
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

// storedAs says how a lock is stored, in the seal form's words.
func storedAs(f store.Form) string {
	return [...]string{
		store.FormFile:    "two files, damage check passed",
		store.FormRaw:     "raw files, no damage check",
		store.FormArchive: "one archive, damage check passed",
	}[f]
}

func infoView(in *ops.Info) string {
	encrypted := okStyle.Render("belongs to this lock, undamaged")
	switch {
	case in.PayloadMissing():
		encrypted = subtleStyle.Render("not found")
	case in.PayloadErr != nil:
		encrypted = badStyle.Render(in.PayloadErr.Error())
	}
	return Columns(KeyColumn).Rows(
		[]string{"Algorithm", in.Alg.ID().String()},
		[]string{"Steps", fmt.Sprintf("%d to open (N = %d)", in.N+1, in.N)},
		[]string{"Lock size", ops.Bytes(int64(in.Size))},
		[]string{"Stored as", storedAs(in.Form)},
		[]string{"Encrypted file", in.PayloadWhere + ": " + encrypted},
	).String()
}

func benchView(b ops.Bench) string {
	return strings.Join([]string{
		fmt.Sprintf("%v: %s a step on this machine %s", b.Alg.ID(),
			headStyle.Render(b.Step.Round(time.Millisecond).String()), subtleStyle.Render("(one core, fastest of 3)")),
		"",
		BenchTable(b).String(),
		"",
		subtleStyle.Render(fmt.Sprintf("Sealing on all %d cores; they share memory bandwidth, so it takes longer.", b.Cores)),
	}, "\n")
}

// BenchTable is bench's predictions as a table, for the CLI as well.
func BenchTable(b ops.Bench) *table.Table {
	t := Columns(HeaderRow).Headers("steps", "opens in ≈", "seals in ≥", "lock size")
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

// stepView is a run's one step in flight, as a second bar under the
// overall one.
func stepView(lay barLayout, w worker, stepAvg time.Duration, now time.Time) string {
	if w.index < 0 || w.since.IsZero() {
		return ""
	}
	label := fmt.Sprintf("%-*s", lay.label, fmt.Sprintf("step %d", w.index+1))
	f, text := inFlight(now.Sub(w.since), stepAvg)
	if stepAvg == 0 {
		text += ", timing the first"
	}
	return fmt.Sprintf("%s %s %s", label, lay.bar.ViewAs(f), subtleStyle.Render(text))
}

// inFlight estimates how far along a step is, el into it, from the recent
// step time: the bar's fill, short of full, and "el of ~avg". A step
// reports nothing until it ends, so this is all there is to show.
func inFlight(el, stepAvg time.Duration) (float64, string) {
	if stepAvg == 0 {
		return 0, fmt.Sprintf("%.1fs", el.Seconds())
	}
	return min(float64(el)/float64(stepAvg), 0.99), fmt.Sprintf("%.1fs of ~%.1fs", el.Seconds(), stepAvg.Seconds())
}

// barLayout is the shared geometry of a run's bars: the label column and a
// bar sized to what the window leaves, both fixed for the run by its total.
type barLayout struct {
	label int
	total int            // the run's step count, which sets the widths of step numbers
	bar   progress.Model // the run's overall bar, and a solve's step bar under it
	sub   progress.Model // a worker's bar: one solid color, set apart from the overall
}

// stepRightWidth bounds the text right of a step bar: "999.9s of ~999.9s".
const stepRightWidth = 17

func newBarLayout(width int, s snapshot) barLayout {
	label := max(len(s.stage), len("step ")+digits(s.total), len("worker ")+digits(len(s.workers)))
	right := max(len("100.0%  ")+2*digits(s.total)+len("/ steps"), // the overall bar's
		len("#")+digits(s.total)+1+stepRightWidth) // a worker's
	bar := 40
	if width > 0 {
		// margins (2+2), the spaces either side of the bar, and the 1-column
		// slack lipgloss keeps at the right edge
		bar = min(max(width-4-label-2-right-1, 10), 50)
	}
	return barLayout{label, s.total,
		progress.New(progress.WithDefaultBlend(), progress.WithWidth(bar), progress.WithoutPercentage()),
		progress.New(progress.WithColors(accent), progress.WithWidth(bar), progress.WithoutPercentage())}
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

// workerRows is a bar per worker, stacked under the overall bar on the same
// layout: the step it runs (inFlight), or how many it finished once it is
// through. Only rows of them show, from the scroll'th; a line under them
// says which, and how to see the rest.
func workerRows(lay barLayout, ws []worker, stepAvg time.Duration, now time.Time, scroll, rows int) []string {
	if rows <= 0 {
		rows = workerRowsFor(0)
	}
	if len(ws) == rows+1 {
		rows++ // scrolling to see one more row is not worth a line of its own
	}
	scroll = min(max(scroll, 0), max(len(ws)-rows, 0))
	var lines []string
	for w := scroll; w < min(scroll+rows, len(ws)); w++ {
		s := ws[w]
		label := fmt.Sprintf("%-*s", lay.label, fmt.Sprintf("worker %d", w+1))
		switch {
		case s.since.IsZero():
			lines = append(lines, fmt.Sprintf("%s %s %s", label, lay.sub.ViewAs(0), subtleStyle.Render("starting")))
		case s.index >= 0:
			f, text := inFlight(now.Sub(s.since), stepAvg)
			lines = append(lines, fmt.Sprintf("%s %s %s", label, lay.sub.ViewAs(f),
				subtleStyle.Render(fmt.Sprintf("#%-*d %s", digits(lay.total), s.index+1, text))))
		default:
			lines = append(lines, fmt.Sprintf("%s %s %s", label, lay.sub.ViewAs(0),
				okStyle.Render("✓")+subtleStyle.Render(fmt.Sprintf(" %d done", s.done))))
		}
	}
	if len(ws) > rows {
		lines = append(lines, subtleStyle.Render(fmt.Sprintf("workers %d–%d of %d · ↑/↓ to scroll",
			scroll+1, min(scroll+rows, len(ws)), len(ws))))
	}
	return lines
}

// barStep is the shortest recent step time worth a bar per worker. Below it
// each bar fills and empties several times a second, which reads as noise,
// and the run's own bar already moves every step.
const barStep = 2 * time.Second

// workerRowsFor is how many worker bars fit a window height rows tall,
// beside the rest of the run screen; 8 when the height is not known.
func workerRowsFor(height int) int {
	if height <= 0 {
		return 8
	}
	return max(height-22, 3) // the title, bars, notes and help take ~22 rows
}
