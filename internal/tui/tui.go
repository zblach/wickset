// Package tui is chainlock's interactive terminal interface: a menu of the
// CLI's operations, a form for each, and live progress while one runs. It
// runs the same package ops as the CLI, so files, checks and messages match.
package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"chainlock/internal/ops"
)

// Run shows the TUI until the user quits. file, if given, preselects the
// action that suits it, and starts the file field of whichever is chosen.
func Run(ctx context.Context, file string) error {
	_, err := tea.NewProgram(newModel(ctx, file), tea.WithContext(ctx)).Run()
	return err
}

type screen int

const (
	menuScreen screen = iota
	formScreen
	runScreen
	resultScreen
)

type model struct {
	ctx     context.Context
	initial string // file from the command line
	screen  screen
	width   int
	height  int
	cursor  action // menu selection

	act     action
	page    int  // of act's form; see pages
	details bool // showing the form's ? panel instead of the form
	// The matches tab listed for a path, and the text they were listed for.
	matches    []string
	matchesFor string
	in         *inputs
	form       *huh.Form
	// The last window size (passed on to forms as formSize) and background
	// color, replayed into each new form.
	sizeMsg, bgMsg tea.Msg

	job     *job
	confirm bool // asking whether to cancel the job
	scroll  int  // the first worker bar shown
	spin    spinner.Model
	res     *result

	keyHelp help.Model // draws the help line from the screen's bindings
}

// result is a finished job.
type result struct {
	title     string
	act       action
	value     any
	err       error
	notes     []ops.Note
	elapsed   time.Duration
	cancelled bool
}

func newModel(ctx context.Context, file string) *model {
	return &model{
		ctx:     ctx,
		initial: file,
		cursor:  guess(file),
		spin:    spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(pickStyle)),
		keyHelp: newHelp(),
	}
}

func (m *model) Init() tea.Cmd { return tea.RequestBackgroundColor }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height, m.sizeMsg = msg.Width, msg.Height, msg
		if m.form != nil { // the form gets the room left to it, not the window
			f, cmd := m.form.Update(m.formSize())
			m.form = f.(*huh.Form)
			return m, cmd
		}
	case tea.BackgroundColorMsg:
		m.bgMsg = msg
	case spinner.TickMsg:
		if m.job != nil { // the spinner's tick is what redraws a run, ten times a second
			var cmd tea.Cmd
			m.spin, cmd = m.spin.Update(msg)
			return m, cmd
		}
		return m, nil
	case doneMsg:
		return m.finish(msg), nil
	case submitMsg:
		if m.page+1 < pages(m.act) {
			m.page++
			m.in.Alg = defaultAlg(m.in)
			return m, m.openForm()
		}
		subject := filepath.Base(strings.TrimSpace(m.in.File))
		if m.act == actBench {
			subject = m.in.Alg.String()
		}
		return m, m.start(actions[m.act].doing+" "+subject, operation(m.act, m.in))
	case backMsg:
		if m.page > 0 {
			m.page--
			return m, m.openForm()
		}
		m.screen, m.form = menuScreen, nil
		return m, nil
	case tea.KeyPressMsg:
		if cmd, handled := m.key(msg); handled {
			return m, cmd
		}
	}
	if m.screen == formScreen && m.form != nil {
		f, cmd := m.form.Update(msg)
		m.form = f.(*huh.Form)
		return m, cmd
	}
	return m, nil
}

// key handles a key press outside a form, by the screen's bindings
// (keys.go). A form gets every key it does not take.
func (m *model) key(k tea.KeyPressMsg) (tea.Cmd, bool) {
	switch m.screen {
	case menuScreen:
		switch {
		case key.Matches(k, menuKeys.Up):
			m.cursor = (m.cursor + action(len(actions)) - 1) % action(len(actions))
		case key.Matches(k, menuKeys.Down):
			m.cursor = (m.cursor + 1) % action(len(actions))
		case key.Matches(k, menuKeys.Pick):
			return m.pick(m.cursor), true
		case key.Matches(k, menuKeys.Quit):
			return tea.Quit, true
		case key.Matches(k, menuKeys.Jump):
			return m.pick(actionKeys[k.String()]), true
		}
		return nil, true
	case formScreen:
		tab := key.Matches(k, formKeys.Complete)
		if !tab {
			m.matches = nil
		}
		switch {
		case tab && m.pathFocused():
			return m.completeFocused()
		case m.details:
			if key.Matches(k, formKeys.Close) {
				m.details = false
			}
			return nil, true
		case key.Matches(k, formKeys.Details) && (k.String() != "?" || m.questionFree()):
			m.details = helpText(m.act, m.page) != ""
			return nil, m.details
		}
		return nil, false
	case runScreen:
		switch {
		case m.confirm && key.Matches(k, runKeys.Yes):
			m.confirm = false
			m.job.stop()
		case m.confirm && key.Matches(k, runKeys.No):
			m.confirm = false
		case !m.confirm && key.Matches(k, runKeys.Cancel):
			m.confirm = true
		case key.Matches(k, runKeys.Up):
			m.scroll = max(m.scroll-1, 0)
		case key.Matches(k, runKeys.Down):
			n := len(m.job.snapshot().workers)
			m.scroll = min(m.scroll+1, max(n-workerRowsFor(m.height), 0))
		}
		return nil, true
	case resultScreen:
		switch {
		case key.Matches(k, resultKeys.Menu):
			m.screen, m.res = menuScreen, nil
		case key.Matches(k, resultKeys.Quit):
			return tea.Quit, true
		}
		return nil, true
	}
	return nil, false
}

// pick opens act's form, its file field starting with the command line's
// file, whichever action that is; the field's own checks say if it does not
// suit. (guess chose which action the menu offers first.)
func (m *model) pick(act action) tea.Cmd {
	m.act, m.cursor, m.screen, m.page = act, act, formScreen, 0
	m.in = &inputs{File: m.initial}
	m.in.Alg = defaultAlg(m.in)
	return m.openForm()
}

// questionFree reports whether ? would open the details panel rather than be
// typed: anywhere but in a text field that already holds text. Nothing typed
// here starts with ?, so an empty field gives it up.
func (m *model) questionFree() bool {
	in, ok := m.form.GetFocusedField().(*huh.Input)
	return !ok || in.GetValue() == ""
}

// pathFocused reports whether the focused field takes a path.
func (m *model) pathFocused() bool {
	in, ok := m.form.GetFocusedField().(*huh.Input)
	return ok && in.GetKey() == pathField
}

// completeFocused is tab in a path field, as in a shell: it completes what
// it can, and when the matches share nothing more, lists them (in place of
// the help line). Handled false lets tab move to the next field as usual:
// when the field is empty, nothing matches, or the matches for this same
// text were listed by the tab before.
func (m *model) completeFocused() (tea.Cmd, bool) {
	typed, _ := m.form.GetFocusedField().GetValue().(string)
	if typed == "" {
		return nil, false
	}
	add, matches := complete(typed)
	switch {
	case add != "":
		m.matches = nil
		var cmds []tea.Cmd
		for _, r := range add { // typed in, so the field takes it as its own
			f, cmd := m.form.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
			m.form, cmds = f.(*huh.Form), append(cmds, cmd)
		}
		return tea.Batch(cmds...), true
	case len(matches) > 1 && m.matchesFor != typed:
		m.matches, m.matchesFor = matches, typed
		return nil, true
	}
	m.matches, m.matchesFor = nil, ""
	return nil, false
}

// formSize is the room a form has: the window less the screen's own lines
// around it (chrome, the header, the help line). huh fits a form to the
// height it is given, scrolling within it, so a form given the whole window
// runs off the bottom and loses its last line.
func (m *model) formSize() tea.WindowSizeMsg {
	const below = 2 // huh draws two lines under the height it fits its fields to
	around := lipgloss.Height(chrome(m.width, ops.TestBuild(), []string{"head", "form"}, "help")) - 1
	return tea.WindowSizeMsg{Width: max(m.width-4, 20), Height: max(m.height-around-below, 6)}
}

// openForm shows the current page of the action's form over m.in, which
// keeps what earlier pages, or earlier visits to this one, collected.
func (m *model) openForm() tea.Cmd {
	m.details, m.matches, m.matchesFor = false, nil, ""
	m.form = newForm(m.act, m.in, m.page)
	cmds := []tea.Cmd{m.form.Init()}
	var size tea.Msg
	if m.sizeMsg != nil {
		size = m.formSize()
	}
	for _, msg := range []tea.Msg{size, m.bgMsg} {
		if msg != nil {
			f, cmd := m.form.Update(msg)
			m.form, cmds = f.(*huh.Form), append(cmds, cmd)
		}
	}
	return tea.Batch(cmds...)
}

// start runs f as the job titled title.
func (m *model) start(title string, f op) tea.Cmd {
	m.job = newJob(m.ctx, title, f)
	m.screen, m.form, m.confirm, m.scroll = runScreen, nil, false, 0
	return tea.Batch(m.job.run, m.spin.Tick)
}

func (m *model) finish(d doneMsg) *model {
	j := m.job
	s := j.snapshot()
	m.res = &result{
		title: j.title, act: m.act, value: d.value, err: d.err, notes: s.notes,
		elapsed: time.Since(j.start), cancelled: s.cancelled,
	}
	m.job, m.confirm, m.screen = nil, false, resultScreen
	return m
}

func (m *model) View() tea.View {
	var parts []string
	switch m.screen {
	case menuScreen:
		parts = append(parts, m.menuView())
	case formScreen:
		head := headStyle.Render(actions[m.act].name) + "  " + subtleStyle.Render(actions[m.act].desc)
		if n := pages(m.act); n > 1 {
			head += subtleStyle.Render(fmt.Sprintf("  (%d of %d)", m.page+1, n))
		}
		if m.details {
			parts = append(parts, head, panelStyle.Render(helpText(m.act, m.page)))
		} else {
			parts = append(parts, head, m.form.View())
		}
	case runScreen:
		parts = append(parts, m.runView())
	case resultScreen:
		parts = append(parts, renderResult(m.res))
	}
	v := tea.NewView(chrome(m.width, ops.TestBuild(), parts, m.helpLine()))
	v.AltScreen = true
	v.WindowTitle = "chainlock"
	if m.job != nil {
		v.ProgressBar = tea.NewProgressBar(tea.ProgressBarDefault, int(100*m.job.snapshot().fraction()))
	}
	return v
}

// helpLine is the line under the screen: the bindings it takes now, or,
// after a tab that could not complete further, what the path matches.
func (m *model) helpLine() string {
	var keys []key.Binding
	switch m.screen {
	case menuScreen:
		keys = []key.Binding{menuKeys.Up, menuKeys.Pick, menuKeys.Jump, menuKeys.Quit}
	case formScreen:
		switch {
		case m.details:
			keys = []key.Binding{formKeys.Close}
		case len(m.matches) > 0: // one line, so the screen keeps its height
			return subtleStyle.Render(ansi.Truncate("matches: "+strings.Join(m.matches, "  "), max(m.width-4, 20), "…"))
		default:
			if m.pathFocused() {
				keys = append(keys, formKeys.Complete)
			}
			keys = append(keys, m.form.KeyBinds()...)
			back := formKeys.Back
			if m.page == 0 {
				back.SetHelp("esc", "menu")
			}
			keys = append(keys, back)
			if helpText(m.act, m.page) != "" {
				keys = append(keys, formKeys.Details)
			}
		}
	case runScreen:
		switch {
		case m.confirm:
			keys = []key.Binding{runKeys.Yes, runKeys.No}
		default:
			keys = []key.Binding{runKeys.Cancel}
			if len(m.job.snapshot().workers) > workerRowsFor(m.height)+1 {
				keys = append(keys, runKeys.Up)
			}
		}
	case resultScreen:
		keys = []key.Binding{resultKeys.Menu, resultKeys.Quit}
	}
	m.keyHelp.SetWidth(max(m.width-4, 0)) // within the margins; 0, before the size is known, is no limit
	return m.keyHelp.ShortHelpView(keys)
}

func (m *model) menuView() string {
	lines := []string{headStyle.Render("What would you like to do?"), ""}
	for i, a := range actions {
		name := keyStyle.Render(fmt.Sprintf("%-2s", menuKey(action(i)))) + fmt.Sprintf("%-7s", a.name)
		if action(i) == m.cursor {
			lines = append(lines, pickStyle.Render("› ")+name+" "+a.desc)
		} else {
			lines = append(lines, "  "+name+" "+subtleStyle.Render(a.desc))
		}
	}
	if m.initial != "" {
		lines = append(lines, "", subtleStyle.Render("file: "+m.initial))
	}
	return strings.Join(lines, "\n")
}

// runView is the run screen for the job as it stands now (render.go).
func (m *model) runView() string {
	j := m.job
	return renderRun(m.width, runFrame{
		title: j.title, spinner: m.spin.View(), start: j.start, now: time.Now(),
		run: j.snapshot(), confirm: m.confirm, scroll: m.scroll, rows: workerRowsFor(m.height),
	})
}
