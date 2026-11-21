package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"github.com/charmbracelet/x/ansi"
)

// send gives f msg and then the messages its commands produce, as a program
// would, a few rounds deep (enough for a field change; ticks are skipped).
func send(f *huh.Form, msg tea.Msg) {
	queue := []tea.Msg{msg}
	for round := 0; round < 4 && len(queue) > 0; round++ {
		var next []tea.Msg
		for _, m := range queue {
			_, cmd := f.Update(m)
			next = append(next, run(cmd)...)
		}
		queue = next
	}
}

func run(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	switch m := cmd().(type) {
	case nil:
		return nil
	case tea.BatchMsg:
		var out []tea.Msg
		for _, c := range m {
			out = append(out, run(c)...)
		}
		return out
	default:
		if t := strings.ToLower(fmt.Sprintf("%T", m)); strings.Contains(t, "tick") || strings.Contains(t, "blink") {
			return nil // cursor blinks never end
		}
		return []tea.Msg{m}
	}
}

// TestFormsShowEveryField: on each page of each form, in a short window,
// the last field, once focused, shows its input line. (huh sizes a form to
// the height it is given; the TUI gives it only what its own lines leave.)
func TestFormsShowEveryField(t *testing.T) {
	for act := range action(len(actions)) {
		for page := range pages(act) {
			m := newModel(t.Context(), "")
			m.Update(tea.WindowSizeMsg{Width: 100, Height: 24})
			m.screen, m.act, m.page, m.in = formScreen, act, page, &inputs{Steps: "1h"}
			m.openForm()
			for range 8 {
				send(m.form, tea.KeyPressMsg{Code: tea.KeyTab})
			}
			// A screen taller than the window loses its bottom lines, which
			// is how the last field's input line went missing.
			v := ansi.Strip(m.View().Content)
			n := len(strings.Split(strings.TrimRight(v, "\n"), "\n"))
			if n > 24 {
				t.Errorf("%s page %d: %d lines in a 24-line window:\n%s", actions[act].name, page+1, n, v)
			}
		}
	}
}
