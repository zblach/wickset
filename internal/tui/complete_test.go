package tui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"github.com/charmbracelet/x/ansi"
)

// tree makes files (a name ending in / is a directory) under a temp dir.
func tree(t *testing.T, names ...string) string {
	dir := t.TempDir()
	for _, n := range names {
		p := filepath.Join(dir, n)
		if strings.HasSuffix(n, "/") {
			os.MkdirAll(p, 0o755)
		} else {
			os.WriteFile(p, nil, 0o600)
		}
	}
	return dir + string(filepath.Separator)
}

func TestComplete(t *testing.T) {
	d := tree(t, "notes.txt", "notes.txt.lock", "docs/", ".hidden", "xé.txt", "xè.txt")
	for _, c := range []struct {
		typed, add string
		matches    []string
	}{
		{d + "no", "tes.txt", nil},                                     // to the common prefix
		{d + "notes.txt", "", []string{"notes.txt", "notes.txt.lock"}}, // nothing to add: list
		{d + "do", "cs/", nil},                                         // a directory, ready to go on
		{d + ".h", "idden", nil},                                       // hidden, when asked for
		{d + "x", "", []string{"xè.txt", "xé.txt"}},                    // é and è share a byte, not a character
		{d + "zz", "", nil},                                            // no match
		{d + "missing/x", "", nil},                                     // no such directory
	} {
		add, matches := complete(c.typed)
		if add != c.add || !slices.Equal(matches, c.matches) {
			t.Errorf("complete(%q) = %q, %q; want %q, %q", strings.TrimPrefix(c.typed, d), add, matches, c.add, c.matches)
		}
	}
	if add, _ := complete(d); strings.HasPrefix(add, ".") {
		t.Errorf("hidden file offered unasked: %q", add)
	}
}

// TestTabCompletes: in a path field, tab completes, then lists what it
// cannot choose between, and only then moves on.
func TestTabCompletes(t *testing.T) {
	d := tree(t, "notes.txt", "notes.txt.lock")
	m := newModel(t.Context(), "")
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m.pick(actOpen) // Lock, then Save as
	if hint := ansi.Strip(newHelp().ShortHelpView([]key.Binding{formKeys.Complete})); !strings.Contains(ansi.Strip(m.helpLine()), hint) {
		t.Fatalf("no completion hint %q in a path field: %q", hint, m.helpLine())
	}
	for _, r := range d + "no" {
		m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	value := func() string { s, _ := m.form.GetFocusedField().GetValue().(string); return s }
	tab := tea.KeyPressMsg{Code: tea.KeyTab}

	m.Update(tab)
	if got := value(); got != d+"notes.txt" {
		t.Fatalf("after tab: %q, want the common prefix %q", got, d+"notes.txt")
	}
	m.Update(tab)
	if !slices.Equal(m.matches, []string{"notes.txt", "notes.txt.lock"}) {
		t.Fatalf("second tab listed %q", m.matches)
	}
	if value() != d+"notes.txt" {
		t.Fatal("listing changed the field")
	}
	// The third tab moves on, to Save as, keeping what Lock holds.
	_, cmd := m.Update(tab)
	for _, msg := range run(cmd) {
		m.Update(msg)
	}
	if f, ok := m.form.GetFocusedField().(*huh.Input); !ok || value() != "" || len(m.matches) > 0 {
		t.Fatalf("after the third tab: focus %T holding %q, matches %v", f, value(), m.matches)
	}
	if m.in.File != d+"notes.txt" {
		t.Fatalf("Lock now %q", m.in.File)
	}
}
