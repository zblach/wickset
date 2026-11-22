package tui

import (
	"slices"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"
)

// The keys each screen takes, as bubbles bindings: what a key press matches
// and what the help line under the screen says are the same values. A form's
// own keys are huh's (huh.Form.KeyBinds); formKeys are what the TUI adds.

var menuKeys = struct {
	Up, Down, Pick, Jump, Quit key.Binding
}{
	Up:   key.NewBinding(key.WithKeys("up", "k", "shift+tab"), key.WithHelp("↑/↓", "choose")),
	Down: key.NewBinding(key.WithKeys("down", "j", "tab")),
	Pick: key.NewBinding(key.WithKeys("enter", "space"), key.WithHelp("enter", "select")),
	Jump: key.NewBinding(key.WithKeys(jumpKeys()...), key.WithHelp(jumpKeys()[0]+"–"+jumpKeys()[len(jumpKeys())-1], "open")),
	Quit: key.NewBinding(key.WithKeys("q", "esc", "ctrl+c"), key.WithHelp("q", "quit")),
}

var formKeys = struct {
	Complete, Details, Close, Back key.Binding
}{
	Complete: key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "complete")),
	Details:  key.NewBinding(key.WithKeys("?", "f1"), key.WithHelp("?", "details")),
	Close:    key.NewBinding(key.WithKeys("?", "f1", "esc", "enter", "q"), key.WithHelp("? or esc", "close")),
	// Back is huh's Quit: the form's cancel, a page back or to the menu.
	Back: key.NewBinding(key.WithKeys("esc", "ctrl+c"), key.WithHelp("esc", "back")),
}

var runKeys = struct {
	Cancel, Yes, No key.Binding
}{
	Cancel: key.NewBinding(key.WithKeys("esc", "ctrl+c", "q"), key.WithHelp("esc", "cancel")),
	Yes:    key.NewBinding(key.WithKeys("y", "Y"), key.WithHelp("y", "cancel")),
	No:     key.NewBinding(key.WithKeys("n", "N", "esc"), key.WithHelp("n", "keep going")),
}

var resultKeys = struct {
	Menu, Quit key.Binding
}{
	Menu: key.NewBinding(key.WithKeys("enter", "esc", "backspace", "space"), key.WithHelp("enter", "menu")),
	Quit: key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}

// jumpKeys are actionKeys' keys, in the menu's order.
func jumpKeys() []string {
	var ks []string
	for k := range actionKeys {
		ks = append(ks, k)
	}
	slices.SortFunc(ks, func(a, b string) int { return int(actionKeys[a]) - int(actionKeys[b]) })
	return ks
}

// newHelp is the help line's renderer, in the screen's subtle style.
func newHelp() help.Model {
	h := help.New()
	h.ShortSeparator = " · "
	h.Styles.ShortKey = lipgloss.NewStyle().Foreground(dim).Bold(true)
	h.Styles.ShortDesc = subtleStyle
	h.Styles.ShortSeparator = subtleStyle
	h.Styles.Ellipsis = subtleStyle
	return h
}
