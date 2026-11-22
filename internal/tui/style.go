package tui

import (
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// The palette is ANSI's 16 colors, so it follows the terminal's own theme,
// light or dark.
var (
	accent = lipgloss.Color("5") // magenta
	ok     = lipgloss.Color("2")
	warn   = lipgloss.Color("3")
	bad    = lipgloss.Color("1")
	dim    = lipgloss.Color("8")

	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(accent).Padding(0, 1)
	subtleStyle  = lipgloss.NewStyle().Foreground(dim)
	headStyle    = lipgloss.NewStyle().Bold(true)
	pickStyle    = lipgloss.NewStyle().Bold(true).Foreground(accent)
	okStyle      = lipgloss.NewStyle().Bold(true).Foreground(ok)
	warnStyle    = lipgloss.NewStyle().Foreground(warn)
	badStyle     = lipgloss.NewStyle().Bold(true).Foreground(bad)
	bannerStyle  = lipgloss.NewStyle().Foreground(warn).Border(lipgloss.RoundedBorder()).BorderForeground(warn).Padding(0, 1)
	panelStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(dim).Padding(0, 1)
	confirmStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(bad).Padding(0, 1)
	keyStyle     = lipgloss.NewStyle().Foreground(accent)

	// A workBar's cells: finished, in progress, pending.
	cellStyles = [...]lipgloss.Style{
		cellDone:    lipgloss.NewStyle().Foreground(accent),
		cellBusy:    lipgloss.NewStyle().Foreground(lipgloss.Color("6")), // cyan
		cellPending: lipgloss.NewStyle().Foreground(dim),
	}
)

// formTheme is huh's Charm theme, except that unselected options and
// placeholders, which it draws in near-black 256-color grays on a dark
// background, take the terminal's own text and dim colors instead.
func formTheme(isDark bool) *huh.Styles {
	t := huh.ThemeCharm(isDark)
	for _, f := range []*huh.FieldStyles{&t.Focused, &t.Blurred} {
		f.Option = f.Option.Foreground(lipgloss.NoColor{})
		f.UnselectedOption = f.UnselectedOption.Foreground(lipgloss.NoColor{})
		f.TextInput.Placeholder = f.TextInput.Placeholder.Foreground(dim)
	}
	return t
}
