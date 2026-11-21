package tui

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"chainlock/alg"
	"chainlock/internal/ops"
	"chainlock/internal/store"
)

// submitMsg and backMsg are a form's submit and cancel.
type (
	submitMsg struct{}
	backMsg   struct{}
)

// pages is how many forms act takes in turn. Seal takes two, so that the
// delay, given first, can choose the algorithm the second offers by default.
func pages(act action) int {
	if act == actSeal {
		return 2
	}
	return 1
}

// newForm builds page of act's form over in. Esc as well as ctrl+c leaves it.
func newForm(act action, in *inputs, page int) *huh.Form {
	file := func(title, desc string) huh.Field {
		return huh.NewInput().Key(pathField).Title(title).Description(desc).Value(&in.File).Validate(existingFile)
	}
	out := huh.NewInput().Key(pathField).Title("Save as").Value(&in.Out).Placeholder("same name, without the extension").
		Description("Optional. Where to write the decrypted file.")
	keyOut := huh.NewInput().Key(pathField).Title("Key file").Value(&in.KeyOut).Validate(keyPath(false)).
		Description("Optional. Saves a key that opens the file at once, with no wait.\n" +
			"Keep it somewhere other than the lock.")
	algorithm := huh.NewSelect[alg.ID]().Title("Algorithm").Options(algOptions()...).Value(&in.Alg)
	workers := huh.NewInput().Title("Workers").Value(&in.Workers).Validate(workersValidator).Placeholder("0").CharLimit(4).
		Description(fmt.Sprintf("Steps computed at once. 0 or -1: one per core (%d here).", runtime.GOMAXPROCS(0)))
	lock := "A .lock file (with its .payload next to it), or a .chainlock.tar."

	var fields []huh.Field
	switch {
	case act == actSeal && page == 0:
		fields = []huh.Field{
			file("File to lock", "The file to encrypt."),
			huh.NewInput().Title("Delay").Value(&in.Steps).Validate(stepsValidator(0)).
				Description("How long opening it should take, such as 30m, 8h, 3d or 2w.\n" +
					"Or an exact number of steps."),
		}
	case act == actSeal:
		name := "FILE"
		if f := strings.TrimSpace(in.File); f != "" { // known by page 2
			name = filepath.Base(f)
		}
		fields = []huh.Field{
			algorithm.Description(algReason(in)),
			huh.NewSelect[store.Form]().Title("Save as").Value(&in.Form).Options(
				huh.NewOption(fmt.Sprintf("two files     %s and %s", name+store.LockSuffix, name+store.PayloadSuffix), store.FormFile),
				huh.NewOption("one archive   "+name+store.ArchiveSuffix, store.FormArchive),
				huh.NewOption("raw files     no damage check", store.FormRaw),
			),
			workers, keyOut,
		}
	case act == actOpen:
		fields = []huh.Field{
			file("Lock", lock),
			out,
			keyOut.Description("Optional. Saves the key, so you can open it again later with no wait."),
		}
	case act == actExtend:
		fields = []huh.Field{
			file("Lock", lock),
			huh.NewInput().Title("Add").Value(&in.Steps).Validate(stepsValidator(1)).
				Description("How much longer opening it should take, such as 2h or 1w.\n" +
					"Or an exact number of steps."),
			huh.NewInput().Key(pathField).Title("Save as").Value(&in.Out).Placeholder("update the lock in place").
				Description("Optional. Where to write the longer lock."),
			workers,
		}
	case act == actBypass:
		fields = []huh.Field{
			file("Encrypted file", "A .payload file, or its .lock or .chainlock.tar."),
			huh.NewInput().Key(pathField).Title("Key file").Value(&in.Key).Validate(keyPath(true)).
				Description("The key saved earlier by Seal or Open."),
			out,
		}
	case act == actInfo:
		fields = []huh.Field{file("Lock", lock)}
	case act == actBench:
		fields = []huh.Field{algorithm}
	}
	f := huh.NewForm(huh.NewGroup(fields...)).
		WithKeyMap(formKeyMap()).
		WithTheme(huh.ThemeFunc(formTheme)).
		WithShowHelp(false) // the screen's help line shows these bindings with the TUI's own
	f.SubmitCmd = func() tea.Msg { return submitMsg{} }
	f.CancelCmd = func() tea.Msg { return backMsg{} }
	return f
}

// formKeyMap is huh's, with esc as well as ctrl+c leaving the form,
// shift+tab called "previous" ("back" is esc's), and no filtering of selects.
func formKeyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Quit = formKeys.Back
	km.Select.Filter.SetEnabled(false)
	for _, b := range []*key.Binding{&km.Input.Prev, &km.Select.Prev, &km.Text.Prev, &km.Confirm.Prev, &km.MultiSelect.Prev, &km.FilePicker.Prev, &km.Note.Prev} {
		b.SetHelp("shift+tab", "previous")
	}
	return km
}

// algOptions lists the algorithms as what they are: id, name and memory.
// Speeds are left out: they belong to a machine and a year, and seal and
// bench measure them.
func algOptions() []huh.Option[alg.ID] {
	var o []huh.Option[alg.ID]
	for _, a := range alg.All() {
		o = append(o, huh.NewOption(algLabel(a), a.ID()))
	}
	return o
}

// algLabel is an algorithm's id, name and memory per step.
func algLabel(a alg.Alg) string {
	mem := "no real delay"
	if a.MemBytes() > 0 {
		mem = ops.Bytes(int64(a.MemBytes())) + " a step"
	}
	return fmt.Sprintf("%#02x  %-22s %s", byte(a.ID()), a.Name(), mem)
}

// defaultAlg is the algorithm a form offers first. A delay chooses as the
// CLI does (ops.AlgFor); a step count keeps an earlier pick, or 0x01.
func defaultAlg(in *inputs) alg.ID {
	if _, d, err := parseSteps(in.Steps); err == nil && d > 0 {
		return ops.AlgFor(d).ID()
	}
	if _, ok := alg.Lookup(in.Alg); ok {
		return in.Alg
	}
	return alg.Argon2id256M
}

// algReason says, in one line under the title, why the default is what it is.
func algReason(in *inputs) string {
	n, d, _ := parseSteps(in.Steps)
	if d > 0 {
		return fmt.Sprintf("Suggested for a %s delay: %s.", ops.FormatDelay(d), ops.AlgFor(d).ID())
	}
	return fmt.Sprintf("N = %d: %d steps of the algorithm chosen here.", n, n+1)
}

// helpText is the ? panel for page of act's form, or "" if it has none.
// Lines stay within 76 columns.
func helpText(act action, page int) string {
	switch {
	case act == actSeal && page == 0:
		return `Delay
  A time, such as 30m, 8h, 3d, 2w, 6M or 1y, or several: "1w 3d", "2 weeks".
  Lowercase m is minutes and capital M months. A month is 30.44 days and
  a year 365.25: a lock counts steps, not calendar dates.
  Seal times one step on this machine and works out how many steps that
  is. On faster hardware the lock opens sooner, so plan for the fastest
  machine that might try.
  Or a number N, for exactly N+1 steps of the algorithm chosen next.

Sealing does as much work as the wait itself, shared across your cores:
a 12h lock takes 3h or more to make on 4 cores.`
	case act == actSeal:
		return fmt.Sprintf(`Algorithm
  0x01  Argon2id, 256 MiB, 3 passes over it per step
  0x02  Argon2id, 1 GiB, 30 passes: a step about 40× as long as 0x01's
  A longer step means fewer steps for the same delay, so a smaller lock
  file; sealing takes the same time either way. Each worker needs the
  algorithm's memory. Suggested: 0x02 from %v up, 0x01 below.
  Bench shows what a step takes on this machine.

Save as
  two files     the lock and the encrypted file; damage is caught early
  one archive   the same two files, in one tar
  raw files     the bare lock (SPEC.md), with no damage check

Workers   steps computed at once; each needs the algorithm's memory.
Key file  opens the file at once with no wait, even after the lock is
          made longer. Keep it apart from the lock.`, ops.FormatDelay(ops.LongDelay))
	}
	return ""
}
