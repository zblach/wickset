package tui

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/zblach/wickset/alg"
	"github.com/zblach/wickset/internal/ops"
	"github.com/zblach/wickset/internal/store"
)

// cores is what the forms say of the machine's cores: a variable, so tests
// draw the forms the same on any machine.
var cores = runtime.GOMAXPROCS(0)

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
			"Keep it somewhere other than the wick.")
	algorithm := huh.NewSelect[alg.ID]().Title("Algorithm").Options(algOptions()...).Value(&in.Alg)
	workers := huh.NewInput().Title("Workers").Value(&in.Workers).Validate(workersValidator).Placeholder("0").CharLimit(4).
		Description(fmt.Sprintf("Steps on the CPU at once; on a GPU, used if it fails. 0 or -1: one per core (%d).", cores))
	pair := "A .wick file or its .payload: either finds the other beside it."

	var fields []huh.Field
	switch {
	case act == actSeal && page == 0:
		fields = []huh.Field{
			file("File to seal", "The file to encrypt."),
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
				huh.NewOption(fmt.Sprintf("two files     %s and %s", name+store.WickSuffix, name+store.PayloadSuffix), store.FormFile),
				huh.NewOption("raw files     no damage check", store.FormRaw),
			),
			workers, keyOut,
		}
	case act == actOpen:
		fields = []huh.Field{
			file("Wick", pair),
			out,
			keyOut.Description("Optional. Saves the key, so you can open it again later with no wait."),
		}
	case act == actExtend:
		fields = []huh.Field{
			file("Wick", "A .wick file. Its payload never changes."),
			huh.NewInput().Title("Add").Value(&in.Steps).Validate(stepsValidator(1)).
				Description("How much longer opening it should take, such as 2h or 1w.\n" +
					"Or an exact number of steps."),
			huh.NewInput().Key(pathField).Title("Save as").Value(&in.Out).Placeholder("update the wick in place").
				Description("Optional. Where to write the longer wick."),
			workers,
		}
	case act == actBypass:
		fields = []huh.Field{
			file("Encrypted file", "A .payload file, or its .wick."),
			huh.NewInput().Key(pathField).Title("Key file").Value(&in.Key).Validate(keyPath(true)).
				Description("The key saved earlier by Seal or Open."),
			out,
		}
	case act == actInfo:
		fields = []huh.Field{file("Wick", pair)}
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
	if _, ok := alg.SHA256IterOf(a); ok {
		mem = "no memory"
	} else if a.MemBytes() > 0 {
		mem = ops.Bytes(int64(a.MemBytes())) + " a step"
	}
	return fmt.Sprintf("%#02x  %-22s %s", byte(a.ID()), a.Name(), mem)
}

// defaultAlg is the algorithm a form offers first. A delay chooses as the
// CLI does (ops.AlgFor); a step count keeps an earlier pick, or the short
// step.
func defaultAlg(in *inputs) alg.ID {
	if _, d, err := parseSteps(in.Steps); err == nil && d > 0 {
		return ops.AlgFor(d, in.GPU).ID()
	}
	if _, ok := alg.Lookup(in.Alg); ok {
		return in.Alg
	}
	return ops.AlgFor(0, in.GPU).ID()
}

// algReason says, in one line under the title, why the default is what it is.
func algReason(in *inputs) string {
	n, d, _ := parseSteps(in.Steps)
	if d > 0 {
		return fmt.Sprintf("Suggested for a %s delay: %s.", ops.FormatDelay(d), ops.AlgFor(d, in.GPU).ID())
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
  a year 365.25: a wick counts steps, not calendar dates.
  Seal times one step on this machine and works out how many steps that
  is. On faster hardware the wick burns sooner, so plan for the fastest
  machine that might try.
  Or a number N, for exactly N+1 steps of the algorithm chosen next.

Sealing does as much work as the wait itself, shared across your cores
or a GPU: a 12h wick takes 3h or more to make on 4 cores, and minutes
on a GPU with SHA-256.`
	case act == actSeal:
		return fmt.Sprintf(`Algorithm
  0x01  Argon2id, 128 MiB, short step   memory-hard
  0x02  Argon2id, 128 MiB, long step
  0x03  iterated SHA-256, short step    seals far faster on a GPU
  0x04  iterated SHA-256, long step

  A long step means fewer steps for the same delay, so a smaller wick
  file. Suggested: the long step from %v up; SHA-256 with the GPU,
  Argon2id without. Bench shows what a step takes here;
  docs/parameters.md compares them.

Save as
  two files     the wick and the encrypted file; damage is caught early
  raw files     the bare wick (SPEC.md), with no damage check

Workers   steps computed at once on the CPU, each holding the
          algorithm's memory; with a GPU, only if the GPU fails.
Key file  opens the file at once with no wait, even after the wick is
          made longer. Keep it apart from the wick.`, ops.FormatDelay(ops.LongDelay))
	}
	return ""
}
