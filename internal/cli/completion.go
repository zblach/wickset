package cli

import (
	"fmt"
	"os"
	"strings"
)

// shells are those completion prints for.
var shells = []string{"bash", "zsh", "fish"}

// completionCmd prints what makes a shell complete wickset's commands,
// arguments and files: wicks where a wick goes, payloads where a payload
// does (predictors). It prints rather than installs: what goes in a shell's
// startup file is its user's to put there.
type completionCmd struct {
	Shell string `arg:"" enum:"bash,zsh,fish" predictor:"shell" help:"bash, zsh or fish."`
}

func (*completionCmd) Help() string {
	return "Add the lines it prints to your shell's startup file (~/.bashrc,\n" +
		"~/.zshrc, ~/.config/fish/config.fish). The shell then asks this binary\n" +
		"to complete each command line; rebuilding or moving it means printing\n" +
		"them again."
}

func (c *completionCmd) Run() error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	if strings.ContainsAny(bin, "'\n") {
		return fmt.Errorf("%q: a path with quotes or newlines cannot go in a shell script", bin)
	}
	switch c.Shell {
	case "bash":
		fmt.Printf("complete -C '%s' wickset\n", bin)
	case "zsh":
		fmt.Printf("autoload -U +X bashcompinit && bashcompinit\ncomplete -C '%s' wickset\n", bin)
	case "fish":
		fmt.Printf(`function __complete_wickset
    set -lx COMP_LINE (commandline -cp)
    test -z (commandline -ct)
    and set COMP_LINE "$COMP_LINE "
    '%s'
end
complete -f -c wickset -a "(__complete_wickset)"
`, bin)
	}
	return nil
}
