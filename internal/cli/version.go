package cli

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/zblach/wickset/internal/ops"
	"github.com/zblach/wickset/internal/sodium"
)

// version is the release, set at link time for builds that are not of a
// tagged module (-ldflags "-X github.com/zblach/wickset/internal/cli.version=v0.1.0"). Empty,
// it comes from the build info: the tag for go install of a release, or a
// pseudo-version from the checkout for go build.
var version string

// Version is this binary's release, such as v0.1.0, or "devel" when there
// is nothing to tell it by.
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "devel"
}

// versionFlag is --version. It prints when given, rather than kong's
// VersionFlag's string built on every run: asking for the GPU's name opens
// it, which takes a moment.
type versionFlag bool

func (versionFlag) BeforeReset(app *kong.Kong) error {
	fmt.Fprintln(app.Stdout, versionLine())
	app.Exit(0)
	return nil
}

// versionLine is what --version prints: the release, then what this build
// can do, as a bug report or benchmark wants to know it.
func versionLine() string {
	var build []string
	if gpu := ops.GPUName(); gpu != "" {
		build = append(build, "GPU "+gpu)
	} else {
		build = append(build, "no GPU")
	}
	if sodium.Built {
		build = append(build, "libsodium "+sodium.Version())
	}
	if ops.TestBuild() {
		build = append(build, "TEST BUILD")
	}
	return fmt.Sprintf("wickset %s (%s, %s/%s; %s)", Version(), runtime.Version(), runtime.GOOS, runtime.GOARCH, strings.Join(build, ", "))
}
