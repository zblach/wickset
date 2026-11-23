package cli

import (
	"cmp"
	"encoding/csv"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"wickset/internal/ops"
	"wickset/internal/sodium"
)

// benchColumns are benchmarks/scores.csv's: who ran what, on what, and what
// it found. step_s is as the fastest opener runs a step, step_timing says
// how (empty: as this build runs it); speed_up is the seal:open ratio.
var benchColumns = []string{
	"date", "version", "source", "os", "arch", "cpu", "cores", "gpu", "argon2",
	"alg", "step_s", "step_timing", "seal_on", "at_once", "seal_steps_per_s", "speed_up",
}

// benchSource says where a row was measured, where that is not someone's own
// machine: a CI runner, a small shared VM whose rows are reference points
// rather than measurements, with the run that measured them. Empty
// otherwise.
func benchSource() string {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return ""
	}
	kind := cmp.Or(os.Getenv("RUNNER_ENVIRONMENT"), "github") + " runner"
	if img := strings.TrimSpace(os.Getenv("ImageOS") + " " + os.Getenv("ImageVersion")); img != "" {
		kind += " (" + img + ")"
	}
	return kind + ", run " + os.Getenv("GITHUB_RUN_ID")
}

// writeBenchCSV writes b as one row of benchmarks/scores.csv, after the
// header. gpu is the machine's, whether or not sealing used it (seal_on).
func writeBenchCSV(w io.Writer, b ops.Bench) error {
	argon2 := "x/crypto"
	if sodium.Built {
		argon2 = "libsodium " + sodium.Version()
	}
	sealOn, atOnce, rate := "cpu", 1, 1/b.Step.Seconds()
	if b.SealOn != "" {
		sealOn = "gpu"
	}
	if r, ok := b.Best(); ok {
		atOnce, rate = r.At, r.Rate
	}
	f := func(v float64) string { return strconv.FormatFloat(v, 'g', 4, 64) }
	cw := csv.NewWriter(w)
	cw.Write(benchColumns)
	cw.Write([]string{
		time.Now().UTC().Format(time.DateOnly), Version(), benchSource(), runtime.GOOS, runtime.GOARCH,
		cpuName(), strconv.Itoa(runtime.NumCPU()), ops.GPUName(), argon2,
		b.Alg.Name(), f(b.Step.Seconds()), b.StepTiming(), sealOn, strconv.Itoa(atOnce), f(rate), f(b.SpeedUp()),
	})
	cw.Flush()
	return cw.Error()
}
