package cli

import (
	"encoding/csv"
	"io"
	"runtime"
	"strconv"
	"time"

	"wickset/internal/ops"
	"wickset/internal/sodium"
)

// benchColumns are benchmarks/scores.csv's: who ran what, on what, and what
// it found. step_s is as the fastest opener runs a step, step_timing says
// how (empty: as this build runs it); speed_up is the seal:open ratio.
var benchColumns = []string{
	"date", "version", "os", "arch", "cpu", "cores", "gpu", "argon2",
	"alg", "step_s", "step_timing", "seal_on", "at_once", "seal_steps_per_s", "speed_up",
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
	for _, r := range b.Rounds {
		if r.Rate > rate {
			atOnce, rate = r.At, r.Rate
		}
	}
	f := func(v float64) string { return strconv.FormatFloat(v, 'g', 4, 64) }
	cw := csv.NewWriter(w)
	cw.Write(benchColumns)
	cw.Write([]string{
		time.Now().UTC().Format(time.DateOnly), Version(), runtime.GOOS, runtime.GOARCH,
		cpuName(), strconv.Itoa(runtime.NumCPU()), ops.GPUName(), argon2,
		b.Alg.Name(), f(b.Step.Seconds()), b.StepTiming(), sealOn, strconv.Itoa(atOnce), f(rate), f(b.SpeedUp()),
	})
	cw.Flush()
	return cw.Error()
}
