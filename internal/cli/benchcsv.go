package cli

import (
	"cmp"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"wickset/alg"
	"wickset/internal/ops"
	"wickset/internal/sodium"
)

// repo is where benchmark submissions go (benchmarks/README.md).
const repo = "https://github.com/zblach/wickset"

// benchColumns are benchmarks/scores.csv's: who ran what, on what, and what
// it found. step_s is as the fastest opener runs a step, step_timing says
// how (empty: as this build runs it); speed_up is the seal:open ratio.
var benchColumns = []string{
	"date", "version", "source", "os", "arch", "cpu", "cores", "gpu", "argon2",
	"alg", "step_s", "step_timing", "seal_on", "at_once", "seal_steps_per_s", "speed_up",
}

// submitted are the algorithms a submission benches: every defined one.
var submitted = []alg.ID{alg.Argon2idShort, alg.Argon2idLong, alg.SHA256Short, alg.SHA256Long}

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

// writeBenchCSV writes bs as rows of benchmarks/scores.csv, after the
// header. gpu is the machine's, whether or not sealing used it (seal_on).
func writeBenchCSV(w io.Writer, bs ...ops.Bench) error {
	argon2 := "x/crypto"
	if sodium.Built {
		argon2 = "libsodium " + sodium.Version()
	}
	f := func(v float64) string { return strconv.FormatFloat(v, 'g', 4, 64) }
	cw := csv.NewWriter(w)
	cw.Write(benchColumns)
	for _, b := range bs {
		sealOn, atOnce, rate := "cpu", 1, 1/b.Step.Seconds()
		if b.SealOn != "" {
			sealOn = "gpu"
		}
		if r, ok := b.Best(); ok {
			atOnce, rate = r.At, r.Rate
		}
		cw.Write([]string{
			time.Now().UTC().Format(time.DateOnly), Version(), benchSource(), runtime.GOOS, runtime.GOARCH,
			cpuName(), strconv.Itoa(runtime.NumCPU()), ops.GPUName(), argon2,
			b.Alg.Name(), f(b.Step.Seconds()), b.StepTiming(), sealOn, strconv.Itoa(atOnce), f(rate), f(b.SpeedUp()),
		})
	}
	cw.Flush()
	return cw.Error()
}

// benchAll benches every submitted algorithm on the CPU, then, where env
// seals on a GPU, on the GPU too.
func benchAll(ctx context.Context, env *ops.Env) ([]ops.Bench, error) {
	modes := []bool{false}
	if env.GPU {
		modes = append(modes, true)
	}
	defer func(gpu bool) { env.GPU = gpu }(env.GPU)
	var out []ops.Bench
	for _, gpu := range modes {
		env.GPU = gpu
		for _, id := range submitted {
			a, _ := alg.Lookup(id)
			b, err := env.Bench(ctx, a)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
	}
	return out, nil
}

// submitLink is a link that opens a new file in benchmarks/submissions with
// rows already in it: following it, someone without write access gets a
// fork made for them and proposes the file as a pull request. Nothing is
// sent until then.
func submitLink(rows string) string {
	name := fmt.Sprintf("benchmarks/submissions/%s-%s-%s-%s.csv",
		time.Now().UTC().Format("2006-01-02"), runtime.GOOS, runtime.GOARCH, slug(cmp.Or(cpuName(), "cpu")))
	q := url.Values{"filename": {name}, "value": {rows}}
	return repo + "/new/main?" + q.Encode()
}

var nonWord = regexp.MustCompile(`[^a-z0-9]+`)

// slug is s as a file name part: "Apple M5" is "apple-m5".
func slug(s string) string {
	return strings.Trim(nonWord.ReplaceAllString(strings.ToLower(s), "-"), "-")
}
