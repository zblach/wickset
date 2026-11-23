package cli

import (
	"encoding/csv"
	"net/url"
	"strings"
	"testing"
	"time"

	"wickset/alg"
	"wickset/internal/ops"
)

// TestSubmitLink: the link opens GitHub's new-file page in
// benchmarks/submissions, with the rows as the file's contents, intact.
func TestSubmitLink(t *testing.T) {
	a, _ := alg.Lookup(alg.SHA256Short)
	b := ops.Bench{Alg: a, Step: 300 * time.Millisecond, Rounds: []ops.BenchRound{{At: 4, Rate: 10}}}
	var rows strings.Builder
	if err := writeBenchCSV(&rows, b, b); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(strings.NewReader(rows.String())).ReadAll()
	if err != nil || len(recs) != 3 || recs[0][0] != "date" {
		t.Fatalf("rows %q (%v)", rows.String(), err)
	}

	u, err := url.Parse(submitLink(rows.String()))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "github.com" || !strings.HasSuffix(u.Path, "/new/main") ||
		!strings.HasPrefix(q.Get("filename"), "benchmarks/submissions/") || !strings.HasSuffix(q.Get("filename"), ".csv") {
		t.Errorf("link %s", u)
	}
	if q.Get("value") != rows.String() {
		t.Errorf("the file would hold %q, not the rows", q.Get("value"))
	}
	if got := slug("AMD EPYC 9V74 80-Core Processor"); got != "amd-epyc-9v74-80-core-processor" {
		t.Errorf("slug %q", got)
	}
}
