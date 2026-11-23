package cli

import (
	"encoding/csv"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zblach/wickset/alg"
	"github.com/zblach/wickset/internal/ops"
)

// TestSubmitLink: the link opens the benchmark issue form with this
// machine's fields and the rows, intact, and the summary has a line a
// bench.
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
	if u.Host != "github.com" || !strings.HasSuffix(u.Path, "/issues/new") || q.Get("template") != "benchmark.yml" {
		t.Errorf("link %s", u)
	}
	for _, field := range []string{"title", "cpu", "os", "version"} { // the form's required fields, and the title
		if q.Get(field) == "" {
			t.Errorf("no %s in %s", field, u)
		}
	}
	if q.Get("rows") != rows.String() {
		t.Errorf("the form would hold %q, not the rows", q.Get("rows"))
	}

	var summary strings.Builder
	if err := writeBenchSummary(&summary, b, b); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(summary.String()), "\n"); len(lines) != 3 || !strings.Contains(lines[1], a.Name()) {
		t.Errorf("summary:\n%s", summary.String())
	}
}
