package ops

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Units: delays as people write them, and byte counts.
//
// Delays are written as systemd writes time spans (systemd.time(7)): terms
// that add up, such as 90s, 8h, 3d, 2w, 6M, 1y, "1w 3d" or "2 weeks". Case
// matters only where systemd's does: m is a minute, M a month. A wick counts
// steps, not dates, so a month and a year are fixed spans, systemd's own:
// 30.44 and 365.25 days.
const (
	Day   = 24 * time.Hour
	Week  = 7 * Day
	Month = 2629800 * time.Second  // 30.44 days
	Year  = 31557600 * time.Second // 365.25 days
)

var delayUnits = map[string]time.Duration{}

func init() {
	for size, names := range map[time.Duration][]string{
		time.Nanosecond:  {"nsec", "ns"},
		time.Microsecond: {"usec", "us", "µs", "μs"},
		time.Millisecond: {"msec", "ms"},
		time.Second:      {"seconds", "second", "sec", "s"},
		time.Minute:      {"minutes", "minute", "min", "m"},
		time.Hour:        {"hours", "hour", "hr", "h"},
		Day:              {"days", "day", "d"},
		Week:             {"weeks", "week", "w"},
		Month:            {"months", "month", "M"},
		Year:             {"years", "year", "y"},
	} {
		for _, n := range names {
			delayUnits[n] = size
		}
	}
}

// delayTerm is one number and its unit, as in 1.5d or "2 weeks".
var delayTerm = regexp.MustCompile(`^\s*([0-9]+(?:\.[0-9]*)?|\.[0-9]+)\s*([a-zA-Zµμ]+)\s*`)

var errDelay = errors.New("a delay is a number and a unit, such as 90s, 30min, 8h, 3d, 2w, 6M or 1y (M is months, m minutes), or several: 1w 3d")

// ParseDelay reads a delay as systemd.time(7) writes a time span, except
// that a number needs a unit: systemd reads a bare one as seconds, but in
// wickset a bare number is a step count. It must be positive.
func ParseDelay(s string) (time.Duration, error) {
	rest := strings.TrimSpace(s)
	if rest == "" {
		return 0, errDelay
	}
	var total float64 // nanoseconds; a float so a fraction of a year is exact enough
	for rest != "" {
		m := delayTerm.FindStringSubmatch(rest)
		if m == nil {
			return 0, errDelay
		}
		unit, ok := delayUnits[m[2]]
		if !ok {
			return 0, fmt.Errorf("%q is not a unit; %w", m[2], errDelay)
		}
		n, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, errDelay
		}
		total += n * float64(unit)
		rest = rest[len(m[0]):]
	}
	switch {
	case total <= 0:
		return 0, errDelay
	case total > math.MaxInt64:
		return 0, fmt.Errorf("delay %q is too long; the most is about 292 years", s)
	}
	return time.Duration(total), nil
}

// FormatDelay writes a delay as ParseDelay reads it, in whole units from
// years down: 2w, "1w 3d", "1y 2d", 90s; sub-second remainders are dropped
// at a minute or more. Months are left out, as a month is not a whole
// number of days: 45 days is "6w 3d".
func FormatDelay(d time.Duration) string {
	if d < time.Minute {
		return d.String()
	}
	d = d.Round(time.Second)
	var parts []string
	for _, u := range []struct {
		name string
		size time.Duration
	}{{"y", Year}, {"w", Week}, {"d", Day}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}} {
		if n := d / u.size; n > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", n, u.name))
			d -= n * u.size
		}
	}
	return strings.Join(parts, " ")
}

// Span formats an elapsed or estimated time, which may run to months, as
// finely as is worth reading: to the millisecond under a second, the second
// under an hour, the minute under a day, and in days and hours beyond.
func Span(d time.Duration) string {
	switch {
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	case d < Day:
		return strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
	}
	h := int(d.Round(time.Hour).Hours())
	return fmt.Sprintf("%dd %dh", h/24, h%24)
}

// Bytes formats a byte count.
func Bytes(n int64) string {
	for _, u := range []struct {
		name string
		size int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= u.size {
			// one decimal, dropped when it is zero: 256 MiB, 3.5 MiB
			return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/float64(u.size)), ".0") + " " + u.name
		}
	}
	return fmt.Sprintf("%d B", n)
}
