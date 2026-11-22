//go:build !darwin

package cli

import (
	"bufio"
	"os"
	"strings"
)

// cpuName is the processor's name from /proc/cpuinfo, such as "AMD EPYC
// 7763 64-Core Processor", or "" where it says none (Linux on Arm names
// only part numbers).
func cpuName() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if k, v, ok := strings.Cut(s.Text(), ":"); ok && strings.TrimSpace(k) == "model name" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
