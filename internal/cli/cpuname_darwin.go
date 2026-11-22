package cli

import "golang.org/x/sys/unix"

// cpuName is the processor's marketing name, such as "Apple M5", or "".
func cpuName() string {
	s, _ := unix.Sysctl("machdep.cpu.brand_string")
	return s
}
