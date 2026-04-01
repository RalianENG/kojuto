//go:build linux

package probe

import (
	"os"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// CanUseEBPF checks whether the current environment supports eBPF kprobes.
func CanUseEBPF() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// Check if running as root or has CAP_BPF
	if !hasCapabilities() {
		return false
	}

	// Check kernel version >= 5.8 (for BPF ring buffer and modern features)
	if !hasMinKernel(5, 8) {
		return false
	}

	return true
}

func hasCapabilities() bool {
	// Running as root is sufficient
	if os.Geteuid() == 0 {
		return true
	}

	// Check for CAP_BPF (39) and CAP_PERFMON (38)
	// These were introduced in Linux 5.8
	hdr := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}

	const capBPF = 39
	const capPerfmon = 38

	hasBPF := data[capBPF/32].Effective&(1<<(capBPF%32)) != 0
	hasPerfmon := data[capPerfmon/32].Effective&(1<<(capPerfmon%32)) != 0

	return hasBPF && hasPerfmon
}

func hasMinKernel(major, minor int) bool {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return false
	}

	release := ""
	for _, b := range uname.Release {
		if b == 0 {
			break
		}
		release += string(rune(b))
	}

	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}

	maj := 0
	min := 0
	for _, c := range parts[0] {
		if c >= '0' && c <= '9' {
			maj = maj*10 + int(c-'0')
		}
	}
	for _, c := range parts[1] {
		if c >= '0' && c <= '9' {
			min = min*10 + int(c-'0')
		}
	}

	if maj > major {
		return true
	}
	if maj == major && min >= minor {
		return true
	}
	return false
}
