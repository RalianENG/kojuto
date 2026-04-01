//go:build linux

package cmd

import (
	"fmt"
	"os"
	"syscall"
)

func getPIDNSInode(pid uint32) (uint32, error) {
	path := fmt.Sprintf("/proc/%d/ns/pid", pid)
	fi, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unexpected stat type for %s", path)
	}
	return uint32(stat.Ino), nil
}
