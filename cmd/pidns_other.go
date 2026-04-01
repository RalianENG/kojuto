//go:build !linux

package cmd

import (
	"fmt"
	"runtime"
)

func getPIDNSInode(_ uint32) (uint32, error) {
	return 0, fmt.Errorf("PID namespace inspection requires Linux, current OS: %s", runtime.GOOS)
}
