//go:build !linux

package probe

import (
	"fmt"
	"runtime"

	"github.com/RalianENG/kojuto/internal/types"
)

// CanUseEBPF always returns false on non-Linux platforms.
func CanUseEBPF() bool {
	return false
}

// NewEBPF returns an unsupported probe on non-Linux platforms.
func NewEBPF() *unsupportedProbe {
	return &unsupportedProbe{}
}

// NewStrace returns a Probe that always errors on non-Linux platforms.
func NewStrace() *unsupportedProbe {
	return &unsupportedProbe{}
}

type unsupportedProbe struct {
}

func (p *unsupportedProbe) Start(_ uint32) error {
	return fmt.Errorf("host-level probe requires Linux, current OS: %s", runtime.GOOS)
}

// StartWithPID is not supported on non-Linux platforms.
func (p *unsupportedProbe) StartWithPID(_ uint32) error {
	return fmt.Errorf("host-level probe requires Linux, current OS: %s", runtime.GOOS)
}

// Events returns nil on non-Linux platforms.
func (p *unsupportedProbe) Events() <-chan types.SyscallEvent {
	return nil
}

// Close is a no-op on non-Linux platforms.
func (p *unsupportedProbe) Close() error {
	return nil
}

// Method returns "unsupported" on non-Linux platforms.
func (p *unsupportedProbe) Method() string {
	return "unsupported"
}

// Dropped always returns 0 on non-Linux platforms.
func (p *unsupportedProbe) Dropped() uint64 {
	return 0
}

// LostSamples always returns 0 on non-Linux platforms. Present so callers
// can read the counter uniformly across platforms; the Linux probe backs it
// with an atomic because two perf-buffer readers update it concurrently.
func (p *unsupportedProbe) LostSamples() uint64 {
	return 0
}
