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
	LostSamples uint64
}

func (p *unsupportedProbe) Start(_ uint32) error {
	return fmt.Errorf("host-level probe requires Linux, current OS: %s", runtime.GOOS)
}

// StartWithPID is not supported on non-Linux platforms.
func (p *unsupportedProbe) StartWithPID(_ uint32) error {
	return fmt.Errorf("host-level probe requires Linux, current OS: %s", runtime.GOOS)
}

// Events returns nil on non-Linux platforms.
func (p *unsupportedProbe) Events() <-chan types.ConnectEvent {
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
