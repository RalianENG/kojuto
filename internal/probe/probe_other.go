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

// NewStrace returns an unsupported probe on non-Linux platforms.
func NewStrace() *unsupportedProbe {
	return &unsupportedProbe{}
}

type unsupportedProbe struct{}

func (p *unsupportedProbe) Start(targetPIDNS uint32) error {
	return fmt.Errorf("host-level probe requires Linux, current OS: %s", runtime.GOOS)
}

func (p *unsupportedProbe) StartWithPID(pid uint32) error {
	return fmt.Errorf("host-level probe requires Linux, current OS: %s", runtime.GOOS)
}

func (p *unsupportedProbe) Events() <-chan types.ConnectEvent {
	return nil
}

func (p *unsupportedProbe) Close() error {
	return nil
}

func (p *unsupportedProbe) Method() string {
	return "unsupported"
}
