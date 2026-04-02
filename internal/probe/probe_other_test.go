//go:build !linux

package probe

import (
	"testing"
)

func TestCanUseEBPF_NonLinux(t *testing.T) {
	if CanUseEBPF() {
		t.Error("CanUseEBPF() should return false on non-Linux")
	}
}

func TestNewEBPF_NonLinux(t *testing.T) {
	p := NewEBPF()
	if p == nil {
		t.Fatal("NewEBPF returned nil")
	}

	if err := p.Start(0); err == nil {
		t.Error("expected error from Start on non-Linux")
	}

	if err := p.StartWithPID(0); err == nil {
		t.Error("expected error from StartWithPID on non-Linux")
	}

	if p.Events() != nil {
		t.Error("expected nil Events channel on non-Linux")
	}

	if p.Method() != "unsupported" {
		t.Errorf("Method() = %q, want 'unsupported'", p.Method())
	}

	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestNewStrace_NonLinux(t *testing.T) {
	p := NewStrace()
	if p == nil {
		t.Fatal("NewStrace returned nil")
	}

	if err := p.Start(0); err == nil {
		t.Error("expected error from Start on non-Linux")
	}

	if err := p.StartWithPID(0); err == nil {
		t.Error("expected error from StartWithPID on non-Linux")
	}
}
