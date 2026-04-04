//go:build linux

package probe

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"sync"

	"github.com/RalianENG/kojuto/internal/types"
)

// StraceFallback monitors connect(2) syscalls by running strace on the container PID.
type StraceFallback struct {
	cmd       *exec.Cmd
	events    chan types.SyscallEvent
	done      chan struct{}
	closeOnce sync.Once
}

// NewStrace creates a strace-based fallback probe.
func NewStrace() *StraceFallback {
	return &StraceFallback{
		events: make(chan types.SyscallEvent, 256),
		done:   make(chan struct{}),
	}
}

// Start attaches strace to the target PID and begins parsing output.
// targetPIDNS is ignored; instead use StartWithPID.
func (s *StraceFallback) Start(_ uint32) error {
	return errors.New("StraceFallback requires StartWithPID, not Start")
}

// StartWithPID attaches strace to the given host PID.
func (s *StraceFallback) StartWithPID(pid uint32) error {
	s.cmd = exec.Command("strace",
		"-f",
		"-e", "trace=connect,sendto,sendmsg,sendmmsg,bind,listen,accept,accept4,execve,openat,rename,renameat,renameat2",
		"-e", "signal=none",
		"-p", strconv.FormatUint(uint64(pid), 10),
	)

	stderr, err := s.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("strace stderr pipe: %w", err)
	}

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("starting strace: %w", err)
	}

	go func() {
		defer close(s.events)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			evt, ok := parseStraceLine(scanner.Text())
			if ok {
				select {
				case s.events <- evt:
				case <-s.done:
					return
				}
			}
		}
	}()

	return nil
}

func (s *StraceFallback) Events() <-chan types.SyscallEvent {
	return s.events
}

func (s *StraceFallback) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
			_ = s.cmd.Wait()
		}
	})
	return nil
}

func (s *StraceFallback) Method() string {
	return "strace"
}
