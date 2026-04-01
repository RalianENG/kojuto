package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/RalianENG/kojuto/internal/types"
)

// ContainerStrace monitors connect(2) syscalls by running strace inside the Docker container.
// This works on all platforms where Docker is available (Linux, macOS, Windows).
type ContainerStrace struct {
	events chan types.SyscallEvent
	done   chan struct{}
}

// NewContainerStrace creates a new in-container strace probe.
func NewContainerStrace() *ContainerStrace {
	return &ContainerStrace{
		events: make(chan types.SyscallEvent, 256),
		done:   make(chan struct{}),
	}
}

// Start is not supported for ContainerStrace. Use StartAndInstall instead.
func (c *ContainerStrace) Start(_ uint32) error {
	return errors.New("ContainerStrace requires StartAndInstall, not Start")
}

// StartAndInstall runs strace wrapping pip install inside the container.
// It blocks until installation completes, populating the events channel.
func (c *ContainerStrace) StartAndInstall(ctx context.Context, containerID string, installCmd []string) ([]byte, error) {
	cmd := c.buildCommand(ctx, containerID, installCmd)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("strace stderr pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("pip stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting strace in container: %w", err)
	}

	straceDone := make(chan struct{})
	go c.parseStraceOutput(stderr, straceDone)

	pipOut := drainReader(stdout)

	cmdErr := cmd.Wait()
	<-straceDone
	close(c.events)

	if cmdErr != nil {
		return pipOut, fmt.Errorf("pip install in container failed: %w", cmdErr)
	}

	return pipOut, nil
}

func (c *ContainerStrace) buildCommand(ctx context.Context, containerID string, installCmd []string) *exec.Cmd {
	args := []string{
		"exec", containerID,
		"strace", "-f",
		"-e", "trace=connect,sendto,sendmsg,sendmmsg,bind,listen,accept,accept4,execve,openat,rename,renameat,renameat2,sendfile",
		"-e", "signal=none",
		"--",
	}
	args = append(args, installCmd...)

	return exec.CommandContext(ctx, "docker", args...)
}

func (c *ContainerStrace) parseStraceOutput(stderr io.ReadCloser, done chan<- struct{}) {
	defer close(done)

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		evt, ok := parseStraceLine(scanner.Text())
		if !ok {
			continue
		}

		select {
		case c.events <- evt:
		case <-c.done:
			return
		}
	}
}

// drainReader reads from r up to 10MB and returns the content.
func drainReader(r io.ReadCloser) []byte {
	const maxSize = 10 * 1024 * 1024

	var out []byte

	buf := make([]byte, 4096)

	for {
		n, err := r.Read(buf)
		if n > 0 && len(out) < maxSize {
			remaining := maxSize - len(out)
			if n > remaining {
				n = remaining
			}

			out = append(out, buf[:n]...)
		}

		if err != nil {
			return out
		}
	}
}

// Events returns the channel of captured connect events.
func (c *ContainerStrace) Events() <-chan types.SyscallEvent {
	return c.events
}

// Close stops the probe.
func (c *ContainerStrace) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}

	return nil
}

// Method returns the probe method identifier.
func (c *ContainerStrace) Method() string {
	return "strace-container"
}
