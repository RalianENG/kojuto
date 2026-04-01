package probe

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"

	"github.com/RalianENG/kojuto/internal/types"
)

// ContainerStrace monitors connect(2) syscalls by running strace inside the Docker container.
// This works on all platforms where Docker is available (Linux, macOS, Windows).
type ContainerStrace struct {
	events    chan types.ConnectEvent
	done      chan struct{}
	installOk bool
}

// NewContainerStrace creates a new in-container strace probe.
func NewContainerStrace() *ContainerStrace {
	return &ContainerStrace{
		events: make(chan types.ConnectEvent, 256),
		done:   make(chan struct{}),
	}
}

// Start is not supported for ContainerStrace. Use StartAndInstall instead.
func (c *ContainerStrace) Start(targetPIDNS uint32) error {
	return fmt.Errorf("ContainerStrace requires StartAndInstall, not Start")
}

// StartAndInstall runs strace wrapping pip install inside the container.
// It blocks until installation completes, populating the events channel.
func (c *ContainerStrace) StartAndInstall(ctx context.Context, containerID, pkg string) ([]byte, error) {
	args := []string{
		"exec", containerID,
		"strace", "-f",
		"-e", "trace=connect",
		"-e", "signal=none",
		"--",
		"pip", "install",
		"--no-deps",
		"--no-index",
		"--find-links=/packages",
		pkg,
	}

	cmd := exec.CommandContext(ctx, "docker", args...)

	// strace writes to stderr, pip writes to stdout
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

	// Parse strace output in background
	straceDone := make(chan struct{})
	go func() {
		defer close(straceDone)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			evt, ok := parseStraceLine(scanner.Text())
			if ok {
				select {
				case c.events <- evt:
				case <-c.done:
					return
				}
			}
		}
	}()

	// Drain pip stdout (capped at 10MB to prevent memory exhaustion)
	const maxPipOut = 10 * 1024 * 1024
	var pipOut []byte
	pipDone := make(chan struct{})
	go func() {
		defer close(pipDone)
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 && len(pipOut) < maxPipOut {
				remaining := maxPipOut - len(pipOut)
				if n > remaining {
					n = remaining
				}
				pipOut = append(pipOut, buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for command to finish
	cmdErr := cmd.Wait()
	<-straceDone
	<-pipDone

	c.installOk = cmdErr == nil
	close(c.events)

	if cmdErr != nil {
		return pipOut, fmt.Errorf("pip install in container failed: %w", cmdErr)
	}
	return pipOut, nil
}

func (c *ContainerStrace) Events() <-chan types.ConnectEvent {
	return c.events
}

func (c *ContainerStrace) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return nil
}

func (c *ContainerStrace) Method() string {
	return "strace-container"
}
