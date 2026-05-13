package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/RalianENG/kojuto/internal/types"
)

// straceMaxLine bounds the size of a single strace stderr line. With
// `-s 256` the per-arg cap is 256 bytes, so realistic execve+argv lines
// stay well under 1 MiB. We allow 16 MiB to accommodate exotic kernels
// or tracee writes interleaved on the shared docker exec stderr; lines
// longer than this are treated as adversarial (a malicious package
// trying to overflow bufio.Scanner's default 64 KiB cap so the scan
// loop exits and subsequent strace events are silently dropped).
const straceMaxLine = 16 * 1024 * 1024

// ContainerStrace monitors connect(2) syscalls by running strace inside the Docker container.
// This works on all platforms where Docker is available (Linux, macOS, Windows).
// ContainerStrace monitors connect(2) syscalls by running strace inside the Docker container.
// This works on all platforms where Docker is available (Linux, macOS, Windows).
type ContainerStrace struct {
	events  chan types.SyscallEvent
	done    chan struct{}
	dropped uint64 // events dropped due to full buffer
}

// NewContainerStrace creates a new in-container strace probe.
func NewContainerStrace() *ContainerStrace {
	return &ContainerStrace{
		events: make(chan types.SyscallEvent, 8192),
		done:   make(chan struct{}),
	}
}

// Start is not supported for ContainerStrace. Use StartAndInstall instead.
func (c *ContainerStrace) Start(_ uint32) error {
	return errors.New("ContainerStrace requires StartAndInstall, not Start")
}

// StartAndInstall runs strace wrapping pip install inside the container.
// It blocks until installation completes, populating the events channel.
//
// On every error path the events channel is closed before returning so
// callers can safely `for evt := range c.Events()` to drain — without
// this, a fail-fast error (e.g. ctx already canceled before cmd.Start)
// would leave the channel open and hang the caller.
func (c *ContainerStrace) StartAndInstall(ctx context.Context, containerID string, installCmd []string) ([]byte, error) {
	cmd := c.buildCommand(ctx, containerID, installCmd)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		close(c.events)
		return nil, fmt.Errorf("strace stderr pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		close(c.events)
		return nil, fmt.Errorf("pip stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		close(c.events)
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
		"-s", "256",
		// clone/clone3 are traced to propagate execve comm across thread
		// boundaries (V8 spawns worker threads via clone — they never
		// execve so the analyzer's PID→comm map cannot attribute their
		// mprotect events without seeing the parent relationship).
		"-e", "trace=connect,sendto,sendmsg,sendmmsg,bind,listen,accept,accept4,execve,clone,clone3,openat,rename,renameat,renameat2,sendfile,ptrace,mmap,mprotect,unlink,unlinkat",
		"-e", "signal=none",
		"--",
	}
	args = append(args, installCmd...)

	return exec.CommandContext(ctx, "docker", args...)
}

func (c *ContainerStrace) parseStraceOutput(stderr io.ReadCloser, done chan<- struct{}) {
	defer close(done)

	state := NewParseState()
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 64*1024), straceMaxLine)
	for scanner.Scan() {
		evt, ok := parseStraceLine(scanner.Text(), state)
		if !ok {
			continue
		}

		select {
		case c.events <- evt:
		case <-c.done:
			return
		default:
			// Buffer full — drop event to prevent deadlock.
			// The caller should treat this as inconclusive.
			c.dropped++
		}
	}
	if err := scanner.Err(); err != nil {
		// bufio.ErrTooLong here means the tracee wrote a >16 MiB
		// chunk to the shared docker-exec stderr without a newline,
		// most plausibly to disable parsing of subsequent strace
		// trace lines. Any other error means the pipe died early.
		// Either way we lost an unknown number of events, so flip
		// the verdict to inconclusive via the dropped counter.
		c.dropped++
		fmt.Fprintf(os.Stderr, "warning: strace stderr scanner aborted: %v\n", err)
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

// Dropped returns events discarded because the events channel was full.
func (c *ContainerStrace) Dropped() uint64 {
	return c.dropped
}
