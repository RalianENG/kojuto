package probe

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestContainerStrace_Method(t *testing.T) {
	cs := NewContainerStrace()
	if cs.Method() != "strace-container" {
		t.Errorf("Method() = %q, want %q", cs.Method(), "strace-container")
	}
}

func TestContainerStrace_Start_Unsupported(t *testing.T) {
	cs := NewContainerStrace()
	err := cs.Start(0)
	if err == nil {
		t.Fatal("expected error from Start()")
	}
	if err.Error() != "ContainerStrace requires StartAndInstall, not Start" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestContainerStrace_CloseIdempotent(t *testing.T) {
	cs := NewContainerStrace()

	// First close should succeed.
	if err := cs.Close(); err != nil {
		t.Fatalf("first Close() failed: %v", err)
	}

	// Second close should also succeed (idempotent).
	if err := cs.Close(); err != nil {
		t.Fatalf("second Close() failed: %v", err)
	}
}

func TestContainerStrace_Events(t *testing.T) {
	cs := NewContainerStrace()
	ch := cs.Events()
	if ch == nil {
		t.Fatal("Events() returned nil channel")
	}
}

func TestContainerStrace_Dropped(t *testing.T) {
	cs := NewContainerStrace()
	if got := cs.Dropped(); got != 0 {
		t.Errorf("Dropped() on fresh probe = %d, want 0", got)
	}
	// Simulate the parser hitting the buffer-full fallback. In production
	// this path feeds the verdict → inconclusive gate in cmd/root.go.
	cs.dropped = 42
	if got := cs.Dropped(); got != 42 {
		t.Errorf("Dropped() after increment = %d, want 42", got)
	}
}

// TestContainerStrace_StartAndInstall_CtxAlreadyDeadlined pins the
// fast-path channel-close behavior. When ctx is already canceled before
// cmd.Start runs (which the runProbeAndInstall import loop hits if the
// install phase consumed the whole timeout budget), the events channel
// must still be closed so the caller's `for evt := range ip.Events()`
// drain loop returns. The previous code only closed on the success
// path, hanging the scanner indefinitely under tight timeouts.
func TestContainerStrace_StartAndInstall_CtxAlreadyDeadlined(t *testing.T) {
	cs := NewContainerStrace()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Force cmd.Start to fail with "context canceled".

	_, err := cs.StartAndInstall(ctx, "fake-container-id", []string{"true"})
	if err == nil {
		t.Fatal("expected error from canceled ctx, got nil")
	}

	// The drain loop must NOT block. If the channel is still open, this
	// hangs and the test times out — which is exactly the bug we're
	// regression-guarding against.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range cs.Events() {
		}
	}()
	select {
	case <-done:
		// pass — channel was closed, range terminated
	case <-time.After(2 * time.Second):
		t.Fatal("Events() channel still open after StartAndInstall error — drain loop would hang the scanner")
	}
}

func TestDrainReader(t *testing.T) {
	content := "hello world\nfoo bar\n"
	reader := io.NopCloser(bytes.NewReader([]byte(content)))

	got := drainReader(reader)
	if string(got) != content {
		t.Errorf("drainReader = %q, want %q", string(got), content)
	}
}

func TestDrainReader_Empty(t *testing.T) {
	reader := io.NopCloser(bytes.NewReader(nil))

	got := drainReader(reader)
	if len(got) != 0 {
		t.Errorf("drainReader(empty) returned %d bytes, want 0", len(got))
	}
}

func TestDrainReader_Large(t *testing.T) {
	// drainReader caps at 10MB.
	const maxSize = 10 * 1024 * 1024
	big := make([]byte, maxSize+1000)
	for i := range big {
		big[i] = 'x'
	}
	reader := io.NopCloser(bytes.NewReader(big))

	got := drainReader(reader)
	if len(got) > maxSize {
		t.Errorf("drainReader exceeded max: got %d bytes, want <= %d", len(got), maxSize)
	}
}

func TestBuildCommand(t *testing.T) {
	cs := NewContainerStrace()
	ctx := context.Background()

	cmd := cs.buildCommand(ctx, "abc123", []string{"pip", "install", "requests"})

	// The command should be "docker".
	if cmd.Path == "" {
		t.Fatal("command path is empty")
	}

	args := cmd.Args
	// cmd.Args[0] is the command itself (docker), then the rest are arguments.
	// Verify key arguments are present.
	if len(args) < 5 {
		t.Fatalf("too few args: %v", args)
	}

	// Check that "exec" and container ID are in the right positions.
	const dockerExec = "exec"
	if args[1] != dockerExec {
		t.Errorf("args[1] = %q, want %q", args[1], dockerExec)
	}
	if args[2] != "abc123" {
		t.Errorf("args[2] = %q, want %q", args[2], "abc123")
	}
	if args[3] != "strace" {
		t.Errorf("args[3] = %q, want %q", args[3], "strace")
	}
	if args[4] != "-f" {
		t.Errorf("args[4] = %q, want %q", args[4], "-f")
	}

	// Verify the install command appears at the end after "--".
	found := false
	for i, a := range args {
		if a == "--" {
			remaining := args[i+1:]
			if len(remaining) != 3 || remaining[0] != "pip" || remaining[1] != "install" || remaining[2] != "requests" {
				t.Errorf("install command after -- = %v, want [pip install requests]", remaining)
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("did not find '--' separator in args: %v", args)
	}
}

func TestParseStraceOutput(t *testing.T) {
	// Provide strace lines that parseStraceLine can actually parse.
	straceLines := strings.Join([]string{
		`[pid 100] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0`,
		`[pid 101] execve("/usr/bin/curl", ["curl", "http://evil.com"], ...) = 0`,
		`some unrelated line that should be skipped`,
		`[pid 102] connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) = 0`,
	}, "\n")

	cs := &ContainerStrace{
		events: make(chan types.SyscallEvent, 256),
		done:   make(chan struct{}),
	}

	reader := io.NopCloser(strings.NewReader(straceLines))
	parseDone := make(chan struct{})
	go cs.parseStraceOutput(reader, parseDone)

	<-parseDone

	// Collect events from the channel.
	close(cs.events)
	var events []types.SyscallEvent
	for evt := range cs.events {
		events = append(events, evt)
	}

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// First event: connect to 93.184.216.34:443.
	if events[0].Syscall != types.EventConnect {
		t.Errorf("event[0].Syscall = %q, want %q", events[0].Syscall, types.EventConnect)
	}
	if events[0].DstAddr != "93.184.216.34" {
		t.Errorf("event[0].DstAddr = %q, want %q", events[0].DstAddr, "93.184.216.34")
	}
	if events[0].DstPort != 443 {
		t.Errorf("event[0].DstPort = %d, want 443", events[0].DstPort)
	}

	// Second event: execve curl.
	if events[1].Syscall != types.EventExecve {
		t.Errorf("event[1].Syscall = %q, want %q", events[1].Syscall, types.EventExecve)
	}
	if events[1].Comm != "/usr/bin/curl" {
		t.Errorf("event[1].Comm = %q, want %q", events[1].Comm, "/usr/bin/curl")
	}

	// Third event: connect to 10.0.0.1:80.
	if events[2].Syscall != types.EventConnect {
		t.Errorf("event[2].Syscall = %q, want %q", events[2].Syscall, types.EventConnect)
	}
	if events[2].DstPort != 80 {
		t.Errorf("event[2].DstPort = %d, want 80", events[2].DstPort)
	}
}

func TestParseStraceOutput_Done(_ *testing.T) {
	// Verify that parseStraceOutput exits when c.done is closed.
	cs := &ContainerStrace{
		events: make(chan types.SyscallEvent), // unbuffered — will block
		done:   make(chan struct{}),
	}

	// Many lines to ensure it would block on the channel send.
	var lines []string
	for range 100 {
		lines = append(lines, `[pid 100] connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0`)
	}
	reader := io.NopCloser(strings.NewReader(strings.Join(lines, "\n")))

	parseDone := make(chan struct{})
	close(cs.done) // signal done immediately
	go cs.parseStraceOutput(reader, parseDone)

	<-parseDone // should complete without hanging
}
