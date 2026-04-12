package probe

import "github.com/RalianENG/kojuto/internal/types"

// Probe is the interface for syscall monitoring.
type Probe interface {
	Start(targetPIDNS uint32) error
	Events() <-chan types.SyscallEvent
	Close() error
	Method() string
	// Dropped returns the count of events that were discarded because the
	// events channel was full. Any non-zero value means the scan lost
	// visibility — the caller must treat the verdict as `inconclusive`.
	Dropped() uint64
}
