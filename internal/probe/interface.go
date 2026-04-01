package probe

import "github.com/RalianENG/kojuto/internal/types"

// Probe is the interface for syscall monitoring.
type Probe interface {
	Start(targetPIDNS uint32) error
	Events() <-chan types.ConnectEvent
	Close() error
	Method() string
}
