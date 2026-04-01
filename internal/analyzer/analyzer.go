package analyzer

import "github.com/RalianENG/kojuto/internal/types"

// Analyze determines a verdict based on captured events.
// For v0.1, any connect(2) attempt during install is suspicious.
func Analyze(events []types.ConnectEvent) string {
	if len(events) > 0 {
		return types.VerdictSuspicious
	}
	return types.VerdictClean
}
