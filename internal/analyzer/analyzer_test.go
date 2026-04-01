package analyzer

import (
	"testing"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestAnalyze_Clean(t *testing.T) {
	verdict := Analyze(nil)
	if verdict != types.VerdictClean {
		t.Errorf("expected clean, got %s", verdict)
	}

	verdict = Analyze([]types.ConnectEvent{})
	if verdict != types.VerdictClean {
		t.Errorf("expected clean for empty slice, got %s", verdict)
	}
}

func TestAnalyze_Suspicious(t *testing.T) {
	events := []types.ConnectEvent{
		{
			Timestamp: time.Now(),
			PID:       1234,
			Family:    2,
			DstAddr:   "203.0.113.50",
			DstPort:   443,
		},
	}

	verdict := Analyze(events)
	if verdict != types.VerdictSuspicious {
		t.Errorf("expected suspicious, got %s", verdict)
	}
}
