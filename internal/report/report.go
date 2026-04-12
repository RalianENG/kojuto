package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

// Generate creates a Report from scan results.
func Generate(pkg, version, ecosystem, verdict, probeMethod string, events []types.SyscallEvent, lostSamples, dropped uint64, summary *types.ReportSummary) types.Report {
	if events == nil {
		events = []types.SyscallEvent{}
	}

	return types.Report{
		Package:     pkg,
		Version:     version,
		Ecosystem:   ecosystem,
		Timestamp:   time.Now().UTC(),
		Verdict:     verdict,
		Summary:     summary,
		Events:      events,
		ProbeMethod: probeMethod,
		LostSamples: lostSamples,
		Dropped:     dropped,
	}
}

// WriteJSON writes the report as indented JSON to w.
func WriteJSON(r *types.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}

	return nil
}
