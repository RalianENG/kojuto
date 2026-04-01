package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/RalianENG/kojuto/internal/types"
)

// Generate creates a Report from scan results.
func Generate(pkg, version, verdict, probeMethod string, events []types.ConnectEvent, lostSamples uint64) types.Report {
	if events == nil {
		events = []types.ConnectEvent{}
	}
	return types.Report{
		Package:     pkg,
		Version:     version,
		Timestamp:   time.Now().UTC(),
		Verdict:     verdict,
		Events:      events,
		ProbeMethod: probeMethod,
		LostSamples: lostSamples,
	}
}

// WriteJSON writes the report as indented JSON to w.
func WriteJSON(r types.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
