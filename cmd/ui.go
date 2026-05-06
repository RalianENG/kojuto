package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"golang.org/x/term"

	"github.com/RalianENG/kojuto/internal/types"
)

// Style helpers. fatih/color reads NO_COLOR and detects TTY by default,
// but we explicitly disable when stderr is not a terminal so that piped
// or redirected output stays plain. The --no-color flag (set by
// configureColor) and NO_COLOR env are both respected.
//
// All decorations are pure presentation: every styled string is a
// degradable rendering of the same characters that print without color.
// A user reading via screen reader or `kojuto scan ... 2> log.txt` sees
// the identical glyphs and tokens — no information is color-only.
var (
	styleRedBold    = color.New(color.FgRed, color.Bold).SprintFunc()
	styleGreenBold  = color.New(color.FgGreen, color.Bold).SprintFunc()
	styleYellowBold = color.New(color.FgYellow, color.Bold).SprintFunc()
	styleBold       = color.New(color.Bold).SprintFunc()
	styleDim        = color.New(color.Faint).SprintFunc()
	styleCyan       = color.New(color.FgCyan).SprintFunc()
)

// configureColor decides whether ANSI escape codes are emitted for the
// rest of the process. Called once from PersistentPreRun so any output
// after startup honors the same setting.
//
//   - --no-color flag → force off
//   - NO_COLOR env (any non-empty value) → force off (handled by fatih/color)
//   - stderr not a TTY → off (we route progress + verdict to stderr)
//   - otherwise → on
func configureColor(noColor bool) {
	if noColor {
		color.NoColor = true
		return
	}
	// fatih/color initializes NoColor based on stdout's TTY status. We
	// override using stderr because the user-facing progress + verdict
	// goes to stderr (stdout is reserved for the JSON report when
	// `-o -` or no -o is used).
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		color.NoColor = true
	}
}

// progressOut returns the writer for phase progress narration. When
// --quiet is in effect, all phase narration is dropped — only the
// final verdict block reaches the user.
func progressOut() io.Writer {
	if flagQuiet {
		return io.Discard
	}
	return os.Stderr
}

// phaseInfo prints a single, untimed narration line:
//
//	preparing sandbox
//	scanning  axios-attack-demo (npm)
//
// `verb` is column-padded to 9 chars to vertically align with timed
// phase lines. `extra` is the free-form descriptor.
func phaseInfo(verb, extra string) {
	fmt.Fprintf(progressOut(), "  %s %s\n", styleDim(padRight(verb, 9)), extra)
}

// phaseStart records wall time for a phase that completes after
// observable work (install/import). Calling .end() emits the
// completion line with elapsed time inline:
//
//	install   2.3s
//	import    1.1s   Linux
//
// We print only on completion (no "starting" line) to keep the log
// terse — preceding phaseInfo lines provide context during silence.
type phaseStart struct {
	verb  string
	extra string
	t0    time.Time
}

func startPhase(verb, extra string) phaseStart {
	return phaseStart{verb: verb, extra: extra, t0: time.Now()}
}

func (p phaseStart) end() {
	if p.t0.IsZero() {
		return
	}
	d := time.Since(p.t0)
	dur := padRight(formatDuration(d), 6)
	fmt.Fprintf(progressOut(), "  %s %s  %s\n",
		styleDim(padRight(p.verb, 9)),
		styleCyan(dur),
		styleDim(p.extra))
}

// formatDuration renders sub-second times as "0.42s" and longer as
// "12s" / "1m 23s". Keeps the column narrow.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d / time.Minute)
	s := int(d.Seconds()) - m*60
	return fmt.Sprintf("%dm %ds", m, s)
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// pkgCoord returns "name@version" or just "name" when version is empty.
// Used as the human-readable package identifier in headers and verdict
// blocks.
func pkgCoord(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// renderVerdictBlock writes the post-scan verdict + breakdown to w.
// Format is the structured plain-text design — no box-drawing, no
// ASCII art, just indentation and degradable color. Designed to read
// the same with or without ANSI.
func renderVerdictBlock(w io.Writer, verdict, pkg, version string, suspiciousCount int, summary *types.ReportSummary, lostSamples, dropped uint64) {
	fmt.Fprintln(w)

	switch verdict {
	case types.VerdictClean:
		fmt.Fprintf(w, "  %s  %s\n", styleGreenBold("✓ CLEAN"), pkgCoord(pkg, version))
		if summary != nil && summary.Description != "" {
			fmt.Fprintf(w, "  %s\n", summary.Description)
		}
	case types.VerdictInconclusive:
		fmt.Fprintf(w, "  %s  %s\n", styleYellowBold("! INCONCLUSIVE"), pkgCoord(pkg, version))
		fmt.Fprintln(w)
		renderInconclusiveDetail(w, lostSamples, dropped)
		if summary != nil && summary.Remediation != "" {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "  %s\n", summary.Remediation)
		}
	case types.VerdictSuspicious:
		fmt.Fprintf(w, "  %s  %s\n", styleRedBold("✗ SUSPICIOUS"), pkgCoord(pkg, version))
		fmt.Fprintln(w)
		if summary != nil {
			renderBreakdown(w, suspiciousCount, summary)
			if summary.Remediation != "" {
				fmt.Fprintln(w)
				fmt.Fprintf(w, "  %s\n", summary.Remediation)
			}
		} else {
			fmt.Fprintf(w, "  %d suspicious event(s) detected.\n", suspiciousCount)
		}
	}
}

func renderInconclusiveDetail(w io.Writer, lostSamples, dropped uint64) {
	parts := []string{}
	if lostSamples > 0 {
		parts = append(parts, styleCyan(strconv.FormatUint(lostSamples, 10))+" kernel sample(s) lost")
	}
	if dropped > 0 {
		parts = append(parts, styleCyan(strconv.FormatUint(dropped, 10))+" event(s) dropped")
	}
	if len(parts) == 0 {
		parts = append(parts, "probe data lost")
	}
	fmt.Fprintf(w, "  %s\n", strings.Join(parts, ", "))
	fmt.Fprintf(w, "  %s\n", styleDim("Detection coverage incomplete — treating as failure."))
}

// renderBreakdown emits the per-category table:
//
//	46 events across 7 categories:
//	   14  memory_execution    shellcode injection (mmap+mprotect RWX)
//	   20  evasion             ptrace self-check, sandbox detection
//	    6  credential_access   ~/.ssh, ~/.aws, ~/.git-credentials
func renderBreakdown(w io.Writer, total int, summary *types.ReportSummary) {
	if len(summary.Breakdown) == 0 {
		// Fallback for older summaries (e.g. tests that don't populate
		// Breakdown). Use the joined description.
		if summary.Description != "" {
			fmt.Fprintf(w, "  %s\n", summary.Description)
		}
		return
	}

	fmt.Fprintf(w, "  %s events across %s categories:\n",
		styleCyan(strconv.Itoa(total)),
		styleCyan(strconv.Itoa(len(summary.Breakdown))))

	// Compute alignment: longest category name + small gutter.
	nameWidth := 0
	for _, h := range summary.Breakdown {
		if len(h.Category) > nameWidth {
			nameWidth = len(h.Category)
		}
	}

	for _, h := range summary.Breakdown {
		fmt.Fprintf(w, "  %4s  %s  %s\n",
			styleCyan(strconv.Itoa(h.Count)),
			styleBold(padRight(h.Category, nameWidth)),
			styleDim(h.Description))
	}
}

// renderBatchSummary writes the post-batch table:
//
//	scanned 50 packages in 1m 38s
//
//	✓ 47 clean
//	✗  3 suspicious:
//	     requests-utility       credential_access, c2_communication
//	     axios-fork             code_execution, anti_forensics
func renderBatchSummary(w io.Writer, total, scanErrors int, suspicious []batchSuspicious, elapsed time.Duration) {
	clean := total - len(suspicious) - scanErrors

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  scanned %s packages in %s\n",
		styleCyan(strconv.Itoa(total)),
		styleDim(formatDuration(elapsed)))
	fmt.Fprintln(w)

	if clean > 0 {
		fmt.Fprintf(w, "  %s %d clean\n",
			styleGreenBold("✓"),
			clean)
	}
	if scanErrors > 0 {
		fmt.Fprintf(w, "  %s %d errored\n",
			styleYellowBold("!"),
			scanErrors)
	}
	if len(suspicious) > 0 {
		fmt.Fprintf(w, "  %s %d suspicious:\n",
			styleRedBold("✗"),
			len(suspicious))

		nameWidth := 0
		for _, s := range suspicious {
			if len(s.name) > nameWidth {
				nameWidth = len(s.name)
			}
		}
		for _, s := range suspicious {
			fmt.Fprintf(w, "       %s  %s\n",
				styleBold(padRight(s.name, nameWidth)),
				styleDim(strings.Join(s.categories, ", ")))
		}
	}
}

// batchSuspicious is a minimal record carried from per-package scans
// to the batch summary renderer. Defined here (not inline in
// runBatchScan) so renderBatchSummary stays decoupled and unit-testable.
type batchSuspicious struct {
	name       string
	categories []string
}
