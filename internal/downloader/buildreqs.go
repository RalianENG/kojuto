package downloader

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RalianENG/kojuto/internal/types"
)

// A legacy-free sdist names its build backend in pyproject.toml's
// [build-system] requires (hatchling, poetry-core, flit-core, ...). A
// victim's pip installs those into an isolated build environment before it
// builds; the analysis sandbox has no network, so without them the build
// fails with BackendUnavailable and the package's code never runs. Measured
// on 260 malware samples: 14 failed for exactly this reason.
//
// The requirements are fetched per scan, in the download sandbox, as wheels
// only (no package code runs where there is network), at whatever version
// a victim would get today. Nothing is baked into the image: a fixed set of
// pre-installed backends would itself be a constant for a package to test
// for.

const (
	// pyprojectMaxSize bounds the pyproject.toml read out of an archive.
	pyprojectMaxSize = 256 << 10
	// archiveScanMaxEntries / archiveScanMaxBytes bound the walk over an
	// attacker-supplied archive looking for pyproject.toml.
	archiveScanMaxEntries = 20000
	archiveScanMaxBytes   = 512 << 20
	// maxBuildRequires bounds how many requirements are passed on.
	maxBuildRequires = 32
)

// buildRequirementRe accepts a PEP 508 requirement in the restricted shape
// build backends are declared with: a distribution name, optional extras,
// optional version specifiers and an optional environment marker. It
// rejects what would change how pip runs rather than what it fetches — a
// leading "-" (an option such as --index-url), a direct reference ("name @
// url"), and any URL or path.
var buildRequirementRe = regexp.MustCompile(
	`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,\s-]*\])?\s*([<>=!~]=?=?\s*[A-Za-z0-9.*+!_-]+\s*(,\s*[<>=!~]=?=?\s*[A-Za-z0-9.*+!_-]+\s*)*)?(;[A-Za-z0-9._\s<>=!~'"()-]*)?$`,
)

func validBuildRequirement(req string) bool {
	if req == "" || len(req) > 200 {
		return false
	}
	if strings.Contains(req, "@") || strings.Contains(req, "://") || strings.ContainsAny(req, "/\\") {
		return false
	}
	return buildRequirementRe.MatchString(req)
}

// BuildRequires returns the validated [build-system] requires of the sdist
// at localPath (a .tar.gz, .zip, or an unpacked source directory). It returns
// nil without error when there is nothing to fetch: a wheel, no
// pyproject.toml, or no requires. Requirements that fail validation are
// dropped, never passed on.
func BuildRequires(localPath string) ([]string, error) {
	data, err := readPyproject(localPath)
	if err != nil || data == nil {
		return nil, err
	}
	reqs, ok := parseBuildRequires(string(data))
	if !ok {
		return nil, nil
	}
	var out []string
	for _, r := range reqs {
		r = strings.TrimSpace(r)
		if validBuildRequirement(r) {
			out = append(out, r)
		}
		if len(out) == maxBuildRequires {
			break
		}
	}
	return out, nil
}

// readPyproject returns the top-level pyproject.toml of an sdist, or nil if
// there is none. Archives are read in memory, never extracted.
func readPyproject(localPath string) ([]byte, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", localPath, err)
	}
	if info.IsDir() {
		return readCapped(filepath.Join(localPath, "pyproject.toml"))
	}
	name := strings.ToLower(filepath.Base(localPath))
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return pyprojectFromTarGz(localPath)
	case strings.HasSuffix(name, ".zip"):
		return pyprojectFromZip(localPath)
	default:
		return nil, nil // wheels need no build
	}
}

func readCapped(p string) ([]byte, error) {
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", p, err)
	}
	defer f.Close()
	return readAllCapped(f)
}

// isTopLevelPyproject matches "<top>/pyproject.toml" — the sdist root, not a
// nested project.
func isTopLevelPyproject(name string) bool {
	clean := path.Clean(strings.TrimPrefix(name, "./"))
	return path.Base(clean) == "pyproject.toml" && strings.Count(clean, "/") == 1
}

func pyprojectFromTarGz(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", p, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil // not a gzip stream: nothing to read, not an error
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, archiveScanMaxBytes))
	for range archiveScanMaxEntries {
		hdr, err := tr.Next()
		if err != nil {
			return nil, nil //nolint:nilerr // end of archive or a malformed one: no pyproject to report
		}
		if hdr.Typeflag == tar.TypeReg && isTopLevelPyproject(hdr.Name) {
			return readAllCapped(tr)
		}
	}
	return nil, nil
}

func pyprojectFromZip(p string) ([]byte, error) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, nil //nolint:nilerr // not a zip: nothing to read
	}
	defer zr.Close()
	for i, zf := range zr.File {
		if i == archiveScanMaxEntries {
			break
		}
		if !zf.FileInfo().Mode().IsRegular() || !isTopLevelPyproject(zf.Name) {
			continue
		}
		return readZipEntry(zf)
	}
	return nil, nil
}

// parseBuildRequires extracts the string array assigned to `requires` in the
// [build-system] table. It is deliberately a narrow reader rather than a TOML
// parser: it understands table headers, comments, basic and literal strings
// and a (possibly multi-line) array of strings, and gives up (ok=false) on
// anything else, in which case nothing is fetched.
func parseBuildRequires(doc string) (reqs []string, ok bool) {
	lines := strings.Split(doc, "\n")
	inTable := false
	for i := range lines {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "[") {
			inTable = strings.TrimSpace(strings.SplitN(line, "#", 2)[0]) == "[build-system]"
			continue
		}
		if !inTable || !strings.HasPrefix(line, "requires") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "requires"))
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(rest, "="))
		// Join continuation lines until the array closes.
		for j := i + 1; j < len(lines) && !arrayClosed(value); j++ {
			value += "\n" + lines[j]
		}
		return parseStringArray(value)
	}
	return nil, false
}

// arrayClosed reports whether s holds a complete array, ignoring brackets
// inside strings and comments.
func arrayClosed(s string) bool {
	_, ok := parseStringArray(s)
	return ok
}

// parseStringArray parses `[ "a", 'b', ... ]`, allowing newlines, trailing
// commas and # comments between elements.
// readZipEntry reads one archive member, capped at pyprojectMaxSize. An
// unreadable member is treated as absent.
func readZipEntry(zf *zip.File) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, nil //nolint:nilerr // unreadable entry: treat as absent
	}
	defer rc.Close()
	return readAllCapped(rc)
}

func parseStringArray(s string) ([]string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil, false
	}
	var out []string
	i := 1
	for i < len(s) {
		switch c := s[i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',':
			i++
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == ']':
			return out, true
		case c == '"' || c == '\'':
			str, next, ok := readTOMLString(s, i)
			if !ok {
				return nil, false
			}
			out = append(out, str)
			i = next
		default:
			return nil, false
		}
	}
	return nil, false
}

// DownloadBuildDeps fetches the given build requirements (and their own
// dependencies) as wheels inside a download sandbox, into destDir. Wheels
// only: no sdist is built and no package code runs where there is network.
// The requirements follow "--" so none can be read as a pip option.
func DownloadBuildDeps(ctx context.Context, reqs []string, destDir string) ([]types.SyscallEvent, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	args := append([]string{"pip"}, pypiDownloadArgs()...)
	args = append(args, "--")
	args = append(args, reqs...)
	out, events, err := runInSandbox(ctx, destDir, args)
	echoSandboxOutput(out)
	if err != nil {
		return events, fmt.Errorf("fetching build requirements: %w", err)
	}
	return events, nil
}

// readTOMLString reads the basic ("...", with backslash escapes) or literal
// ('...') string starting at s[i] and returns it with the index just past
// its closing quote.
func readTOMLString(s string, i int) (str string, next int, ok bool) {
	quote := s[i]
	var b strings.Builder
	j := i + 1
	for j < len(s) && s[j] != quote {
		if quote == '"' && s[j] == '\\' && j+1 < len(s) {
			j++
		}
		b.WriteByte(s[j])
		j++
	}
	if j >= len(s) {
		return "", 0, false
	}
	return b.String(), j + 1, true
}

// readAllCapped reads at most pyprojectMaxSize bytes of a pyproject.toml.
func readAllCapped(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, pyprojectMaxSize))
	if err != nil {
		return nil, fmt.Errorf("reading pyproject.toml: %w", err)
	}
	return data, nil
}
