// Package depfile parses dependency files (requirements.txt, package.json)
// and extracts package names and versions for batch scanning.
package depfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RalianENG/kojuto/internal/types"
)

// Dep represents a single dependency extracted from a file.
type Dep struct {
	Name    string
	Version string
}

// Parse reads a dependency file and returns the list of packages.
// Ecosystem is auto-detected from the filename.
func Parse(path string) ([]Dep, string, error) {
	ext := strings.ToLower(filepath.Base(path))

	switch {
	case strings.HasSuffix(ext, ".json"):
		deps, err := parsePackageJSON(path)
		return deps, types.EcosystemNpm, err
	case strings.HasSuffix(ext, ".txt"):
		deps, err := parseRequirementsTxt(path)
		return deps, types.EcosystemPyPI, err
	default:
		return nil, "", fmt.Errorf("unsupported dependency file: %s (expected *.txt or *.json)", ext)
	}
}

func parseRequirementsTxt(path string) ([]Dep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var deps []Dep
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)

		// Skip empty lines, comments, and options.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Remove inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Remove environment markers (e.g. ; python_version >= "3.8").
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Parse name and version specifier.
		dep := Dep{}
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if idx := strings.Index(line, sep); idx >= 0 {
				dep.Name = strings.TrimSpace(line[:idx])
				if sep == "==" {
					dep.Version = strings.TrimSpace(line[idx+len(sep):])
				}
				break
			}
		}
		if dep.Name == "" {
			dep.Name = line
		}

		// Skip URLs and path references.
		if strings.Contains(dep.Name, "/") || strings.Contains(dep.Name, "\\") {
			continue
		}

		if dep.Name != "" {
			deps = append(deps, dep)
		}
	}

	return deps, nil
}

func parsePackageJSON(path string) ([]Dep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if jsonErr := json.Unmarshal(data, &pkg); jsonErr != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, jsonErr)
	}

	var deps []Dep

	for name, ver := range pkg.Dependencies {
		deps = append(deps, Dep{Name: name, Version: cleanNpmVersion(ver)})
	}
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, Dep{Name: name, Version: cleanNpmVersion(ver)})
	}

	return deps, nil
}

// cleanNpmVersion strips ^ ~ >= etc. to extract a pinned version if possible.
// Returns empty string for ranges, which lets npm resolve to latest matching.
func cleanNpmVersion(ver string) string {
	ver = strings.TrimSpace(ver)

	// Exact version: "1.2.3"
	if len(ver) > 0 && ver[0] >= '0' && ver[0] <= '9' {
		return ver
	}

	// Pinned with prefix: "^1.2.3" or "~1.2.3"
	if len(ver) > 1 && (ver[0] == '^' || ver[0] == '~') {
		return ver[1:]
	}

	// Range, *, latest, etc. — let npm resolve.
	return ""
}