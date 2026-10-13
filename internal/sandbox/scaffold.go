package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RalianENG/kojuto/internal/types"
)

// scaffoldNames are the in-sandbox names of kojuto's own scaffolding — the
// directory holding its probe scripts, hooks and resolver, every file in
// it, the package-manager cache directory, the install script, and the
// prefix its audit hooks write on the wire. All of them are drawn fresh
// for every scan.
//
// kojuto is open source, so any fixed name is one a package can test for:
// `if os.path.exists("/opt/kojuto"): sys.exit()` costs an attacker one
// line and turned every scan of that package into a clean verdict. With
// per-scan names there is no constant to test for — the scaffolding has
// to be recognized by its shape, which is a much higher bar, and the
// attempt shows up in the trace like any other environment probing.
//
// The parser learns the names it needs through types.ScanMarkers.
type scaffoldNames struct {
	// dir holds kojuto's OWN scripts — the OS-simulation import probes,
	// the Node audit hook and the synthetic DNS resolver. containerArgs
	// mounts it as a dedicated tmpfs with mode=0755, so it stays
	// root-owned: the scanned package runs as the unprivileged dev user
	// and can read and execute these scripts but cannot create files
	// here.
	//
	// The location is load-bearing. The probes used to live in /tmp/,
	// which sitecustomize.py lists in _USER_PREFIXES because malware
	// drops payloads there, so kojuto's own probes counted as user code:
	// a 100-package PyPI measurement found 30,788 of 46,031
	// dynamic_code_execution events (67%) were kojuto's own. Staging
	// outside every user prefix fixes that at the source, and because the
	// directory is root-owned, the parser can exempt everything in it
	// (types.ScanMarkers.ScaffoldDir) without a package being able to
	// buy the same exemption by planting a file there.
	dir           string
	cacheDir      string // tmpfs for npm/pip caches and the install script
	auditPrefix   string // wire prefix of audit-hook lines
	requireHook   string // Node audit hook, loaded via NODE_OPTIONS
	resolver      string // synthetic DNS resolver script
	resolverReady string // marker the resolver writes once bound
	installScript string // install command, staged for `sh <path>`
	buildDeps     string // wheels of a local sdist's build requirements
	probes        map[string]string
}

// scaffoldTokenChars is the alphabet for path components: lowercase and
// digits, the shape of the generated names package managers and tooling
// already leave all over a filesystem.
const scaffoldTokenChars = "abcdefghijklmnopqrstuvwxyz0123456789"

// scaffoldToken returns a random path component of n characters that
// starts with a letter.
func scaffoldToken(n int) string {
	letter := randFrom(scaffoldTokenChars[:26], 1)
	return letter + randFrom(scaffoldTokenChars, n-1)
}

// auditPrefixChars is the alphabet for the audit wire prefix: uppercase
// only, so it cannot collide with the lowercase-led output that pip, npm
// and Python tracebacks write to the same stream.
const auditPrefixChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func newScaffoldNames() *scaffoldNames {
	dir := "/opt/" + scaffoldToken(10)
	cacheDir := "/var/cache/" + scaffoldToken(10)
	return &scaffoldNames{
		dir:           dir,
		cacheDir:      cacheDir,
		auditPrefix:   randFrom(auditPrefixChars, 12) + ":",
		requireHook:   dir + "/" + scaffoldToken(8) + ".js",
		resolver:      dir + "/" + scaffoldToken(8) + ".py",
		resolverReady: dir + "/." + scaffoldToken(8),
		installScript: cacheDir + "/" + scaffoldToken(8) + ".sh",
		buildDeps:     cacheDir + "/" + scaffoldToken(8),
		probes:        make(map[string]string),
	}
}

// probe returns the staged path of the probe script for kind (e.g.
// "linux.py", "all_win32.js"). The name is random but stable for the
// scan, so the writer and the command builder agree on it.
func (n *scaffoldNames) probe(kind string) string {
	if p, ok := n.probes[kind]; ok {
		return p
	}
	ext := kind[strings.LastIndex(kind, "."):]
	p := n.dir + "/" + scaffoldToken(8) + ext
	n.probes[kind] = p
	return p
}

// markers returns what the strace parser needs to recognize kojuto's own
// scaffolding in this scan's trace.
func (n *scaffoldNames) markers() types.ScanMarkers {
	return types.ScanMarkers{
		AuditPrefix: n.auditPrefix,
		ScaffoldDir: n.dir,
	}
}

// scaffold returns the sandbox's scaffold names, drawing them on first use.
func (s *Sandbox) scaffold() *scaffoldNames {
	if s.names == nil {
		s.names = newScaffoldNames()
	}
	return s.names
}

// sitecustomizePath is where the interpreter auto-loads sitecustomize.py.
var sitecustomizePath = "/usr/local/lib/python" + SandboxPythonVersion + "/site-packages/sitecustomize.py"

// renderHook substitutes this scan's values into a hook template and
// fails if a placeholder survives: a hook writing a literal placeholder
// as its prefix would emit lines the parser never recognizes, silently
// disabling dynamic-code detection.
func renderHook(tmpl string, values map[string]string) (string, error) {
	out := tmpl
	for k, v := range values {
		out = strings.ReplaceAll(out, k, v)
	}
	for k := range values {
		if strings.Contains(out, k) {
			return "", fmt.Errorf("hook placeholder %s left unrendered", k)
		}
	}
	return out, nil
}

// auditedPackages returns the packages the Python hook treats as user
// code: the batch list when set, otherwise the single scanned package.
func (s *Sandbox) auditedPackages() []string {
	if len(s.scanPkgs) > 0 {
		return s.scanPkgs
	}
	if s.pkg != "" {
		return []string{s.pkg}
	}
	return []string{}
}

// stageAuditHooks writes this scan's audit hooks into the sandbox:
// sitecustomize.py into site-packages, where the interpreter auto-loads
// it, and the Node require hook into the scaffold directory, where
// NODE_OPTIONS points. Both carry the scan's random wire prefix; the
// Python hook also has the audited package list baked in, which used to
// travel in a fixed-name environment variable.
func (s *Sandbox) stageAuditHooks(ctx context.Context) error {
	n := s.scaffold()
	pkgs, err := json.Marshal(s.auditedPackages()) // a JSON string list is a valid Python list literal
	if err != nil {
		return fmt.Errorf("encoding audited packages: %w", err)
	}
	site, err := renderHook(sitecustomizeTemplate, map[string]string{
		"__AUDIT_PREFIX__": n.auditPrefix,
		"__SCAN_PKGS__":    string(pkgs),
	})
	if err != nil {
		return err
	}
	node, err := renderHook(requireHookTemplate, map[string]string{
		"__AUDIT_PREFIX__": n.auditPrefix,
	})
	if err != nil {
		return err
	}
	if err := s.dockerWriteFile(ctx, sitecustomizePath, site); err != nil {
		return fmt.Errorf("staging python audit hook: %w", err)
	}
	if err := s.dockerWriteFile(ctx, n.requireHook, node); err != nil {
		return fmt.Errorf("staging node audit hook: %w", err)
	}
	return nil
}

// Markers returns this scan's scaffold markers for the strace parser.
func (s *Sandbox) Markers() types.ScanMarkers {
	return s.scaffold().markers()
}

// wheelFileRe matches the wheel filenames StageBuildDeps accepts. pip
// download names them from index metadata, but they are still copied into
// a shell-visible path, so anything outside the wheel filename alphabet is
// skipped rather than quoted.
var wheelFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*\.whl$`)

// StageBuildDeps copies the wheels of a local sdist's build requirements
// (fetched by downloader.DownloadBuildDeps) into the sandbox, where the
// install script installs them before the sdist. They go to the per-scan
// cache tmpfs rather than the package mount: when the user scans a
// directory, that mount is the user's own directory.
func (s *Sandbox) StageBuildDeps(ctx context.Context, wheels []string) error {
	var staged int
	dir := s.scaffold().buildDeps
	for _, w := range wheels {
		name := filepath.Base(w)
		if !wheelFileRe.MatchString(name) {
			continue
		}
		data, err := os.ReadFile(w)
		if err != nil {
			return fmt.Errorf("reading build dependency %s: %w", name, err)
		}
		if staged == 0 {
			if err := s.dockerExecRoot(ctx, "mkdir", "-p", dir); err != nil {
				return err
			}
		}
		if err := s.dockerWriteFile(ctx, dir+"/"+name, string(data)); err != nil {
			return fmt.Errorf("staging build dependency %s: %w", name, err)
		}
		staged++
	}
	s.buildDepsStaged = staged > 0
	return nil
}
