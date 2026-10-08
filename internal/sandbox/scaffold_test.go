package sandbox

import (
	"context"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

// TestScaffoldNames_RandomPerScan pins that no scaffold name is a constant:
// two scans share none of them, and every one has the expected shape.
func TestScaffoldNames_RandomPerScan(t *testing.T) {
	a, b := newScaffoldNames(), newScaffoldNames()
	pairs := map[string][2]string{
		"dir":           {a.dir, b.dir},
		"cacheDir":      {a.cacheDir, b.cacheDir},
		"auditPrefix":   {a.auditPrefix, b.auditPrefix},
		"requireHook":   {a.requireHook, b.requireHook},
		"resolver":      {a.resolver, b.resolver},
		"resolverReady": {a.resolverReady, b.resolverReady},
		"installScript": {a.installScript, b.installScript},
		"probe":         {a.probe("linux.py"), b.probe("linux.py")},
	}
	for name, p := range pairs {
		if p[0] == p[1] {
			t.Errorf("%s identical across scans: %q", name, p[0])
		}
	}

	if !regexp.MustCompile(`^/opt/[a-z][a-z0-9]{9}$`).MatchString(a.dir) {
		t.Errorf("dir = %q", a.dir)
	}
	if !regexp.MustCompile(`^/var/cache/[a-z][a-z0-9]{9}$`).MatchString(a.cacheDir) {
		t.Errorf("cacheDir = %q", a.cacheDir)
	}
	if !regexp.MustCompile(`^[A-Z]{12}:$`).MatchString(a.auditPrefix) {
		t.Errorf("auditPrefix = %q", a.auditPrefix)
	}
	for _, p := range []string{a.requireHook, a.resolver, a.resolverReady, a.probe("all_win32.js")} {
		if !strings.HasPrefix(p, a.dir+"/") {
			t.Errorf("%q is outside the scaffold dir %q", p, a.dir)
		}
	}
	if !strings.HasPrefix(a.installScript, a.cacheDir+"/") {
		t.Errorf("install script %q is outside the cache dir %q", a.installScript, a.cacheDir)
	}
}

// TestScaffoldNames_ProbeStable pins that a probe kind maps to one path for
// the whole scan — the script writer and the command builder must agree —
// while different kinds get different paths with their own extension.
func TestScaffoldNames_ProbeStable(t *testing.T) {
	n := newScaffoldNames()
	if n.probe("linux.py") != n.probe("linux.py") {
		t.Error("probe path changed within a scan")
	}
	if n.probe("linux.py") == n.probe("win32.py") {
		t.Error("two probe kinds share a path")
	}
	if !strings.HasSuffix(n.probe("all_darwin.js"), ".js") || !strings.HasSuffix(n.probe("darwin.py"), ".py") {
		t.Error("probe path lost its extension")
	}
}

func TestSandboxMarkers(t *testing.T) {
	sb := &Sandbox{}
	m := sb.Markers()
	if m.AuditPrefix != sb.scaffold().auditPrefix || m.ScaffoldDir != sb.scaffold().dir {
		t.Errorf("Markers() = %+v does not match the sandbox's scaffold", m)
	}
	if m != sb.Markers() {
		t.Error("Markers() changed between calls")
	}
}

func TestRenderHook(t *testing.T) {
	out, err := renderHook("p=__A__ q=__B__ again=__A__", map[string]string{"__A__": "x", "__B__": "y"})
	if err != nil || out != "p=x q=y again=x" {
		t.Errorf("renderHook = %q, %v", out, err)
	}
	// A placeholder the values do not cover is not caught here (renderHook
	// only knows the keys it was given), but one whose replacement
	// reintroduces it must fail rather than ship an unrendered hook.
	if _, err := renderHook("__A__", map[string]string{"__A__": "__A__"}); err == nil {
		t.Error("renderHook accepted output that still contains its placeholder")
	}
}

// fixedNamePattern matches the names kojuto used to stage under before
// they were randomised: anything a package could test for by string.
var fixedNamePattern = regexp.MustCompile(`(?i)kojuto|_kj_`)

// TestNoFixedNamesReachTheSandbox is the regression guard for the whole
// change: nothing kojuto hands the sandbox — mounts, environment, staged
// hooks, probe-script source — may carry a fixed kojuto-identifying name.
// Docker labels are exempt: they are not visible from inside a container.
func TestNoFixedNamesReachTheSandbox(t *testing.T) {
	withFakeExec(t)
	for _, eco := range []string{types.EcosystemPyPI, types.EcosystemNpm} {
		sb := newTestSandbox(t, eco)
		sb.networkName = "net"
		args, err := sb.containerArgs()
		if err != nil {
			t.Fatalf("containerArgs(%s): %v", eco, err)
		}
		for _, a := range args {
			if strings.HasPrefix(a, "--label=") || a == SandboxImage {
				continue
			}
			if fixedNamePattern.MatchString(a) {
				t.Errorf("%s: container arg %q carries a fixed name", eco, a)
			}
		}
	}

	n := newScaffoldNames()
	for name, tmpl := range map[string]string{
		"sitecustomize.py": sitecustomizeTemplate,
		"require hook":     requireHookTemplate,
		"resolver.py":      resolverScript,
	} {
		rendered, err := renderHook(tmpl, map[string]string{
			"__AUDIT_PREFIX__": n.auditPrefix,
			"__SCAN_PKGS__":    `["pkg"]`,
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if loc := fixedNamePattern.FindStringIndex(rendered); loc != nil {
			t.Errorf("%s as staged contains %q", name, rendered[loc[0]:loc[1]])
		}
	}
	for name, src := range map[string]string{
		"python probe": pythonImportProbeSource([]string{"pkg"}, n.auditPrefix),
		"node probe":   nodeImportProbeSource([]string{"pkg"}, n.auditPrefix),
	} {
		if loc := fixedNamePattern.FindStringIndex(src); loc != nil {
			t.Errorf("%s contains %q", name, src[loc[0]:loc[1]])
		}
		if !strings.Contains(src, n.auditPrefix+"import_attempt:") {
			t.Errorf("%s does not emit this scan's prefix", name)
		}
	}
}

// TestStageAuditHooks checks what lands in the sandbox: both hooks at
// their scan-specific paths, carrying the scan's prefix, with the audited
// package list baked into the Python hook as a list literal.
func TestStageAuditHooks(t *testing.T) {
	type call struct {
		args []string
		cmd  *exec.Cmd
	}
	var calls []call
	orig := execCommand
	execCommand = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		c := exec.CommandContext(ctx, "true")
		calls = append(calls, call{args, c})
		return c
	}
	t.Cleanup(func() { execCommand = orig })

	sb := &Sandbox{containerID: testContainerID, pkg: "evil-pkg"}
	sb.SetScanPkgs([]string{"evil-pkg", `quo"te`})
	if err := sb.stageAuditHooks(context.Background()); err != nil {
		t.Fatalf("stageAuditHooks: %v", err)
	}
	written := map[string]string{}
	for _, c := range calls {
		r, ok := c.cmd.Stdin.(*strings.Reader)
		if !ok {
			continue
		}
		_, _ = r.Seek(0, io.SeekStart)
		body, _ := io.ReadAll(r)
		path := c.args[len(c.args)-1] // sh -c "cat > '<path>'"
		path = strings.TrimSuffix(strings.TrimPrefix(path, "cat > '"), "'")
		written[path] = string(body)
	}

	n := sb.scaffold()
	site, ok := written[sitecustomizePath]
	if !ok {
		t.Fatalf("sitecustomize.py not staged; wrote %v", keys(written))
	}
	if !strings.Contains(site, `_P = "`+n.auditPrefix+`"`) {
		t.Error("sitecustomize.py does not carry the scan's prefix")
	}
	if !strings.Contains(site, `_SCAN_PKGS = ["evil-pkg","quo\"te"]`) {
		t.Errorf("sitecustomize.py package list not baked in as a list literal:\n%s", site)
	}
	node, ok := written[n.requireHook]
	if !ok {
		t.Fatalf("require hook not staged at %s; wrote %v", n.requireHook, keys(written))
	}
	if !strings.Contains(node, `const PREFIX = '`+n.auditPrefix+`'`) {
		t.Error("require hook does not carry the scan's prefix")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
