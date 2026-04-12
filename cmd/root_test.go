package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestDetectPackageName(t *testing.T) {
	cases := []struct {
		filename string
		want     string
	}{
		{"malware-1.0.0-py3-none-any.whl", "malware"},
		{"evil-pkg-2.0.0.tgz", "evil-pkg"},
		{"requests-2.31.0.tar.gz", "requests"},
		{"my-package-0.1.0.zip", "my-package"},
		{"simple-1.0.whl", "simple"},
		{"noversion.whl", "noversion"},
		{"1.0.0.tgz", "1.0.0"}, // edge: starts with version-like string
	}

	for _, tc := range cases {
		t.Run(tc.filename, func(t *testing.T) {
			got := detectPackageName(tc.filename)
			if got != tc.want {
				t.Errorf("detectPackageName(%q) = %q, want %q", tc.filename, got, tc.want)
			}
		})
	}
}

func TestDetectPackageFromDir(t *testing.T) {
	// Create temp dir with a .whl file.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fake-pkg-1.0.0-py3-none-any.whl"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	got := detectPackageFromDir(dir)
	if got != "fake-pkg" {
		t.Errorf("detectPackageFromDir = %q, want %q", got, "fake-pkg")
	}

	// Dir with no recognizable files → falls back to dir basename.
	emptyDir := t.TempDir()
	got2 := detectPackageFromDir(emptyDir)
	if got2 != filepath.Base(emptyDir) {
		t.Errorf("detectPackageFromDir(empty) = %q, want %q", got2, filepath.Base(emptyDir))
	}
}

func TestVerdictError(t *testing.T) {
	err := &VerdictError{Verdict: "suspicious", ExitCode: 2}

	if err.Error() != "verdict: suspicious" {
		t.Errorf("VerdictError.Error() = %q, want %q", err.Error(), "verdict: suspicious")
	}

	if err.ExitCode != 2 {
		t.Errorf("VerdictError.ExitCode = %d, want 2", err.ExitCode)
	}
}

func TestWritePinnedPyPI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements-locked.txt")

	deps := []pinnedDep{
		{Name: "requests", Version: "2.31.0"},
		{Name: "flask", Version: "3.0.0"},
		{Name: "noversion", Version: ""},
	}

	if err := writePinnedPyPI(path, deps); err != nil {
		t.Fatalf("writePinnedPyPI failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	content := string(data)

	if !strings.Contains(content, "requests==2.31.0") {
		t.Error("expected requests==2.31.0 in output")
	}
	if !strings.Contains(content, "flask==3.0.0") {
		t.Error("expected flask==3.0.0 in output")
	}
	if strings.Contains(content, "noversion==") {
		t.Error("noversion should not have == when version is empty")
	}
	if !strings.Contains(content, "noversion\n") {
		t.Error("noversion should appear without version pinning")
	}
	if !strings.Contains(content, "# Pinned by kojuto") {
		t.Error("expected header comment in output")
	}
}

func TestWritePinnedNpm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-pinned.json")

	deps := []pinnedDep{
		{Name: "lodash", Version: "4.17.21"},
		{Name: "express", Version: "4.18.2"},
		{Name: "noversion", Version: ""},
	}

	if err := writePinnedNpm(path, deps); err != nil {
		t.Fatalf("writePinnedNpm failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed["name"] != "pinned-by-kojuto" {
		t.Errorf("expected name pinned-by-kojuto, got %v", parsed["name"])
	}
	if parsed["private"] != true {
		t.Errorf("expected private=true, got %v", parsed["private"])
	}

	depsMap, ok := parsed["dependencies"].(map[string]interface{})
	if !ok {
		t.Fatal("dependencies is not an object")
	}

	if depsMap["lodash"] != "4.17.21" {
		t.Errorf("expected lodash=4.17.21, got %v", depsMap["lodash"])
	}
	if depsMap["express"] != "4.18.2" {
		t.Errorf("expected express=4.18.2, got %v", depsMap["express"])
	}
	if depsMap["noversion"] != "*" {
		t.Errorf("expected noversion=*, got %v", depsMap["noversion"])
	}

	// Verify trailing newline.
	if data[len(data)-1] != '\n' {
		t.Error("expected trailing newline in output")
	}
}

func TestWritePinnedFile_UnsupportedEcosystem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	err := writePinnedFile(path, nil, "cargo")
	if err == nil {
		t.Fatal("expected error for unsupported ecosystem")
	}
	if !strings.Contains(err.Error(), "unsupported ecosystem") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSelectProbeMethod_ExplicitMethod(t *testing.T) {
	// When not "auto", selectProbeMethod returns the value as-is.
	original := flagProbeMethod
	defer func() { flagProbeMethod = original }()

	for _, method := range []string{methodEBPF, methodStrace, methodStraceContainer} {
		flagProbeMethod = method
		got := selectProbeMethod()
		if got != method {
			t.Errorf("selectProbeMethod() = %q, want %q", got, method)
		}
	}
}

func TestSelectProbeMethod_Auto(t *testing.T) {
	original := flagProbeMethod
	defer func() { flagProbeMethod = original }()

	flagProbeMethod = methodAuto
	got := selectProbeMethod()
	// Auto should always resolve to strace-container.
	if got != methodStraceContainer {
		t.Errorf("selectProbeMethod(auto) = %q, want %q", got, methodStraceContainer)
	}
}

func TestConstants(t *testing.T) {
	if methodAuto != "auto" {
		t.Errorf("methodAuto = %q, want 'auto'", methodAuto)
	}
	if methodEBPF != "ebpf" {
		t.Errorf("methodEBPF = %q, want 'ebpf'", methodEBPF)
	}
	if methodStrace != "strace" {
		t.Errorf("methodStrace = %q, want 'strace'", methodStrace)
	}
	if methodStraceContainer != "strace-container" {
		t.Errorf("methodStraceContainer = %q, want 'strace-container'", methodStraceContainer)
	}
	if exitCodeSuspicious != 2 {
		t.Errorf("exitCodeSuspicious = %d, want 2", exitCodeSuspicious)
	}
}

func TestRunScan_NoArgs(t *testing.T) {
	// No args, no -f, no --local → error.
	original := flagFile
	originalLocal := flagLocal
	defer func() {
		flagFile = original
		flagLocal = originalLocal
	}()

	flagFile = ""
	flagLocal = ""
	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(err.Error(), "no package specified") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFindDockerfile(t *testing.T) {
	// findDockerfile checks relative paths; just verify it returns something.
	result := findDockerfile()
	if result == "" {
		t.Error("findDockerfile returned empty string")
	}
}

func TestScanCmdFlags(t *testing.T) {
	// Verify that scan command has all expected flags registered.
	expectedFlags := []string{
		"version", "output", "ecosystem", "file",
		"pin", "local", "runtime", "probe-method", "timeout",
	}

	for _, name := range expectedFlags {
		f := scanCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("expected flag %q not found on scan command", name)
		}
	}
}

func TestScanCmdDefaults(t *testing.T) {
	if f := scanCmd.Flags().Lookup("ecosystem"); f != nil {
		if f.DefValue != types.EcosystemPyPI {
			t.Errorf("ecosystem default = %q, want %q", f.DefValue, types.EcosystemPyPI)
		}
	}

	if f := scanCmd.Flags().Lookup("probe-method"); f != nil {
		if f.DefValue != methodAuto {
			t.Errorf("probe-method default = %q, want %q", f.DefValue, methodAuto)
		}
	}

	if f := scanCmd.Flags().Lookup("timeout"); f != nil {
		if f.DefValue != "5m0s" {
			t.Errorf("timeout default = %q, want %q", f.DefValue, "5m0s")
		}
	}
}

func TestVersionCmd(t *testing.T) {
	// Verify the version command is registered.
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("version command not registered")
	}
}

func TestPrintVerdict(_ *testing.T) {
	// Just ensure printVerdict doesn't panic for each verdict type.
	// Output goes to stderr which we don't capture, but no panic = pass.
	printVerdict(types.VerdictClean, 0, 0, 0)
	printVerdict(types.VerdictSuspicious, 3, 0, 0)
	printVerdict(types.VerdictInconclusive, 0, 5, 0)
	printVerdict(types.VerdictInconclusive, 0, 0, 12)
	printVerdict(types.VerdictInconclusive, 0, 5, 12)
}

func TestOpenOutput_Stdout(t *testing.T) {
	original := flagOutput
	defer func() { flagOutput = original }()

	flagOutput = ""
	f, err := openOutput()
	if err != nil {
		t.Fatalf("openOutput() error: %v", err)
	}
	if f != os.Stdout {
		t.Error("expected os.Stdout when flagOutput is empty")
	}
}

func TestOpenOutput_File(t *testing.T) {
	original := flagOutput
	defer func() { flagOutput = original }()

	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "test-output.json")

	f, err := openOutput()
	if err != nil {
		t.Fatalf("openOutput() error: %v", err)
	}
	defer f.Close()

	if f == os.Stdout {
		t.Error("expected a file, not os.Stdout")
	}

	// Verify the file was actually created.
	if _, err := os.Stat(flagOutput); err != nil {
		t.Errorf("output file was not created: %v", err)
	}
}

func TestOutputReport_Clean(t *testing.T) {
	origOutput := flagOutput
	origVersion := flagVersion
	origEcosystem := flagEcosystem
	defer func() {
		flagOutput = origOutput
		flagVersion = origVersion
		flagEcosystem = origEcosystem
	}()

	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "report.json")
	flagVersion = testVersion
	flagEcosystem = types.EcosystemPyPI

	result := &scanResult{
		method: "strace-container",
		events: nil, // no events → clean
	}

	err := outputReport("test-pkg", result)
	if err != nil {
		t.Fatalf("outputReport returned error for clean scan: %v", err)
	}

	// Verify report file was written.
	data, readErr := os.ReadFile(flagOutput)
	if readErr != nil {
		t.Fatalf("reading report: %v", readErr)
	}
	if len(data) == 0 {
		t.Error("report file is empty")
	}
	if !strings.Contains(string(data), `"verdict": "clean"`) {
		t.Errorf("expected clean verdict in report, got: %s", string(data))
	}
}

func TestOutputReport_Suspicious(t *testing.T) {
	origOutput := flagOutput
	origVersion := flagVersion
	origEcosystem := flagEcosystem
	defer func() {
		flagOutput = origOutput
		flagVersion = origVersion
		flagEcosystem = origEcosystem
	}()

	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "report.json")
	flagVersion = testVersion
	flagEcosystem = types.EcosystemPyPI

	// A listen event is always suspicious per the analyzer.
	result := &scanResult{
		method: "strace-container",
		events: []types.SyscallEvent{
			{Syscall: types.EventListen, PID: 1234},
		},
	}

	err := outputReport("evil-pkg", result)
	if err == nil {
		t.Fatal("expected VerdictError for suspicious scan")
	}

	var ve *VerdictError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerdictError, got %T: %v", err, err)
	}
	if ve.Verdict != types.VerdictSuspicious {
		t.Errorf("verdict = %q, want %q", ve.Verdict, types.VerdictSuspicious)
	}
	if ve.ExitCode != exitCodeSuspicious {
		t.Errorf("exit code = %d, want %d", ve.ExitCode, exitCodeSuspicious)
	}
}

func TestOutputReport_Inconclusive(t *testing.T) {
	origOutput := flagOutput
	origVersion := flagVersion
	origEcosystem := flagEcosystem
	defer func() {
		flagOutput = origOutput
		flagVersion = origVersion
		flagEcosystem = origEcosystem
	}()

	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "report.json")
	flagVersion = testVersion
	flagEcosystem = types.EcosystemPyPI

	result := &scanResult{
		method:      "strace-container",
		events:      nil,
		lostSamples: 10,
	}

	err := outputReport("test-pkg", result)
	if err == nil {
		t.Fatal("expected VerdictError for inconclusive scan")
	}

	var ve *VerdictError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerdictError, got %T: %v", err, err)
	}
	if ve.Verdict != types.VerdictInconclusive {
		t.Errorf("verdict = %q, want %q", ve.Verdict, types.VerdictInconclusive)
	}
}

// Non-zero `dropped` (userspace channel overflow) must also flip the
// verdict to inconclusive — same correctness contract as lostSamples,
// but through the userspace path instead of the kernel perf buffer.
func TestOutputReport_InconclusiveOnDropped(t *testing.T) {
	origOutput := flagOutput
	origVersion := flagVersion
	origEcosystem := flagEcosystem
	defer func() {
		flagOutput = origOutput
		flagVersion = origVersion
		flagEcosystem = origEcosystem
	}()

	dir := t.TempDir()
	flagOutput = filepath.Join(dir, "report.json")
	flagVersion = testVersion
	flagEcosystem = types.EcosystemPyPI

	result := &scanResult{
		method:  "ebpf",
		events:  nil,
		dropped: 17,
	}

	err := outputReport("test-pkg", result)
	if err == nil {
		t.Fatal("expected VerdictError when dropped > 0")
	}

	var ve *VerdictError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerdictError, got %T: %v", err, err)
	}
	if ve.Verdict != types.VerdictInconclusive {
		t.Errorf("verdict = %q, want %q", ve.Verdict, types.VerdictInconclusive)
	}

	// Report JSON should carry the dropped count through.
	raw, readErr := os.ReadFile(flagOutput)
	if readErr != nil {
		t.Fatalf("reading report: %v", readErr)
	}
	var r types.Report
	if jsonErr := json.Unmarshal(raw, &r); jsonErr != nil {
		t.Fatalf("unmarshal report: %v", jsonErr)
	}
	if r.Dropped != 17 {
		t.Errorf("report.dropped = %d, want 17", r.Dropped)
	}
	if r.Verdict != types.VerdictInconclusive {
		t.Errorf("report.verdict = %q, want inconclusive", r.Verdict)
	}
}

func TestGetPIDNSInode_InvalidPID(t *testing.T) {
	// PID 0 or a non-existent PID should always return an error on any platform.
	// On Linux: /proc/1234/ns/pid won't exist for a fake PID.
	// On non-Linux: the function returns "requires Linux" error.
	_, err := getPIDNSInode(1234)
	if err == nil {
		t.Fatal("expected error for non-existent PID")
	}
}

func TestSetVersionInfo(t *testing.T) {
	SetVersionInfo("1.2.3", "abc", "2026-01-01")
	if appVersion != "1.2.3" {
		t.Errorf("appVersion = %q, want 1.2.3", appVersion)
	}
	if appCommit != "abc" {
		t.Errorf("appCommit = %q, want abc", appCommit)
	}
	if appDate != "2026-01-01" {
		t.Errorf("appDate = %q, want 2026-01-01", appDate)
	}
	// Reset
	SetVersionInfo("dev", "none", "unknown")
}

func TestDownloadHint(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"pip not found", errors.New("executable file not found"), "pip is not installed"},
		{"npm not found", errors.New("executable file not found"), "pip is not installed"},
		{"no matching", errors.New("No matching distribution found"), "Check the name"},
		{"404", errors.New("404 not found"), "package not found"},
		{"other", errors.New("some random error"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := downloadHint(types.EcosystemPyPI, tc.err)
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("downloadHint = %q, want containing %q", got, tc.want)
			}
			if tc.want == "" && got != "" {
				t.Errorf("downloadHint = %q, want empty", got)
			}
		})
	}

	// npm ecosystem
	got := downloadHint(types.EcosystemNpm, errors.New("executable file not found"))
	if !strings.Contains(got, "npm is not installed") {
		t.Errorf("npm hint = %q, want containing 'npm is not installed'", got)
	}
}

func TestDockerHint(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"not found", errors.New("executable file not found"), "Docker is not installed"},
		{"daemon", errors.New("Cannot connect to the Docker daemon"), "Docker daemon is not running"},
		{"permission", errors.New("permission denied docker.sock"), "permission denied"},
		{"other", errors.New("something else"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dockerHint(tc.err)
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("dockerHint = %q, want containing %q", got, tc.want)
			}
			if tc.want == "" && got != "" {
				t.Errorf("dockerHint = %q, want empty", got)
			}
		})
	}
}

func TestPreRunLoadConfig_Default(t *testing.T) {
	// No config file, no strict — should use defaults without error.
	origConfig := flagConfig
	origStrict := flagStrict
	defer func() { flagConfig = origConfig; flagStrict = origStrict }()

	flagConfig = "nonexistent-config-file.yml"
	flagStrict = false

	if err := preRunLoadConfig(nil, nil); err != nil {
		t.Fatalf("preRunLoadConfig failed: %v", err)
	}
}

func TestPreRunLoadConfig_StrictIgnoresExclude(t *testing.T) {
	origConfig := flagConfig
	origStrict := flagStrict
	defer func() { flagConfig = origConfig; flagStrict = origStrict }()

	// Write a temp config with excludes.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "kojuto.yml")
	os.WriteFile(cfgPath, []byte("sensitive_paths:\n  exclude:\n    - \"/.ssh/\"\n"), 0644)

	flagConfig = cfgPath
	flagStrict = true

	if err := preRunLoadConfig(nil, nil); err != nil {
		t.Fatalf("preRunLoadConfig with --strict failed: %v", err)
	}
}

func TestPreRunLoadConfig_InvalidConfig(t *testing.T) {
	origConfig := flagConfig
	origStrict := flagStrict
	defer func() { flagConfig = origConfig; flagStrict = origStrict }()

	// Write invalid YAML.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad.yml")
	os.WriteFile(cfgPath, []byte("{{invalid yaml"), 0644)

	flagConfig = cfgPath
	flagStrict = false

	if err := preRunLoadConfig(nil, nil); err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestRunProbeAndInstall_UnknownMethod(t *testing.T) {
	_, err := runProbeAndInstall(context.TODO(), nil, "test-pkg", "unknown-method")
	if err == nil {
		t.Fatal("expected error for unknown probe method")
	}
	if !strings.Contains(err.Error(), "unknown probe method") {
		t.Errorf("unexpected error: %v", err)
	}
}
