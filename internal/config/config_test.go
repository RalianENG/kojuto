package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultSensitivePaths(t *testing.T) {
	paths := DefaultSensitivePaths()
	if len(paths) < 20 {
		t.Errorf("expected at least 20 default paths, got %d", len(paths))
	}

	// Verify critical paths are present.
	required := []string{
		// Original paths
		"/.ssh/", "/.aws/", "/.env", "/.kube/config", "/.config/google-chrome/", "/.bashrc",
		// Crypto wallets
		"/.bitcoin/", "/.ethereum/", "/.solana/",
		// Browser extensions
		"/Local Storage/leveldb/", "/IndexedDB/",
		// Sandbox detection paths (intentionally narrow — see excluded list below)
		"/proc/self/status", "/proc/self/mountinfo", "/sys/class/net",
	}
	for _, want := range required {
		found := false
		for _, p := range paths {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing required path: %s", want)
		}
	}

	// /proc/self/maps and /proc/self/cgroup are deliberately NOT in the
	// defaults: V8/Node startup, glibc and Python's runpy read these on
	// every process launch, so flagging them by default produced
	// per-scan evasion noise that swamped real signal. Pin the absence
	// so future "let's add these back to be safe" changes have to
	// confront this test.
	excluded := []string{"/proc/self/maps", "/proc/self/cgroup"}
	for _, banned := range excluded {
		for _, p := range paths {
			if p == banned {
				t.Errorf("default path %q must stay out of defaults — too noisy under interpreter startup; opt in via config include if needed",
					banned)
			}
		}
	}
}

func TestLoad_NoFile(t *testing.T) {
	cfg, err := Load("/nonexistent/kojuto.yml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	// No include/exclude → empty.
	if len(cfg.SensitivePaths.Include) != 0 {
		t.Errorf("expected 0 includes, got %d", len(cfg.SensitivePaths.Include))
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kojuto.yml")
	content := `
sensitive_paths:
  include:
    - "/.custom/secret"
  exclude:
    - "/.npmrc"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if len(cfg.SensitivePaths.Include) != 1 {
		t.Errorf("expected 1 include, got %d", len(cfg.SensitivePaths.Include))
	}
	if cfg.SensitivePaths.Include[0] != "/.custom/secret" {
		t.Errorf("include[0] = %q, want %q", cfg.SensitivePaths.Include[0], "/.custom/secret")
	}
	if len(cfg.SensitivePaths.Exclude) != 1 {
		t.Errorf("expected 1 exclude, got %d", len(cfg.SensitivePaths.Exclude))
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kojuto.yml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestMergeSensitivePaths_Default(t *testing.T) {
	cfg := &Config{}
	paths := MergeSensitivePaths(cfg)

	// Should equal defaults.
	defaults := DefaultSensitivePaths()
	if len(paths) != len(defaults) {
		t.Errorf("expected %d paths, got %d", len(defaults), len(paths))
	}
}

func TestMergeSensitivePaths_Include(t *testing.T) {
	cfg := &Config{
		SensitivePaths: SensitivePathConfig{
			Include: []string{"/.custom/path"},
		},
	}
	paths := MergeSensitivePaths(cfg)

	found := false
	for _, p := range paths {
		if p == "/.custom/path" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom path in merged result")
	}
	if len(paths) != len(DefaultSensitivePaths())+1 {
		t.Errorf("expected defaults+1, got %d", len(paths))
	}
}

func TestMergeSensitivePaths_Exclude(t *testing.T) {
	cfg := &Config{
		SensitivePaths: SensitivePathConfig{
			Exclude: []string{"/.ssh/"},
		},
	}
	paths := MergeSensitivePaths(cfg)

	for _, p := range paths {
		if p == "/.ssh/" {
			t.Error("/.ssh/ should have been excluded")
		}
	}
	if len(paths) != len(DefaultSensitivePaths())-1 {
		t.Errorf("expected defaults-1, got %d", len(paths))
	}
}
