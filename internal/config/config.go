// Package config handles kojuto's runtime configuration, including
// user-customizable sensitive path patterns.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds user-customizable settings loaded from kojuto.yml.
type Config struct {
	SensitivePaths SensitivePathConfig `yaml:"sensitive_paths"`
}

// SensitivePathConfig controls which file paths are flagged as suspicious
// when accessed via openat during install or import.
type SensitivePathConfig struct {
	// Extra patterns to add on top of the built-in defaults.
	Include []string `yaml:"include,omitempty"`
	// Patterns to remove from the defaults (e.g. if causing false positives).
	Exclude []string `yaml:"exclude,omitempty"`
}

// DefaultSensitivePaths returns the built-in set of sensitive path patterns.
// These cover credentials, secrets, browser data, cloud CLI configs,
// shell startup files, and other high-value targets observed in real
// supply chain attacks (Datadog malicious-software-packages-dataset).
func DefaultSensitivePaths() []string {
	return []string{
		// --- SSH / GPG ---
		"/.ssh/",
		"/.gnupg/",

		// --- Cloud credentials ---
		"/.aws/",
		"/.azure/",
		"/.config/gcloud/",
		"/.kube/config",
		"/.oci/config",
		"/.aliyun/config",

		// --- System secrets ---
		"/etc/shadow",
		// /etc/passwd is intentionally excluded: many standard tools
		// (getpwnam, uid lookups) read it during normal operation.
		"/proc/self/environ",
		// /proc/self/maps and /proc/self/cgroup were previously excluded
		// because glibc, V8/Node startup, Python's runpy, and container-
		// aware libraries read these on every process launch, generating
		// multiple false-positive evasion events for any node-based or
		// otherwise heavy package. Re-added now that Analyze()
		// deduplicates CategoryEvasion events by FilePath — N reads of
		// the same path collapse to one forensic breadcrumb, so the
		// verdict rule (2+ MEDIUM events) measures DISTINCT sandbox
		// probes, not raw read repetitions. A package that reads only
		// /proc/self/maps still stays clean (1 evasion event); a package
		// that reads maps + cgroup + status is flagged as an evasion
		// cluster (3 distinct events).
		"/proc/self/maps",      // libfaketime / LD_PRELOAD fingerprint
		"/proc/self/cgroup",    // Docker / k8s container detection
		"/proc/self/status",    // TracerPid detection (strace parent process)
		"/proc/self/mountinfo", // overlay filesystem detection
		"/sys/class/net",       // network namespace detection (no trailing slash)

		// --- Git / VCS ---
		"/.netrc",
		"/.git-credentials",

		// --- Container / CI ---
		"/.docker/config.json",
		"/.config/gh/",
		// .npmrc and .pypirc are intentionally excluded from defaults:
		// npm and pip read these during normal operation, causing false
		// positives on every scan. Add via include if needed.

		// --- Environment / dotenv ---
		"/.env",
		"/.env.local",
		"/.env.production",

		// --- Browser data ---
		"/.config/google-chrome/",
		"/.config/chromium/",
		"/.mozilla/firefox/",
		"/.config/BraveSoftware/",
		"/.config/opera/",
		"/.config/vivaldi/",
		"/.config/microsoft-edge/",
		"/Library/Application Support/Google/Chrome/",
		"/Library/Application Support/BraveSoftware/",
		"/Library/Application Support/Microsoft Edge/",

		// --- Browser extension / wallet DB (MetaMask, Phantom, etc.) ---
		"/Local Storage/leveldb/",
		"/IndexedDB/",

		// --- Shell startup (persistence targets) ---
		"/.bashrc",
		"/.bash_profile",
		"/.zshrc",
		"/.profile",
		"/.bash_history",
		"/.zsh_history",

		// --- Desktop keyrings ---
		"/.local/share/keyrings/",
		"/Library/Keychains/",

		// --- Cryptocurrency wallets ---
		// Primary targets for supply chain attack info-stealers.
		"/.bitcoin/",
		"/.ethereum/",
		"/.solana/",
		"/.config/solana/",
		"/.monero/",
		"/.electrum/",
		"/.exodus/",
		"/.atomic/",
		"/.tronlink/",
		"/.config/Ledger Live/",
		"/Library/Application Support/Exodus/",
		"/Library/Application Support/atomic/",
		"/Library/Application Support/Phantom/",
		"/.local/share/io.parity.ethereum/",

		// --- Application tokens ---
		"/.config/slack/",
		"/.config/discord/",
		"/.terraform.d/credentials.tfrc.json",
		"/.vault-token",
		"/.config/heroku/",
		"/.config/netlify/",
		"/.config/vercel/",
	}
}

// Load reads a config file from path. Returns default config if file doesn't exist.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // no config file = all defaults
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	return cfg, nil
}

// MergeSensitivePaths combines default paths with user config (include/exclude).
func MergeSensitivePaths(cfg *Config) []string {
	defaults := DefaultSensitivePaths()

	// Build exclusion set.
	exclude := make(map[string]bool, len(cfg.SensitivePaths.Exclude))
	for _, p := range cfg.SensitivePaths.Exclude {
		exclude[p] = true
	}

	// Filter defaults.
	var result []string
	for _, p := range defaults {
		if !exclude[p] {
			result = append(result, p)
		}
	}

	// Append user inclusions.
	result = append(result, cfg.SensitivePaths.Include...)

	return result
}
