package sandbox

import (
	"regexp"
	"strings"
	"testing"
)

func TestRandHex(t *testing.T) {
	for _, n := range []int{8, 16, 36, 40, 64} {
		h := randHex(n)
		if len(h) != n {
			t.Errorf("randHex(%d) returned length %d", n, len(h))
		}
		if matched, _ := regexp.MatchString("^[0-9a-f]+$", h); !matched {
			t.Errorf("randHex(%d) contains non-hex chars: %s", n, h)
		}
	}

	// Two calls should produce different values.
	a := randHex(32)
	b := randHex(32)
	if a == b {
		t.Errorf("randHex produced identical values: %s", a)
	}
}

func TestFakeAWSKeyID(t *testing.T) {
	key := fakeAWSKeyID()
	if !strings.HasPrefix(key, "AKIA") {
		t.Errorf("AWS key ID should start with AKIA, got %s", key)
	}
	if len(key) != 20 {
		t.Errorf("AWS key ID should be 20 chars, got %d: %s", len(key), key)
	}

	// Should be different each call.
	if fakeAWSKeyID() == fakeAWSKeyID() {
		t.Error("fakeAWSKeyID produced identical values")
	}
}

func TestFakeAWSSecret(t *testing.T) {
	secret := fakeAWSSecret()
	if len(secret) != 40 {
		t.Errorf("AWS secret should be 40 chars, got %d: %s", len(secret), secret)
	}
}

func TestFakeGitHubToken(t *testing.T) {
	token := fakeGitHubToken()
	if !strings.HasPrefix(token, "ghp_") {
		t.Errorf("GitHub token should start with ghp_, got %s", token)
	}
	if len(token) != 40 {
		t.Errorf("GitHub token should be 40 chars (ghp_ + 36), got %d: %s", len(token), token)
	}
}

func TestFakeNpmToken(t *testing.T) {
	token := fakeNpmToken()
	if !strings.HasPrefix(token, "npm_") {
		t.Errorf("npm token should start with npm_, got %s", token)
	}
	if len(token) != 40 {
		t.Errorf("npm token should be 40 chars (npm_ + 36), got %d: %s", len(token), token)
	}
}

func TestHoneypotEnvVars(t *testing.T) {
	vars := honeypotEnvVars()

	// Check CI signals are present.
	found := map[string]bool{}
	for _, v := range vars {
		parts := strings.SplitN(v, "=", 2)
		found[parts[0]] = true
	}

	required := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN"}
	for _, key := range required {
		if !found[key] {
			t.Errorf("missing required env var: %s", key)
		}
	}

	// Two calls should produce different token values.
	vars2 := honeypotEnvVars()
	for i, v := range vars {
		parts := strings.SplitN(v, "=", 2)
		if parts[0] == "CI" || parts[0] == "GITHUB_ACTIONS" || parts[0] == "GITLAB_CI" || parts[0] == "AWS_DEFAULT_REGION" {
			continue // static values
		}
		if v == vars2[i] {
			t.Errorf("expected different value for %s across calls", parts[0])
		}
	}
}

func TestSanitizeDockerArg(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"my-host", "my-host"},
		{"host.local", "host.local"},
		{"host name", "hostname"},
		{"--inject", "--inject"},
		{"$(evil)", "evil"},
		{"", "localhost"},
		{"日本語ホスト", "localhost"},
		{"valid_host-123.local", "valid_host-123.local"},
	}

	for _, tc := range cases {
		got := sanitizeDockerArg(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeDockerArg(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
