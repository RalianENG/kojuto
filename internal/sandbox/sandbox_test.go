package sandbox

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"hash/crc32"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestBuildDepsManifestIsHashPinned guards the supply chain story for
// the sandbox image. The Dockerfile installs setuptools + wheel from
// build-deps.txt with --require-hashes — without those two packages,
// `pip install --no-build-isolation <sdist>` fails at the build_meta
// backend stage and PyPI .tar.gz scans report empty events. The hash
// pin keeps the trust boundary the same as the digest-pinned base
// image: any update has to consciously refresh both version + sha256.
func TestBuildDepsManifestIsHashPinned(t *testing.T) {
	data, err := os.ReadFile("build-deps.txt")
	if err != nil {
		t.Fatalf("build-deps.txt missing — Dockerfile.sandbox depends on it: %v", err)
	}
	body := string(data)

	for _, pkg := range []string{"setuptools==", "wheel=="} {
		if !strings.Contains(body, pkg) {
			t.Errorf("build-deps.txt must pin %s — without it the sandbox image cannot build sdists", pkg)
		}
	}

	// At least two --hash entries (one per package). Catches accidental
	// `pip install setuptools wheel` style edits that drop hash pinning.
	if got := strings.Count(body, "--hash=sha256:"); got < 2 {
		t.Errorf("build-deps.txt must include sha256 hashes for every pinned package, found %d", got)
	}
}

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
	// AKIA + 16 base32 characters (A-Z, 2-7): anything else is a key no
	// AWS account was ever issued, and trivially recognisable as fake.
	re := regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`)
	for range 50 {
		if key := fakeAWSKeyID(); !re.MatchString(key) {
			t.Fatalf("AWS key ID %q does not match %s", key, re)
		}
	}
	if fakeAWSKeyID() == fakeAWSKeyID() {
		t.Error("fakeAWSKeyID produced identical values")
	}
}

func TestFakeAWSSecret(t *testing.T) {
	re := regexp.MustCompile(`^[A-Za-z0-9+/]{40}$`)
	if secret := fakeAWSSecret(); !re.MatchString(secret) {
		t.Errorf("AWS secret %q does not match %s", secret, re)
	}
}

// verifyTokenChecksum recomputes a checksummed token's last six
// characters from its 30-character random part.
func verifyTokenChecksum(t *testing.T, token, prefix string) {
	t.Helper()
	if !strings.HasPrefix(token, prefix) || len(token) != len(prefix)+36 {
		t.Fatalf("token %q: want %s + 36 chars", token, prefix)
	}
	body, sum := token[len(prefix):len(prefix)+30], token[len(prefix)+30:]
	if want := tokenChecksum(crc32.ChecksumIEEE([]byte(body))); sum != want {
		t.Errorf("token %q: checksum %q, want %q", token, sum, want)
	}
}

func TestCheckedTokens(t *testing.T) {
	for range 20 {
		verifyTokenChecksum(t, fakeGitHubToken(), "ghp_")
		verifyTokenChecksum(t, fakeGitHubActionsToken(), "ghs_")
		verifyTokenChecksum(t, fakeNpmToken(), "npm_")
	}
}

func TestTokenChecksumEncoding(t *testing.T) {
	cases := map[uint32]string{
		0:          "000000",
		61:         "00000z",
		62:         "000010",
		0xFFFFFFFF: "4gfFC3", // 4294967295 in base62, digits < upper < lower
	}
	for v, want := range cases {
		if got := tokenChecksum(v); got != want {
			t.Errorf("tokenChecksum(%d) = %q, want %q", v, got, want)
		}
	}
}

func TestFakeSSHKeyPair(t *testing.T) {
	priv, pub, err := fakeSSHKeyPair("alice@laptop")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(priv))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("private key is not an RSA PEM block: %q", priv)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("private key does not parse: %v", err)
	}

	fields := strings.Fields(pub)
	if len(fields) != 3 || fields[0] != "ssh-rsa" || fields[2] != "alice@laptop" {
		t.Fatalf("public key line = %q", pub)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	// The public blob must carry the private key's own modulus.
	var parts [][]byte
	for len(blob) >= 4 {
		n := binary.BigEndian.Uint32(blob)
		parts = append(parts, blob[4:4+n])
		blob = blob[4+n:]
	}
	if len(parts) != 3 || string(parts[0]) != "ssh-rsa" {
		t.Fatalf("public blob has %d fields", len(parts))
	}
	if new(big.Int).SetBytes(parts[2]).Cmp(key.N) != 0 {
		t.Error("public key modulus does not match the private key")
	}
}

func TestHoneypotEnvVars(t *testing.T) {
	vars := honeypotEnvVars("alice", "alice-laptop", "/home/alice/projects")
	env := map[string]string{}
	for _, v := range vars {
		k, val, _ := strings.Cut(v, "=")
		env[k] = val
	}

	// One CI provider, consistently: a self-hosted GitHub Actions runner
	// whose identity matches the mirrored host.
	for k, want := range map[string]string{
		"CI":                      "true",
		"GITHUB_ACTIONS":          "true",
		"RUNNER_ENVIRONMENT":      "self-hosted",
		"RUNNER_NAME":             "alice-laptop",
		"GITHUB_REPOSITORY":       "alice/projects",
		"GITHUB_REPOSITORY_OWNER": "alice",
		"GITHUB_WORKSPACE":        "/home/alice/projects",
	} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q", k, env[k], want)
		}
	}
	for _, other := range []string{"GITLAB_CI", "BUILD_ID", "JENKINS_URL", "CIRCLECI", "TRAVIS"} {
		if _, ok := env[other]; ok {
			t.Errorf("%s set alongside GitHub Actions: contradictory CI identity", other)
		}
	}
	verifyTokenChecksum(t, env["GITHUB_TOKEN"], "ghs_")
	verifyTokenChecksum(t, env["NPM_TOKEN"], "npm_")
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(env["GITHUB_SHA"]) {
		t.Errorf("GITHUB_SHA = %q", env["GITHUB_SHA"])
	}

	// Secrets and run identifiers are random per scan.
	env2 := map[string]string{}
	for _, v := range honeypotEnvVars("alice", "alice-laptop", "/home/alice/projects") {
		k, val, _ := strings.Cut(v, "=")
		env2[k] = val
	}
	for _, k := range []string{"GITHUB_TOKEN", "GITHUB_SHA", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "NPM_TOKEN"} {
		if env[k] == env2[k] {
			t.Errorf("%s identical across scans", k)
		}
	}
}

func TestSanitizeDockerArg(t *testing.T) {
	cases := []struct {
		input    string
		fallback string
		want     string
	}{
		{"my-host", "localhost", "my-host"},
		{"host.local", "localhost", "host.local"},
		{"host name", "localhost", "hostname"},
		{"--inject", "localhost", "--inject"},
		{"$(evil)", "localhost", "evil"},
		{"", "localhost", "localhost"},
		{"日本語ホスト", "localhost", "localhost"},
		{"valid_host-123.local", "localhost", "valid_host-123.local"},
		// Verify the fallback is parameterised, not hardcoded to "localhost".
		{"", "user", "user"},
		{"$(evil)", "user", "evil"},
		{"日本語", "user", "user"},
		// Shell / volume-spec metacharacters get stripped.
		{"a;rm -rf /", "user", "arm-rf"},
		{"a/b", "user", "ab"},
		{"a:b", "user", "ab"},
	}

	for _, tc := range cases {
		got := sanitizeDockerArg(tc.input, tc.fallback)
		if got != tc.want {
			t.Errorf("sanitizeDockerArg(%q, %q) = %q, want %q", tc.input, tc.fallback, got, tc.want)
		}
	}
}
