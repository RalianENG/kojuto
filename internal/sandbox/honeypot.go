package sandbox

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"math/big"
	"path"
	"runtime"
	"time"
)

// Honeypots exist to be read by credential-harvesting code. They only work
// if that code treats them as real, so every value here follows the format
// a validator would check: right charset, right length, valid checksum,
// a key that parses, files whose ages look like a machine in use. All of it
// is generated per scan, so no constant from this file can be matched.

// base62Chars is the character set used by real AWS/GitHub/npm tokens.
// Using hex-only characters makes honeypot tokens statistically detectable
// (hex has 16 chars, base62 has 62 — entropy per character differs).
const base62Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// awsKeyIDChars is the alphabet of the 16 characters after an access key
// ID's "AKIA" prefix: the IDs are base32-encoded, so uppercase letters and
// the digits 2-7 only. A lowercase letter or a 0/1/8/9 there is a key no
// AWS account ever issued.
const awsKeyIDChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// awsSecretChars is the alphabet of a secret access key: base64.
const awsSecretChars = base62Chars + "+/"

// tokenChecksumAlphabet encodes the CRC32 checksum that GitHub (ghp_, ghs_,
// ...) and npm (npm_) tokens carry in their last six characters. GitHub
// describes the scheme as CRC32 of the token, Base62-encoded and
// zero-padded; this follows the convention public validators implement —
// CRC32 (IEEE) of the 30-character random part, digits before uppercase
// before lowercase. A token whose checksum does not verify is rejected by
// any offline validity check without a network round-trip.
const tokenChecksumAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// randFrom returns n characters drawn uniformly from charset.
func randFrom(charset string, n int) string {
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[0]
			continue
		}
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}

// randBase62 returns n random base62 characters, matching the character
// distribution of real cloud tokens and API keys.
func randBase62(n int) string {
	return randFrom(base62Chars, n)
}

// randHex returns n random hex characters (still used for non-token values).
func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// randIntRange returns a uniformly random integer in [lo, hi].
func randIntRange(lo, hi int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(hi-lo+1))
	if err != nil {
		return lo
	}
	return lo + n.Int64()
}

// fakeAWSKeyID generates a structurally valid AWS access key ID:
// AKIA + 16 base32 characters.
func fakeAWSKeyID() string {
	return "AKIA" + randFrom(awsKeyIDChars, 16)
}

// fakeAWSSecret generates a realistic AWS secret access key:
// 40 base64 characters.
func fakeAWSSecret() string {
	return randFrom(awsSecretChars, 40)
}

// tokenChecksum encodes v in tokenChecksumAlphabet, zero-padded to six
// characters (62^6 > 2^32, so six always suffice).
func tokenChecksum(v uint32) string {
	out := []byte("000000")
	for i := len(out) - 1; i >= 0 && v > 0; i-- {
		out[i] = tokenChecksumAlphabet[v%62]
		v /= 62
	}
	return string(out)
}

// checksummedToken generates prefix + 30 random base62 characters + the
// six-character checksum of those 30 characters.
func checksummedToken(prefix string) string {
	body := randBase62(30)
	return prefix + body + tokenChecksum(crc32.ChecksumIEEE([]byte(body)))
}

// fakeGitHubToken generates a GitHub personal access token (ghp_), the kind
// a developer keeps in ~/.git-credentials and the gh CLI config.
func fakeGitHubToken() string {
	return checksummedToken("ghp_")
}

// fakeGitHubActionsToken generates the ghs_ installation token GitHub
// Actions exposes as GITHUB_TOKEN. A ghp_ token there would contradict the
// rest of the runner environment.
func fakeGitHubActionsToken() string {
	return checksummedToken("ghs_")
}

// fakeNpmToken generates an npm access token (npm_), which uses the same
// checksummed format as GitHub's.
func fakeNpmToken() string {
	return checksummedToken("npm_")
}

// runnerArch returns RUNNER_ARCH for the host architecture; the sandbox
// image runs natively, so the container shares it.
func runnerArch() string {
	if runtime.GOARCH == "arm64" {
		return "ARM64"
	}
	return "X64"
}

// honeypotEnvVars returns the environment of a GitHub Actions job on a
// self-hosted runner. Malware gates on CI signals (e.g. "if CI, exfiltrate
// GITHUB_TOKEN"), so the job has to be believable as a whole: one CI
// provider, not several at once, with the variables that provider actually
// sets. A self-hosted runner is the persona that agrees with the rest of
// the sandbox — its hostname and user are the host's own (see
// containerArgs), which is exactly what a self-hosted runner reports, and
// GITHUB_WORKSPACE is the mounted project path. Tokens and run identifiers
// are random per scan, so no known honeypot value can be fingerprinted.
func honeypotEnvVars(owner, hostname, workspace string) []string {
	repo := path.Base(workspace)
	return []string{
		// GitHub Actions job (self-hosted runner).
		"CI=true",
		"GITHUB_ACTIONS=true",
		"GITHUB_SERVER_URL=https://github.com",
		"GITHUB_API_URL=https://api.github.com",
		"GITHUB_REPOSITORY=" + owner + "/" + repo,
		"GITHUB_REPOSITORY_OWNER=" + owner,
		"GITHUB_WORKFLOW=CI",
		"GITHUB_EVENT_NAME=push",
		"GITHUB_REF=refs/heads/main",
		"GITHUB_REF_NAME=main",
		"GITHUB_SHA=" + randHex(40),
		fmt.Sprintf("GITHUB_RUN_ID=%d", randIntRange(10_000_000_000, 19_999_999_999)),
		fmt.Sprintf("GITHUB_RUN_NUMBER=%d", randIntRange(12, 1500)),
		"GITHUB_RUN_ATTEMPT=1",
		"GITHUB_WORKSPACE=" + workspace,
		"GITHUB_TOKEN=" + fakeGitHubActionsToken(),
		"RUNNER_OS=Linux",
		"RUNNER_ARCH=" + runnerArch(),
		"RUNNER_ENVIRONMENT=self-hosted",
		"RUNNER_NAME=" + hostname,
		// Fake cloud credentials (random per scan).
		"AWS_ACCESS_KEY_ID=" + fakeAWSKeyID(),
		"AWS_SECRET_ACCESS_KEY=" + fakeAWSSecret(),
		"AWS_DEFAULT_REGION=us-east-1",
		// Fake registry token (random per scan).
		"NPM_TOKEN=" + fakeNpmToken(),
	}
}

// fakeSSHKeyPair generates a fresh RSA-2048 key pair: the private key as
// the PKCS#1 PEM block ssh-keygen wrote by default for years (and still
// reads), and the matching authorized_keys-format public key. The pair is
// genuine and parses, but it is never authorized anywhere and is discarded
// with the container.
func fakeSSHKeyPair(comment string) (privPEM, pubLine string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generating ssh key: %w", err)
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))

	// SSH wire format (RFC 4253 §6.6): string "ssh-rsa", mpint e, mpint n.
	var blob []byte
	blob = appendSSHString(blob, []byte("ssh-rsa"))
	blob = appendSSHString(blob, sshMpint(big.NewInt(int64(key.E))))
	blob = appendSSHString(blob, sshMpint(key.N))
	pubLine = "ssh-rsa " + base64.StdEncoding.EncodeToString(blob) + " " + comment + "\n"
	return privPEM, pubLine, nil
}

func appendSSHString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // bounded: key material is a few hundred bytes
	return append(b, s...)
}

// sshMpint encodes a non-negative integer as an SSH mpint: big-endian,
// with a leading zero byte when the high bit is set.
func sshMpint(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// honeypotFile is one planted file: where it goes, what it holds, its mode.
type honeypotFile struct {
	path    string
	content string
	mode    string
}

// plantHoneypotFiles writes realistic-looking but fake credential files into
// the container. All secret values are randomly generated per scan to prevent
// static fingerprinting by malware that knows kojuto's source code.
// When malware reads these via openat, the access is detected by the
// sensitive-path monitor. If it then tries to exfiltrate the contents,
// the connect/sendto monitor catches the network activity.
//
// The home directory is populated the way a used account looks: the
// distribution's skeleton dotfiles, then credentials whose timestamps are
// spread over the past two years rather than all stamped with the second
// the scan started.
//
// Failure here is fatal: a partially-planted set of honeypots leaves the
// detection contract ("if you read .ssh/id_rsa, you tripped the monitor")
// unenforceable for the missing files.
func (s *Sandbox) plantHoneypotFiles(ctx context.Context) error {
	home := "/home/dev"
	owner := getHostUsername()

	// Generate random credentials for this scan.
	awsKey := fakeAWSKeyID()
	awsSecret := fakeAWSSecret()
	ghToken := fakeGitHubToken()
	sshPriv, sshPub, err := fakeSSHKeyPair(owner + "@" + getHostHostname())
	if err != nil {
		return err
	}

	files := []honeypotFile{
		{home + "/.ssh/id_rsa", sshPriv, "600"},
		{home + "/.ssh/id_rsa.pub", sshPub, "644"},
		{home + "/.aws/credentials", "[default]\n" +
			"aws_access_key_id = " + awsKey + "\n" +
			"aws_secret_access_key = " + awsSecret + "\n", "600"},
		{home + "/.git-credentials", "https://" + owner + ":" + ghToken + "@github.com\n", "600"},
		{home + "/.netrc", "machine github.com\n" +
			"login " + owner + "\n" +
			"password " + ghToken + "\n", "600"},
		{home + "/.config/gh/hosts.yml", "github.com:\n" +
			"    oauth_token: " + ghToken + "\n" +
			"    user: " + owner + "\n" +
			"    git_protocol: https\n", "600"},
	}

	steps := []func() error{
		// Skeleton dotfiles (.bashrc, .profile, ...). The image's copies
		// sit under the /home/dev tmpfs mount, so they have to be copied
		// in. Only timestamps are preserved: `cp -a` would also try to
		// stamp /etc/skel's root ownership and mode onto /home/dev itself.
		func() error {
			return s.dockerExecRoot(ctx, "cp", "-r", "--preserve=timestamps", "/etc/skel/.", home+"/")
		},
		func() error {
			return s.dockerExecRoot(ctx, "mkdir", "-p", home+"/.ssh", home+"/.aws", home+"/.config/gh")
		},
		func() error { return s.dockerExecRoot(ctx, "chmod", "700", home+"/.ssh") },
	}
	for _, f := range files {
		steps = append(steps,
			func() error { return s.dockerWriteFile(ctx, f.path, f.content) },
			func() error { return s.dockerExecRoot(ctx, "chmod", f.mode, f.path) },
		)
	}
	steps = append(steps,
		// Fix ownership so the container user (dev) owns the files.
		func() error { return s.dockerExecRoot(ctx, "chown", "-R", "1000:1000", home) },
		func() error { return s.ageHoneypotFiles(ctx, home, files) },
		// Close the home directory last. The tmpfs is mounted 1777 so root
		// — which holds CHOWN/FOWNER but no DAC override in this sandbox —
		// can plant into it; 0750 is what an ordinary account's home
		// looks like, and FOWNER lets root set it on a directory dev owns.
		func() error { return s.dockerExecRoot(ctx, "chmod", "750", home) },
	)

	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// ageHoneypotFiles backdates the planted files to random points in the
// past two years, then gives each directory the timestamp of its newest
// entry, as the filesystem would have. Ages come from the real host clock:
// this runs before any faketime-wrapped process.
func (s *Sandbox) ageHoneypotFiles(ctx context.Context, home string, files []honeypotFile) error {
	now := time.Now().Unix()
	newest := map[string]int64{}
	for _, f := range files {
		ts := now - randIntRange(30, 720)*86400 - randIntRange(0, 86399)
		if err := s.dockerExecRoot(ctx, "touch", "-d", fmt.Sprintf("@%d", ts), f.path); err != nil {
			return err
		}
		for dir := path.Dir(f.path); dir != home && dir != "/"; dir = path.Dir(dir) {
			if ts > newest[dir] {
				newest[dir] = ts
			}
		}
	}
	for dir, ts := range newest {
		if err := s.dockerExecRoot(ctx, "touch", "-d", fmt.Sprintf("@%d", ts), dir); err != nil {
			return err
		}
	}
	return nil
}
