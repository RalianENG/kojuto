package downloader

import "testing"

func TestValidatePackage_Valid(t *testing.T) {
	cases := []struct {
		pkg     string
		version string
	}{
		{"requests", ""},
		{"requests", "2.31.0"},
		{"my-package", "1.0.0"},
		{"my_package", "1.0.0"},
		{"a", ""},
		{"numpy", "1.26.4"},
		{"package123", "0.0.1"},
	}

	for _, c := range cases {
		if err := ValidatePackage(c.pkg, c.version); err != nil {
			t.Errorf("ValidatePackage(%q, %q) = %v, want nil", c.pkg, c.version, err)
		}
	}
}

func TestValidatePackage_Invalid(t *testing.T) {
	cases := []struct {
		pkg     string
		version string
		desc    string
	}{
		{"--index-url=https://evil.com", "", "flag injection via package name"},
		{"-e", "", "short flag injection"},
		{"", "", "empty package name"},
		{"a b", "", "space in package name"},
		{"pkg", "--bad", "flag injection via version"},
		{"valid", "$(whoami)", "command injection via version"},
	}

	for _, c := range cases {
		if err := ValidatePackage(c.pkg, c.version); err == nil {
			t.Errorf("ValidatePackage(%q, %q) = nil, want error (%s)", c.pkg, c.version, c.desc)
		}
	}
}

func TestDetectVersion(t *testing.T) {
	// DetectVersion with empty dir returns empty string.
	v := DetectVersion(t.TempDir(), "nonexistent")
	if v != "" {
		t.Errorf("expected empty version, got %q", v)
	}
}
