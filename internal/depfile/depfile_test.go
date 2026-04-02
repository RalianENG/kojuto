package depfile

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/RalianENG/kojuto/internal/types"
)

func TestParse_RequirementsTxt(t *testing.T) {
	content := `# This is a comment
requests==2.31.0
six
flask>=2.0
numpy~=1.24
pandas!=1.5.0
scipy>1.10
boto3<2.0

# Options should be skipped
-r other.txt
--index-url https://pypi.org/simple

# Inline comments
click==8.1.7  # CLI framework

# Environment markers
cffi==1.15.1 ; python_version >= "3.8"

# URLs and paths should be skipped
https://example.com/package.tar.gz
./local/package
`

	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	deps, ecosystem, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if ecosystem != types.EcosystemPyPI {
		t.Errorf("expected ecosystem pypi, got %s", ecosystem)
	}

	// Sort for stable comparison.
	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	expected := []Dep{
		{Name: "boto3", Version: ""},
		{Name: "cffi", Version: "1.15.1"},
		{Name: "click", Version: "8.1.7"},
		{Name: "flask", Version: ""},
		{Name: "numpy", Version: ""},
		{Name: "pandas", Version: ""},
		{Name: "requests", Version: "2.31.0"},
		{Name: "scipy", Version: ""},
		{Name: "six", Version: ""},
	}

	if len(deps) != len(expected) {
		t.Fatalf("expected %d deps, got %d: %v", len(expected), len(deps), deps)
	}

	for i, exp := range expected {
		if deps[i].Name != exp.Name || deps[i].Version != exp.Version {
			t.Errorf("dep[%d]: got {%s, %s}, want {%s, %s}", i, deps[i].Name, deps[i].Version, exp.Name, exp.Version)
		}
	}
}

func TestParse_PackageJSON(t *testing.T) {
	content := `{
  "name": "my-project",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "4.17.21",
    "axios": "~1.6.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "typescript": "*"
  }
}`

	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	deps, ecosystem, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if ecosystem != types.EcosystemNpm {
		t.Errorf("expected ecosystem npm, got %s", ecosystem)
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	expected := []Dep{
		{Name: "axios", Version: "1.6.0"},
		{Name: "express", Version: "4.18.0"},
		{Name: "jest", Version: "29.0.0"},
		{Name: "lodash", Version: "4.17.21"},
		{Name: "typescript", Version: ""},
	}

	if len(deps) != len(expected) {
		t.Fatalf("expected %d deps, got %d: %v", len(expected), len(deps), deps)
	}

	for i, exp := range expected {
		if deps[i].Name != exp.Name || deps[i].Version != exp.Version {
			t.Errorf("dep[%d]: got {%s, %s}, want {%s, %s}", i, deps[i].Name, deps[i].Version, exp.Name, exp.Version)
		}
	}
}

func TestParse_UnsupportedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deps.yaml")
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := Parse(path)
	if err == nil {
		t.Error("expected error for unsupported file type")
	}
}

func TestParse_EmptyRequirements(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(path, []byte("# only comments\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deps, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := Parse(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestCleanNpmVersion(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"4.17.21", "4.17.21"},
		{"^4.18.0", "4.18.0"},
		{"~1.6.0", "1.6.0"},
		{">=2.0.0", ""},
		{"*", ""},
		{"latest", ""},
		{"", ""},
	}

	for _, tc := range cases {
		got := cleanNpmVersion(tc.input)
		if got != tc.want {
			t.Errorf("cleanNpmVersion(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
