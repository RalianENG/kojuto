package downloader

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseBuildRequires(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []string
		ok   bool
	}{
		{"one line", "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n", []string{"hatchling"}, true},
		{"multi-line with comments and trailing comma", "[project]\nname = \"x\"\n\n[build-system]\nrequires = [\n  \"poetry-core>=1.0.0\", # backend\n  'wheel',\n]\n", []string{"poetry-core>=1.0.0", "wheel"}, true},
		{"requires outside build-system ignored", "[tool.x]\nrequires = [\"evil\"]\n[build-system]\nrequires = [\"setuptools>=61\"]\n", []string{"setuptools>=61"}, true},
		{"bracket inside a string", "[build-system]\nrequires = [\"pkg[extra]>=1\"]\n", []string{"pkg[extra]>=1"}, true},
		{"no build-system", "[project]\nname = \"x\"\n", nil, false},
		{"not an array", "[build-system]\nrequires = \"hatchling\"\n", nil, false},
		{"unterminated", "[build-system]\nrequires = [\"hatchling\"\n", nil, false},
		{"non-string element", "[build-system]\nrequires = [1, 2]\n", nil, false},
	}
	for _, tc := range cases {
		got, ok := parseBuildRequires(tc.doc)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: parseBuildRequires = %q, %v; want %q, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// TestValidBuildRequirement pins that only plain requirements reach pip:
// anything that would change how pip runs (an option, an index, a direct
// URL or path) is dropped.
func TestValidBuildRequirement(t *testing.T) {
	good := []string{
		"hatchling", "poetry-core>=1.0.0", "setuptools>=61.0", "flit_core >=3.2,<4",
		"pkg[extra]>=1", "wheel; python_version >= '3.8'", "scikit-build-core==0.10.*",
	}
	bad := []string{
		"", "--index-url=http://evil.example/simple", "-e .", "--extra-index-url",
		"pkg @ https://evil.example/pkg.whl", "https://evil.example/pkg.whl",
		"./local-backend", "../x", "/abs/path", "pkg; os.system('x')$",
		"pkg\n--index-url=http://evil", string(make([]byte, 300)),
	}
	for _, r := range good {
		if !validBuildRequirement(r) {
			t.Errorf("rejected valid requirement %q", r)
		}
	}
	for _, r := range bad {
		if validBuildRequirement(r) {
			t.Errorf("accepted unsafe requirement %q", r)
		}
	}
}

const testPyproject = "[build-system]\nrequires = [\"hatchling\", \"--index-url=http://evil\"]\n"

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestBuildRequires_Archives reads the sdist-root pyproject.toml out of each
// archive shape without extracting it, ignores nested ones, and drops the
// unsafe requirement.
func TestBuildRequires_Archives(t *testing.T) {
	dir := t.TempDir()

	tgz := filepath.Join(dir, "pkg-1.0.tar.gz")
	writeTarGz(t, tgz, map[string]string{
		"pkg-1.0/pyproject.toml":        testPyproject,
		"pkg-1.0/vendor/pyproject.toml": "[build-system]\nrequires = [\"nested\"]\n",
	})

	zp := filepath.Join(dir, "pkg-1.0.zip")
	zf, err := os.Create(zp)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, _ := zw.Create("pkg-1.0/pyproject.toml")
	_, _ = w.Write([]byte(testPyproject))
	_ = zw.Close()
	_ = zf.Close()

	src := filepath.Join(dir, "src")
	_ = os.MkdirAll(src, 0o755)
	_ = os.WriteFile(filepath.Join(src, "pyproject.toml"), []byte(testPyproject), 0o644)

	for _, p := range []string{tgz, zp, src} {
		got, err := BuildRequires(p)
		if err != nil || !reflect.DeepEqual(got, []string{"hatchling"}) {
			t.Errorf("BuildRequires(%s) = %q, %v; want [hatchling]", filepath.Base(p), got, err)
		}
	}

	// A wheel needs no build; an sdist without pyproject.toml has nothing
	// to fetch; neither is an error.
	whl := filepath.Join(dir, "pkg-1.0-py3-none-any.whl")
	_ = os.WriteFile(whl, []byte("not read"), 0o644)
	legacy := filepath.Join(dir, "legacy-1.0.tar.gz")
	writeTarGz(t, legacy, map[string]string{"legacy-1.0/setup.py": "from setuptools import setup\nsetup()\n"})
	for _, p := range []string{whl, legacy} {
		if got, err := BuildRequires(p); err != nil || got != nil {
			t.Errorf("BuildRequires(%s) = %q, %v; want nil, nil", filepath.Base(p), got, err)
		}
	}
}
