package safeout

import (
	"bytes"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain passes through", "hello world", "hello world"},
		{"utf8 passes through", "パッケージ", "パッケージ"},
		{"newline escaped", "a\nb", `a\nb`},
		{"carriage return escaped", "a\rb", `a\rb`},
		{"tab escaped", "a\tb", `a\tb`},
		{"escape byte neutralized", "a\x1b[2Jb", `a\x1b[2Jb`},
		{"nul escaped", "a\x00b", `a\x00b`},
		{"del escaped", "a\x7fb", `a\x7fb`},
	}
	for _, tc := range cases {
		if got := String(tc.in); got != tc.want {
			t.Errorf("%s: String(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestStringLeavesNoControlBytes is the property that actually matters:
// whatever goes in, nothing a terminal interprets as a command comes out.
func TestStringLeavesNoControlBytes(t *testing.T) {
	var b strings.Builder
	for i := range 256 {
		b.WriteByte(byte(i))
	}
	got := String(b.String())
	for i := range len(got) {
		if c := got[i]; c < 0x20 || c == 0x7f {
			t.Fatalf("String left control byte %#x at index %d", c, i)
		}
	}
}

func TestWriteStreamKeepsStructureDropsEscapes(t *testing.T) {
	var buf bytes.Buffer
	// A build log shape: real newlines and tabs are the text's structure and
	// must survive, while the ANSI sequence a malicious package would use to
	// erase kojuto's verdict block must not.
	in := []byte("building\n\tstep 1\n\x1b[1A\x1b[2Kerased?\n")
	n, err := WriteStream(&buf, in)
	if err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if n != len(in) {
		t.Errorf("WriteStream returned n = %d, want %d (bytes of input consumed)", n, len(in))
	}

	got := buf.String()
	if !strings.Contains(got, "building\n\tstep 1\n") {
		t.Errorf("newlines/tabs did not survive: %q", got)
	}
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("ESC byte survived into output: %q", got)
	}
	if !strings.Contains(got, `\x1b[1A`) {
		t.Errorf("ESC not rendered as an escape: %q", got)
	}
}

func TestWriteStreamPassesNonUTF8Through(t *testing.T) {
	var buf bytes.Buffer
	// Invalid UTF-8 must not be mangled into U+FFFD — a byte-oriented sink
	// should stay byte-faithful for everything it is not deliberately
	// neutralizing.
	in := []byte{0xff, 0xfe, 'o', 'k'}
	if _, err := WriteStream(&buf, in); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), in) {
		t.Errorf("WriteStream mangled non-UTF-8 input: got %v, want %v", buf.Bytes(), in)
	}
}

func TestWriteStreamCRIsEscaped(t *testing.T) {
	var buf bytes.Buffer
	// CR alone can overwrite the line just printed, so it is escaped even
	// though it is whitespace.
	if _, err := WriteStream(&buf, []byte("real\rfake")); err != nil {
		t.Fatalf("WriteStream: %v", err)
	}
	if strings.ContainsRune(buf.String(), '\r') {
		t.Errorf("CR survived into output: %q", buf.String())
	}
}
