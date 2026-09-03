// Package safeout renders untrusted text safely for a terminal.
//
// kojuto's whole job is to run hostile code and then tell the user what it
// did. Every string that reaches the user therefore has to be assumed
// attacker-authored: pip/npm stdout relayed from inside the sandbox, a
// package's own stderr, a comm name, an audit-hook code snippet. Left raw,
// an ANSI escape sequence in any of those can move the cursor, clear the
// screen, or overwrite the "SUSPICIOUS" verdict block that kojuto prints to
// the same stream a moment later — turning the tool's own output into the
// attacker's last evasion step.
//
// Two renderings are provided because the two sinks want different things:
//
//   - String is strict and is used for values embedded in a structured
//     record (the JSON report), where a newline would break the one-value-
//     per-field shape a consumer like `jq -r` relies on.
//   - WriteStream is for relayed console output, where newlines and tabs
//     are the legitimate structure of the text and only the control bytes
//     that steer the terminal are neutralized.
package safeout

import (
	"fmt"
	"io"
	"strings"
)

// String escapes every C0 control byte (0x00-0x1f) and DEL (0x7f) to a
// printable form. Common whitespace uses the conventional \n / \r / \t
// shorthand; everything else renders as \xNN. Printable ASCII and UTF-8
// multibyte sequences pass through unchanged.
//
// The result contains no byte that a terminal interprets as a command, so
// it is safe to interpolate into a line of kojuto's own output.
func String(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// needsEscape reports whether s contains any byte String would rewrite.
// Byte-wise rather than rune-wise: every byte String escapes is below
// 0x80, so a UTF-8 continuation byte can never produce a false positive.
func needsEscape(s string) bool {
	for i := range len(s) {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// WriteStream copies b to w with terminal-steering control bytes rendered
// inert, and reports the number of bytes of b consumed (not the number
// written, which is larger whenever something was escaped) so callers can
// treat it like w.Write.
//
// Newline and tab survive verbatim: they carry the structure of relayed
// pip/npm output and neutralizing them would collapse a build log into one
// unreadable line for no security gain. Every other C0 byte — ESC above
// all, but also CR, which can overwrite the line just printed — plus DEL
// is escaped to \xNN. Bytes at or above 0x80 are copied untouched, so
// UTF-8 (and any non-UTF-8 payload) survives byte-for-byte without this
// function having to decode it.
func WriteStream(w io.Writer, b []byte) (int, error) {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c == '\n' || c == '\t':
			out = append(out, c)
		case c < 0x20 || c == 0x7f:
			out = append(out, []byte(fmt.Sprintf(`\x%02x`, c))...)
		default:
			out = append(out, c)
		}
	}
	if _, err := w.Write(out); err != nil {
		return 0, fmt.Errorf("writing sanitized output: %w", err)
	}
	return len(b), nil
}
