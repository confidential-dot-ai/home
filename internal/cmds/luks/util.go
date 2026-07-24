package luks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func jsonEncoder() *json.Encoder {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// zero wipes secret bytes best-effort; copies Go made elsewhere are out of reach.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func trimNewline(s string) string { return strings.TrimRight(s, "\r\n") }

// sanitize strips ASCII control characters from untrusted text (openbao error
// bodies, kubectl output) so it cannot forge log lines or terminal escapes.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func cutColon(s string) (a, b string, ok bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func runOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return string(out), nil
}
