package luks

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

func jsonEncoder() *json.Encoder {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc
}

func bytesReader(b []byte) *strings.Reader { return strings.NewReader(string(b)) }

func trimNewline(s string) string { return strings.TrimRight(s, "\r\n") }

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
		return "", err
	}
	return string(out), nil
}
