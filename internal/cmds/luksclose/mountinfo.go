package luksclose

import (
	"os"
	"strings"
)

// procMountinfoContains reports whether /proc/self/mountinfo lists path as a
// mountpoint. Field layout: `<id> <pid> <maj:min> <root> <mountpoint> <opts>…`
// — position 4 (0-indexed) is the mountpoint.
func procMountinfoContains(path string) (bool, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[4] == path {
			return true, nil
		}
	}
	return false, nil
}
