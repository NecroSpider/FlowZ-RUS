package main

import "strings"

// parseProcStatStartTime extracts field 22 (starttime) from /proc/<pid>/stat. The comm field (2) may contain
// spaces and parentheses, so fields are counted from the last ')'. Returns "" if malformed.
func parseProcStatStartTime(stat string) string {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return ""
	}
	f := strings.Fields(stat[i+1:])
	// f[0] is field 3 (state) → starttime (field 22) is f[19].
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
