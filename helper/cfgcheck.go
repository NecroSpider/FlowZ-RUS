// Config policy for a root/SYSTEM-run core — shared verbatim by helper/ (macOS) and helper-win/ (keep in sync).
//
// The config file lives in the user's data dir, so anyone holding the helper token could otherwise make the
// privileged core run programs (tor outbound executable_path / extra_args / torrc / data_directory), serve the
// whole disk (clash_api.external_ui, services[].dashboard.path) or write files anywhere (log.output, cache_file,
// tailscale state_directory). sanitizeConfig rejects those; the helper then runs the core on a root/SYSTEM-owned
// copy of exactly the bytes it validated, so the user file cannot be swapped after the check.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type configPolicy struct {
	allowedDirs []string // log / cache / external_ui / state_directory must resolve inside one of these
	uiDirs      []string // extra dirs services[].dashboard.path may point at (the app's bundled dashboard)
	foldCase    bool     // Windows paths compare case-insensitively
}

var forbiddenConfigKeys = map[string]bool{
	"executable_path": true,
	"extra_args":      true,
	"torrc":           true,
	"data_directory":  true,
}

const maxConfigSize = 64 << 20

// resolveExisting: EvalSymlinks on the longest existing prefix, then re-append the non-existent remainder.
// Returns "" when a component exists but cannot be resolved (dangling symlink / loop) — such a path is rejected.
func resolveExisting(p string) string {
	cur := filepath.Clean(p)
	rest := ""
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return r
			}
			return filepath.Join(r, rest)
		}
		if _, err := os.Lstat(cur); err == nil {
			return ""
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		if rest == "" {
			rest = filepath.Base(cur)
		} else {
			rest = filepath.Join(filepath.Base(cur), rest)
		}
		cur = parent
	}
}

func hasPathPrefix(p, dir string, fold bool) bool {
	if p == "" || dir == "" {
		return false
	}
	if fold {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	dir = strings.TrimRight(dir, `/\`)
	return p == dir || strings.HasPrefix(p, dir+string(os.PathSeparator))
}

func pathWithin(p string, dirs []string, fold bool) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	r := resolveExisting(p)
	if r == "" {
		return false
	}
	for _, d := range dirs {
		if hasPathPrefix(r, d, fold) {
			return true
		}
	}
	return false
}

// resolvedDirs resolves each existing dir (symlinks, e.g. macOS /var → /private/var); missing ones are dropped.
func resolvedDirs(dirs ...string) []string {
	var out []string
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if r, err := filepath.EvalSymlinks(filepath.Clean(d)); err == nil {
			out = append(out, r)
		}
	}
	return out
}

func findForbiddenKey(v any, path string, depth int) string {
	if depth > 64 {
		return path + " (too deep)"
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if forbiddenConfigKeys[strings.ToLower(k)] {
				return path + "." + k
			}
			if r := findForbiddenKey(child, path+"."+k, depth+1); r != "" {
				return r
			}
		}
	case []any:
		for i, child := range t {
			if r := findForbiddenKey(child, fmt.Sprintf("%s[%d]", path, i), depth+1); r != "" {
				return r
			}
		}
	}
	return ""
}

func objAt(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// sanitizeConfig validates a sing-box config for a privileged run. Returns the bytes to run (the input unchanged
// unless a dashboard path had to be dropped), human-readable warnings, or an error starting with
// "config-invalid" / "config-denied".
func sanitizeConfig(data []byte, pol configPolicy) ([]byte, []string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, nil, fmt.Errorf("config-invalid %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("config-invalid trailing data after the JSON object")
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, nil, errors.New("config-invalid top level is not an object")
	}
	if k := findForbiddenKey(obj, "", 0); k != "" {
		return nil, nil, fmt.Errorf("config-denied forbidden key %s", strings.TrimPrefix(k, "."))
	}
	for _, sect := range []string{"outbounds", "endpoints"} {
		arr, _ := obj[sect].([]any)
		for i, el := range arr {
			if m, ok := el.(map[string]any); ok {
				if t, _ := m["type"].(string); strings.EqualFold(t, "tor") {
					return nil, nil, fmt.Errorf("config-denied %s[%d] has type tor", sect, i)
				}
			}
		}
	}
	checkPath := func(label string, v any) error {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil
		}
		if !pathWithin(s, pol.allowedDirs, pol.foldCase) {
			return fmt.Errorf("config-denied %s points outside the app data directory: %s", label, s)
		}
		return nil
	}
	if m := objAt(obj, "log"); m != nil {
		if err := checkPath("log.output", m["output"]); err != nil {
			return nil, nil, err
		}
	}
	if m := objAt(obj, "experimental", "cache_file"); m != nil {
		if err := checkPath("experimental.cache_file.path", m["path"]); err != nil {
			return nil, nil, err
		}
	}
	if m := objAt(obj, "experimental", "clash_api"); m != nil {
		if err := checkPath("experimental.clash_api.external_ui", m["external_ui"]); err != nil {
			return nil, nil, err
		}
	}
	if arr, ok := obj["endpoints"].([]any); ok {
		for i, el := range arr {
			if m, ok := el.(map[string]any); ok {
				if err := checkPath(fmt.Sprintf("endpoints[%d].state_directory", i), m["state_directory"]); err != nil {
					return nil, nil, err
				}
			}
		}
	}
	var warnings []string
	modified := false
	if arr, ok := obj["services"].([]any); ok {
		uiAllowed := append(append([]string{}, pol.allowedDirs...), pol.uiDirs...)
		for i, el := range arr {
			m, ok := el.(map[string]any)
			if !ok {
				continue
			}
			dash, ok := m["dashboard"].(map[string]any)
			if !ok {
				continue
			}
			p, ok := dash["path"].(string)
			if !ok || p == "" {
				continue
			}
			if !pathWithin(p, uiAllowed, pol.foldCase) {
				// Degrade instead of refusing to connect: the dashboard falls back to its built-in download.
				delete(dash, "path")
				modified = true
				warnings = append(warnings, fmt.Sprintf("services[%d].dashboard.path dropped (outside allowed dirs): %s", i, p))
			}
		}
	}
	if !modified {
		return data, warnings, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, nil, fmt.Errorf("config-invalid re-encode: %v", err)
	}
	return buf.Bytes(), warnings, nil
}
