// Core trust model — shared verbatim by helper/ (macOS), helper-linux/ and helper-win/ (each is its own Go module,
// so the file is copied; keep the copies identical). Platform hooks live in trust_<os>.go:
// coreFileName, openNoFollow, statKey, ensureCoreDir, allowlistFileSafe, writeFileReplace.
//
// A core binary (and its libcronet companion) is trusted when its SHA-256 is either
//
//	(a) compiled into this helper at build time (bundledCoreSHA256 / bundledCronetSHA256, wired by
//	    scripts/build-helper.sh from src/shared/core-manifest.json), or
//	(b) listed in <coreDir>/trusted-hashes, a file only an elevated (admin password / UAC / pkexec) step writes.
//
// Everything that reaches the helper over its socket/pipe (install-core) is held to that rule, so holding the
// helper token is no longer enough to make root/SYSTEM run an arbitrary binary.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Set with -ldflags "-X main.bundledCoreSHA256=<hex> -X main.bundledCronetSHA256=<hex>".
var (
	bundledCoreSHA256   string
	bundledCronetSHA256 string
)

const (
	allowlistName    = "trusted-hashes"
	maxBinarySize    = 256 << 20
	maxAllowlistSize = 1 << 20
)

func normHash(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// trustEnforced: false only for ad-hoc builds made without the compiled-in hash (plain `go build`). Release builds
// go through scripts/build-helper.sh, which refuses to build without it. Unenforced = legacy behaviour.
func trustEnforced() bool { return normHash(bundledCoreSHA256) != "" }

// fileKind: which core-directory files install-core accepts. Anything else in a source dir is ignored.
func fileKind(name string) string {
	switch name {
	case coreFileName:
		return "core"
	case "libcronet.so", "libcronet.dylib", "libcronet.dll":
		return "lib"
	}
	return ""
}

func compiledHash(kind string) string {
	if kind == "core" {
		return normHash(bundledCoreSHA256)
	}
	if kind == "lib" {
		return normHash(bundledCronetSHA256)
	}
	return ""
}

// loadAllowlist reads <dir>/trusted-hashes (one hex SHA-256 per line, '#' comments). Unsafe ownership/permissions
// or a non-regular file → treated as empty.
func loadAllowlist(dir string) map[string]bool {
	out := map[string]bool{}
	p := filepath.Join(dir, allowlistName)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || !allowlistFileSafe(fi) {
		return out
	}
	data, err := readRegularFile(p, maxAllowlistSize)
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if h := normHash(strings.TrimPrefix(line, "sha256:")); h != "" {
			out[h] = true
		}
	}
	return out
}

func isTrusted(hash, kind string, allow map[string]bool) bool {
	hash = normHash(hash)
	if hash == "" {
		return false
	}
	if c := compiledHash(kind); c != "" && c == hash {
		return true
	}
	return allow[hash]
}

// readRegularFile reads a file once into memory: never follows a symlink at the final component, refuses
// non-regular files (FIFO/device/dir), checks the opened handle is the same file that was Lstat'ed and caps the size.
// Callers hash and write exactly these bytes, so there is no check-then-use window.
func readRegularFile(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", filepath.Base(path))
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || !os.SameFile(fi, st) {
		return nil, fmt.Errorf("%s: changed while opening", filepath.Base(path))
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s: too large", filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: too large", filepath.Base(path))
	}
	return data, nil
}

// Hash cache for files inside the protected core dir (only root/SYSTEM writes there), keyed on stat identity,
// so a start does not re-hash ~40 MB every time. Callers hold mu.
type hashEntry struct{ key, hash string }

var hashCache = map[string]hashEntry{}

func fileHashCached(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	key := statKey(fi)
	if e, ok := hashCache[path]; ok && key != "" && e.key == key {
		return e.hash, nil
	}
	data, err := readRegularFile(path, maxBinarySize)
	if err != nil {
		return "", err
	}
	h := sha256Hex(data)
	hashCache[path] = hashEntry{key: key, hash: h}
	return h, nil
}

// installCoreFiles copies the trusted core files found in srcDir into dstDir. Every accepted entry must be a
// regular file (Lstat, no symlinks) with an expected name; its bytes are read once, hashed, checked against the
// trust set and written from that same buffer. Nothing is written unless every candidate is trusted.
func installCoreFiles(srcDir, dstDir string) string {
	if dstDir == "" {
		return "ERR coredir-unset"
	}
	if srcDir == "" {
		return "ERR bad-args"
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return "ERR readdir " + err.Error()
	}
	allow := loadAllowlist(dstDir)
	type item struct {
		name string
		data []byte
	}
	var items []item
	haveCore := false
	for _, e := range entries {
		kind := fileKind(e.Name())
		if kind == "" {
			continue
		}
		data, err := readRegularFile(filepath.Join(srcDir, e.Name()), maxBinarySize)
		if err != nil {
			return "ERR bad-source " + e.Name() + ": " + err.Error()
		}
		h := sha256Hex(data)
		if trustEnforced() && !isTrusted(h, kind, allow) {
			return fmt.Sprintf("ERR untrusted-hash %s %s", e.Name(), h)
		}
		items = append(items, item{e.Name(), data})
		if kind == "core" {
			haveCore = true
		}
	}
	if !haveCore {
		return "ERR read-singbox missing " + coreFileName
	}
	if err := ensureCoreDir(dstDir); err != nil {
		return "ERR mkdir " + err.Error()
	}
	keep := map[string]bool{}
	// Companion libraries first, the core last: a half-finished install never pairs a new core with an old lib.
	for pass := 0; pass < 2; pass++ {
		for _, it := range items {
			if (fileKind(it.name) == "core") != (pass == 1) {
				continue
			}
			if err := writeFileReplace(dstDir, it.name, it.data, 0o755); err != nil {
				return "ERR write " + it.name + " " + err.Error()
			}
			keep[it.name] = true
		}
	}
	cleanupCoreDir(dstDir, keep)
	hashCache = map[string]hashEntry{}
	return "OK installed"
}

// cleanupCoreDir removes stale companion libraries that were not part of this install and leftover temp files.
func cleanupCoreDir(dir string, keep map[string]bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || keep[n] {
			continue
		}
		stale := fileKind(n) == "lib" ||
			(strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".new")) ||
			strings.Contains(n, ".old-")
		if stale {
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
}

// dropUntrustedLibs deletes companion libraries in the protected dir whose hash is not trusted (the core would
// load them with root/SYSTEM rights).
func dropUntrustedLibs(dir string, allow map[string]bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if fileKind(e.Name()) != "lib" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		h, err := fileHashCached(p)
		if err != nil || !isTrusted(h, "lib", allow) {
			_ = os.Remove(p)
			delete(hashCache, p)
		}
	}
}

// ensureTrustedCore makes sure <dir>/<coreFileName> exists and is trusted. If it is missing or untrusted and
// seedDir is set (the bundled core directory recorded at install time), the bundled core is seeded — accepted
// only when its bytes hash to a trusted value. Returns the hash of the core that will run.
func ensureTrustedCore(dir, seedDir string) (string, error) {
	if dir == "" {
		return "", errors.New("coredir-unset")
	}
	if err := ensureCoreDir(dir); err != nil {
		return "", fmt.Errorf("core-dir %v", err)
	}
	core := filepath.Join(dir, coreFileName)
	allow := loadAllowlist(dir)
	h, herr := fileHashCached(core)
	if herr == nil && (!trustEnforced() || isTrusted(h, "core", allow)) {
		if trustEnforced() {
			dropUntrustedLibs(dir, allow)
		}
		return h, nil
	}
	seedMsg := ""
	if seedDir != "" {
		resp := installCoreFiles(seedDir, dir)
		if strings.HasPrefix(resp, "OK") {
			return fileHashCached(core)
		}
		seedMsg = "; seed: " + strings.TrimPrefix(resp, "ERR ")
	}
	if herr != nil {
		return "", fmt.Errorf("core-missing %v%s", herr, seedMsg)
	}
	return "", fmt.Errorf("core-untrusted %s%s", h, seedMsg)
}

// bundledTrustFlag answers core-info's optional hash line (the app's bundled-core pin): "1" when this helper would
// accept that core, "0" when it would not (helper built for an older bundled core and the hash is not allowlisted —
// the client then treats the helper as outdated and goes through the reinstall flow), "-" when no hash was sent.
func bundledTrustFlag(dir, h string) string {
	h = normHash(h)
	if h == "" {
		return "-"
	}
	if !trustEnforced() || isTrusted(h, "core", loadAllowlist(dir)) {
		return "1"
	}
	return "0"
}
