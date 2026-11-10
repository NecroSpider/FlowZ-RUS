package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Untagged: the trust logic is pure Go and runs on the macOS dev host as well as on Linux CI.

func tmp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(d, 0o755)
	return d
}

func TestLinuxInstallCoreTrust(t *testing.T) {
	core, lib := []byte("bundled linux core"), []byte("bundled libcronet")
	oc, ol := bundledCoreSHA256, bundledCronetSHA256
	bundledCoreSHA256, bundledCronetSHA256 = sha256Hex(core), sha256Hex(lib)
	t.Cleanup(func() { bundledCoreSHA256, bundledCronetSHA256 = oc, ol })

	src, dst := tmp(t), filepath.Join(tmp(t), "core")
	_ = os.WriteFile(filepath.Join(src, "sing-box"), core, 0o755)
	_ = os.WriteFile(filepath.Join(src, "libcronet.so"), lib, 0o644)
	_ = os.WriteFile(filepath.Join(src, "flowz-helper-linux"), []byte("ignored"), 0o755)
	if r := installCoreFiles(src, dst); r != "OK installed" {
		t.Fatalf("bundled core+lib must install: %q", r)
	}
	if _, err := os.Stat(filepath.Join(dst, "flowz-helper-linux")); err == nil {
		t.Fatal("unexpected names must be ignored")
	}
	// a client-chosen core (old install-core trusted the client's hash) is now refused
	_ = os.WriteFile(filepath.Join(src, "sing-box"), []byte("user picked core"), 0o755)
	if r := installCoreFiles(src, dst); !strings.HasPrefix(r, "ERR untrusted-hash sing-box") {
		t.Fatalf("untrusted core must be refused: %q", r)
	}
	// ...until an elevated step allowlists it
	_ = os.WriteFile(filepath.Join(dst, allowlistName), []byte(sha256Hex([]byte("user picked core"))+"\n"), 0o644)
	if r := installCoreFiles(src, dst); r != "OK installed" {
		t.Fatalf("allowlisted core must install: %q", r)
	}
}

func TestParseProcStatStartTime(t *testing.T) {
	line := "1234 (my (weird) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 12345678 300 18446744073709551615"
	if got := parseProcStatStartTime(line); got != "987654" {
		t.Fatalf("starttime: got %q", got)
	}
	if parseProcStatStartTime("garbage") != "" || parseProcStatStartTime("1 (x) S 1 2") != "" {
		t.Fatal("malformed input must give empty")
	}
}
