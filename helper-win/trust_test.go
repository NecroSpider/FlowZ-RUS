package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Portable test of the shared trust logic with Windows file names (hooks: trust_windows.go / hooks_nonwindows_test.go).
func TestWinInstallCoreTrust(t *testing.T) {
	core, lib := []byte("bundled sing-box.exe"), []byte("bundled libcronet.dll")
	oc, ol := bundledCoreSHA256, bundledCronetSHA256
	bundledCoreSHA256, bundledCronetSHA256 = sha256Hex(core), sha256Hex(lib)
	t.Cleanup(func() { bundledCoreSHA256, bundledCronetSHA256 = oc, ol; hashCache = map[string]hashEntry{} })

	seed, dst := t.TempDir(), filepath.Join(t.TempDir(), "core")
	_ = os.WriteFile(filepath.Join(seed, "sing-box.exe"), core, 0o755)
	_ = os.WriteFile(filepath.Join(seed, "libcronet.dll"), lib, 0o644)
	_ = os.WriteFile(filepath.Join(seed, "com.flowz.helper.exe"), []byte("x"), 0o755)

	// the user-writable userData core is never run; the protected copy is seeded from the bundle
	h, err := ensureTrustedCore(dst, seed)
	if err != nil || h != sha256Hex(core) {
		t.Fatalf("seed: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "libcronet.dll")); string(b) != string(lib) {
		t.Fatal("libcronet.dll must be seeded with the core")
	}
	// a planted DLL with an untrusted hash is removed before the core runs
	_ = os.WriteFile(filepath.Join(dst, "libcronet.dll"), []byte("planted"), 0o644)
	hashCache = map[string]hashEntry{}
	if _, err := ensureTrustedCore(dst, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "libcronet.dll")); err == nil {
		t.Fatal("untrusted libcronet.dll must be removed")
	}
	// install-core over the pipe: untrusted user core refused
	upd := t.TempDir()
	_ = os.WriteFile(filepath.Join(upd, "sing-box.exe"), []byte("downloaded 1.15"), 0o755)
	if r := installCoreFiles(upd, dst); !strings.HasPrefix(r, "ERR untrusted-hash sing-box.exe") {
		t.Fatalf("got %q", r)
	}
}
