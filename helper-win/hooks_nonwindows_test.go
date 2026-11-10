//go:build !windows

package main

// Test-only stand-ins for the trust_windows.go hooks so the platform-neutral logic (trust.go, cfgcheck.go,
// auth.go, selfuninstall.go) can be unit-tested on a macOS/Linux dev host. Real hooks: trust_windows.go.

import (
	"fmt"
	"os"
	"path/filepath"
)

const coreFileName = "sing-box.exe"

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

func statKey(fi os.FileInfo) string { return fmt.Sprintf("%d|%d", fi.Size(), fi.ModTime().UnixNano()) }

func ensureCoreDir(dir string) error { return os.MkdirAll(dir, 0o755) }

func allowlistFileSafe(fi os.FileInfo) bool { return true }

func writeFileReplace(dir, name string, data []byte, perm os.FileMode) error {
	tmp := filepath.Join(dir, "."+name+".new")
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}
