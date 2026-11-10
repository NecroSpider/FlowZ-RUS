//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const coreFileName = "sing-box.exe"

// openNoFollow: Windows has no O_NOFOLLOW; readRegularFile's Lstat (symlinks and junctions are not regular) plus
// the SameFile check after opening refuse reparse points and swaps.
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

func statKey(fi os.FileInfo) string {
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return fmt.Sprintf("%d|%d|%d", fi.Size(), d.LastWriteTime.Nanoseconds(), d.CreationTime.Nanoseconds())
	}
	return fmt.Sprintf("%d|%d", fi.Size(), fi.ModTime().UnixNano())
}

// ensureCoreDir: <support>\core inherits the locked SYSTEM/Administrators-only ACL of the support dir set by the
// installer. A reparse point in its place is removed and replaced by a real directory.
func ensureCoreDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err == nil && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		if err := os.Remove(dir); err != nil {
			return err
		}
		err = os.ErrNotExist
	}
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		return os.MkdirAll(dir, 0o755)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// allowlistFileSafe: confidentiality/integrity come from the inherited directory ACL (SYSTEM + Administrators).
func allowlistFileSafe(fi os.FileInfo) bool { return fi.Mode().IsRegular() }

// writeFileReplace: exclusive temp + fsync + rename. A running sing-box.exe / loaded libcronet.dll cannot be
// overwritten but can be renamed aside; the aside copy is deleted now if possible, else by cleanupCoreDir later.
func writeFileReplace(dir, name string, data []byte, perm os.FileMode) error {
	tmp := filepath.Join(dir, "."+name+".new")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	dst := filepath.Join(dir, name)
	if err := os.Rename(tmp, dst); err == nil {
		return nil
	}
	aside := dst + ".old-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.Rename(dst, aside); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Rename(aside, dst)
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(aside)
	return nil
}
