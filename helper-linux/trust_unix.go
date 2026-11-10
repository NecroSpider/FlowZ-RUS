//go:build linux || darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const coreFileName = "sing-box"

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func statKey(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d|%d|%d|%d", uint64(st.Dev), uint64(st.Ino), fi.Size(), fi.ModTime().UnixNano())
}

// ensureCoreDir: the protected dir must be a real directory (not a symlink), owned by root and not writable by
// group/other (Linux: /usr/local/lib/flowz/core). Running as root the helper repairs ownership/mode; tests (non-root) only require no g/o write.
func ensureCoreDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(dir); err != nil {
			return err
		}
		err = os.ErrNotExist
	}
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	root := os.Geteuid() == 0
	if root {
		_ = os.Lchown(dir, 0, 0)
	}
	_ = os.Chmod(dir, 0o755)
	fi, err = os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || fi.Mode().Perm()&0o022 != 0 || (root && st.Uid != 0) {
		return fmt.Errorf("%s has unsafe ownership or permissions", dir)
	}
	return nil
}

func allowlistFileSafe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	return st.Uid == 0 || (os.Geteuid() != 0 && int(st.Uid) == os.Geteuid())
}

// writeFileReplace: exclusive temp file in the (root-only) dir + fsync + atomic rename. A running binary keeps its
// old inode, so replacing a core in use is safe on Unix.
func writeFileReplace(dir, name string, data []byte, perm os.FileMode) error {
	tmp := filepath.Join(dir, "."+name+".new")
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
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
	_ = os.Chmod(tmp, perm)
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
