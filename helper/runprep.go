package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// relUnder returns p relative to base when p is lexically inside base (after Clean), else "".
func relUnder(base, p string) string {
	if base == "" || p == "" || !filepath.IsAbs(p) {
		return ""
	}
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(p))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return ""
	}
	return rel
}

// openConfRoot opens confDir as an os.Root (fd-based: symlinks inside cannot escape it) and returns the uid/gid
// that owns it. A root-owned confDir (e.g. swapped for a symlink to a system dir) is refused.
func openConfRoot() (*os.Root, int, int, error) {
	if confDir == "" {
		return nil, 0, 0, errors.New("confdir-unset")
	}
	rt, err := os.OpenRoot(confDir)
	if err != nil {
		return nil, 0, 0, err
	}
	fi, err := rt.Stat(".")
	if err != nil {
		rt.Close()
		return nil, 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		rt.Close()
		return nil, 0, 0, errors.New("confdir is owned by root")
	}
	return rt, int(st.Uid), int(st.Gid), nil
}

// readConfigUnder reads the user's config once, through the confDir root (no symlink escape), regular file only.
func readConfigUnder(cfg string) ([]byte, error) {
	rel := relUnder(confDir, cfg)
	if rel == "" {
		return nil, errors.New("config-path-denied")
	}
	rt, _, _, err := openConfRoot()
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	f, err := rt.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxConfigSize {
		return nil, errors.New("config is not a regular file or is too large")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxConfigSize {
		return nil, errors.New("config too large")
	}
	return data, nil
}

func runDir() string { return filepath.Join(supportDir, "run") }

// configPolicyFor: everything the core writes must stay in the app data dir; the dashboard may also be served
// from the app's bundled resources (…/Resources/dashboard, next to …/Resources/mac/sing-box).
func configPolicyFor() configPolicy {
	// APFS is case-insensitive by default: compare paths case-insensitively.
	pol := configPolicy{allowedDirs: resolvedDirs(confDir), foldCase: true}
	if bundledCorePath != "" {
		pol.uiDirs = resolvedDirs(filepath.Join(filepath.Dir(filepath.Dir(bundledCorePath)), "dashboard"))
	}
	return pol
}

// prepareRunConfig validates the user's config and writes the validated bytes to a root-only file the core runs
// with, so the user cannot swap the file between the check and the core reading it.
func prepareRunConfig(cfg string) (string, []string, error) {
	data, err := readConfigUnder(cfg)
	if err != nil {
		return "", nil, fmt.Errorf("config-read %v", err)
	}
	out, warnings, err := sanitizeConfig(data, configPolicyFor())
	if err != nil {
		return "", nil, err
	}
	dir := runDir()
	if fi, err := os.Lstat(dir); err == nil && (!fi.IsDir() || fi.Mode()&os.ModeSymlink != 0) {
		_ = os.Remove(dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("config-write %v", err)
	}
	_ = os.Chmod(dir, 0o700)
	if err := writeFileReplace(dir, "active-config.json", out, 0o600); err != nil {
		return "", nil, fmt.Errorf("config-write %v", err)
	}
	return filepath.Join(dir, "active-config.json"), warnings, nil
}

// openLogUnder opens the early stdout/stderr log for append. The path must be inside confDir and is opened
// through the confDir root with O_NOFOLLOW; it must be a regular file with a single link (a hard link to a
// system file is refused). A file the helper just created is handed to the confDir owner by fd.
func openLogUnder(logPath string) (*os.File, error) {
	rel := relUnder(confDir, logPath)
	if rel == "" {
		return nil, errors.New("log path outside the app data directory")
	}
	rt, uid, gid, err := openConfRoot()
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	created := false
	f, err := rt.OpenFile(rel, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		f, err = rt.OpenFile(rel, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o644)
		created = err == nil
	}
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("log is not a regular single-link file")
	}
	if created && os.Geteuid() == 0 {
		_ = f.Chown(uid, gid)
	}
	return f, nil
}

// ---- runtime dir ownership hand-back (proto v6 behaviour, hardened) ----

// fchownFile is swapped in tests.
var fchownFile = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }

// reclaimUID is the owner whose entries get handed back (root: files the root-run core created).
var reclaimUID uint32 = 0

const reclaimMaxDepth = 32

// chownRuntimeDirs gives root-created entries under confDir/{tailscale,singbox-dashboard,ui} back to the user who
// owns confDir. Walks by file descriptor inside an os.Root: never follows symlinks, opens every entry with
// O_NOFOLLOW and chowns the opened fd (no path re-resolution between check and chown), skips regular files with
// more than one link (hard links to files outside the tree) and anything that is not a file or directory.
func chownRuntimeDirs() {
	rt, uid, gid, err := openConfRoot()
	if err != nil {
		return
	}
	defer rt.Close()
	for _, name := range []string{"tailscale", "singbox-dashboard", "ui"} {
		reclaimEntry(rt, name, uid, gid, 0)
	}
}

func reclaimEntry(rt *os.Root, name string, uid, gid, depth int) {
	if depth > reclaimMaxDepth {
		return
	}
	lfi, err := rt.Lstat(name)
	if err != nil || lfi.Mode()&os.ModeSymlink != 0 {
		return
	}
	if !lfi.Mode().IsRegular() && !lfi.IsDir() {
		return
	}
	f, err := rt.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(lfi, fi) {
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	if fi.Mode().IsRegular() {
		if st.Nlink == 1 && st.Uid == reclaimUID {
			_ = fchownFile(f, uid, gid)
		}
		return
	}
	if !fi.IsDir() {
		return
	}
	if st.Uid == reclaimUID {
		_ = fchownFile(f, uid, gid)
	}
	names, err := f.Readdirnames(-1)
	if err != nil {
		return
	}
	sub, err := rt.OpenRoot(name)
	if err != nil {
		return
	}
	defer sub.Close()
	if sfi, err := sub.Stat("."); err != nil || !os.SameFile(sfi, fi) {
		return // swapped between our open and OpenRoot
	}
	for _, n := range names {
		reclaimEntry(sub, n, uid, gid, depth+1)
	}
}
