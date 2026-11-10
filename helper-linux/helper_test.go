//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// isAuthorized：授权 uid 列表解析 + root 恒授权 + 缺文件失败安全。
func TestIsAuthorized(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "auth")
	if err := os.WriteFile(f, []byte("1000\n1001\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	authFile = f
	for _, uid := range []uint32{1000, 1001} {
		if !isAuthorized(uid) {
			t.Errorf("uid %d should be authorized", uid)
		}
	}
	if isAuthorized(1002) {
		t.Error("uid 1002 is not in the list and should not be authorized")
	}
	if !isAuthorized(0) {
		t.Error("root(0) should always be authorized")
	}
	// 缺失授权文件 → 非 root 一律未授权（失败安全），root 仍授权。
	authFile = filepath.Join(dir, "nonexistent")
	if isAuthorized(1000) {
		t.Error("non-root should not be authorized when the auth file is missing")
	}
	if !isAuthorized(0) {
		t.Error("root should still be authorized when the auth file is missing")
	}
}

// ownedBy：属主校验（open+fstat）。
func TestOwnedBy(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(f, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	self := uint32(os.Getuid())
	if ok, err := ownedBy(f, self); err != nil || !ok {
		t.Errorf("this process's uid should own the file it created: ok=%v err=%v", ok, err)
	}
	if ok, _ := ownedBy(f, self+9999); ok {
		t.Error("a wrong uid should not pass the owner check")
	}
	if ok, err := ownedBy(filepath.Join(t.TempDir(), "none"), self); ok || err == nil {
		t.Error("a nonexistent path should return false + err")
	}
}

// ssPidRe：从 ss 输出行提取 LISTEN 持有者 pid。
func TestSsPidRe(t *testing.T) {
	line := `LISTEN 0 4096 0.0.0.0:9090 0.0.0.0:* users:(("sing-box",pid=1234,fd=7))`
	m := ssPidRe.FindAllStringSubmatch(line, -1)
	if len(m) != 1 || m[0][1] != "1234" {
		t.Errorf("expected to extract pid=1234, got %v", m)
	}
	if got := ssPidRe.FindAllStringSubmatch("no match here", -1); len(got) != 0 {
		t.Errorf("a line without pid should not match, got %v", got)
	}
}

// openLogForCaller: only next to the config, by dir fd, O_NOFOLLOW, regular single-link, never chown an existing file.
func TestOpenLogForCaller(t *testing.T) {
	dir := t.TempDir()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	cfg := filepath.Join(dir, "singbox_config.json")
	if err := os.WriteFile(cfg, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openLogForCaller(cfg, filepath.Join(dir, "singbox_startup.log"), uid, gid)
	if err != nil {
		t.Fatalf("log next to the config must open: %v", err)
	}
	f.Close()
	if _, err := openLogForCaller(cfg, "/etc/passwd", uid, gid); err == nil {
		t.Error("a log outside the config dir must be refused")
	}
	other := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(other, []byte("v"), 0o644)
	_ = os.Symlink(other, filepath.Join(dir, "link.log"))
	if _, err := openLogForCaller(cfg, filepath.Join(dir, "link.log"), uid, gid); err == nil {
		t.Error("a symlinked log must be refused")
	}
	if err := os.Link(other, filepath.Join(dir, "hard.log")); err == nil {
		if _, err := openLogForCaller(cfg, filepath.Join(dir, "hard.log"), uid, gid); err == nil {
			t.Error("a hard-linked log must be refused")
		}
	}
	if _, err := openLogForCaller(cfg, filepath.Join(dir, "x.log"), uid+1, gid); err == nil {
		t.Error("a config dir not owned by the caller must be refused")
	}
}
