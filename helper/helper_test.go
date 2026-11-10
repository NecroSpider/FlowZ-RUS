package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// tdir returns a temp dir with symlinks resolved (macOS /var → /private/var) and no group/other write bits.
func tdir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(d, 0o755)
	return d
}

func writeFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func withCompiled(t *testing.T, core, lib string) {
	t.Helper()
	oc, ol := bundledCoreSHA256, bundledCronetSHA256
	bundledCoreSHA256, bundledCronetSHA256 = core, lib
	hashCache = map[string]hashEntry{}
	t.Cleanup(func() { bundledCoreSHA256, bundledCronetSHA256 = oc, ol })
}

func TestInstallCoreFilesTrust(t *testing.T) {
	good := []byte("bundled core bytes")
	withCompiled(t, sha256Hex(good), "")
	src, dst := tdir(t), filepath.Join(tdir(t), "core")

	// untrusted binary → refused, nothing written
	writeFile(t, filepath.Join(src, "sing-box"), []byte("evil"))
	if r := installCoreFiles(src, dst); !strings.HasPrefix(r, "ERR untrusted-hash sing-box ") {
		t.Fatalf("untrusted core must be refused, got %q", r)
	}
	if _, err := os.Stat(filepath.Join(dst, "sing-box")); err == nil {
		t.Fatal("nothing may be written for an untrusted core")
	}

	// trusted binary + unrelated files → installed, unrelated names ignored
	writeFile(t, filepath.Join(src, "sing-box"), good)
	writeFile(t, filepath.Join(src, "LICENSE"), []byte("x"))
	writeFile(t, filepath.Join(src, "com.flowz.helper"), []byte("x"))
	if r := installCoreFiles(src, dst); r != "OK installed" {
		t.Fatalf("trusted core must install, got %q", r)
	}
	got, _ := os.ReadFile(filepath.Join(dst, "sing-box"))
	if !bytes.Equal(got, good) {
		t.Fatal("installed bytes differ")
	}
	if _, err := os.Stat(filepath.Join(dst, "LICENSE")); err == nil {
		t.Fatal("unexpected names must not be copied")
	}

	// an expected name that is a symlink → refused (never followed)
	src2 := tdir(t)
	if err := os.Symlink(filepath.Join(src, "sing-box"), filepath.Join(src2, "sing-box")); err != nil {
		t.Fatal(err)
	}
	if r := installCoreFiles(src2, dst); !strings.HasPrefix(r, "ERR bad-source sing-box") {
		t.Fatalf("symlinked source must be refused, got %q", r)
	}

	// untrusted companion lib → whole install refused
	writeFile(t, filepath.Join(src, "libcronet.dylib"), []byte("lib"))
	if r := installCoreFiles(src, dst); !strings.HasPrefix(r, "ERR untrusted-hash libcronet.dylib") {
		t.Fatalf("untrusted lib must be refused, got %q", r)
	}
}

func TestAllowlistTrust(t *testing.T) {
	withCompiled(t, sha256Hex([]byte("bundled")), "")
	src, dst := tdir(t), filepath.Join(tdir(t), "core")
	custom := []byte("admin-approved core")
	writeFile(t, filepath.Join(src, "sing-box"), custom)
	if r := installCoreFiles(src, dst); !strings.HasPrefix(r, "ERR untrusted") {
		t.Fatalf("not yet allowlisted: %q", r)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	al := filepath.Join(dst, allowlistName)
	if err := os.WriteFile(al, []byte("# approved\n"+strings.ToUpper(sha256Hex(custom))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := installCoreFiles(src, dst); r != "OK installed" {
		t.Fatalf("allowlisted core must install, got %q", r)
	}
	// a group/other-writable allowlist is ignored
	_ = os.Chmod(al, 0o666)
	if r := installCoreFiles(src, dst); !strings.HasPrefix(r, "ERR untrusted") {
		t.Fatalf("writable allowlist must be ignored, got %q", r)
	}
}

func TestEnsureTrustedCoreSeeds(t *testing.T) {
	good := []byte("bundled core v1")
	withCompiled(t, sha256Hex(good), "")
	seed, dst := tdir(t), filepath.Join(tdir(t), "core")
	writeFile(t, filepath.Join(seed, "sing-box"), good)

	// missing → seeded
	h, err := ensureTrustedCore(dst, seed)
	if err != nil || h != sha256Hex(good) {
		t.Fatalf("missing core must be seeded: %v %s", err, h)
	}
	// replaced by an untrusted binary (e.g. left by an old helper) → re-seeded
	writeFile(t, filepath.Join(dst, "sing-box"), []byte("tampered"))
	hashCache = map[string]hashEntry{}
	if h, err = ensureTrustedCore(dst, seed); err != nil || h != sha256Hex(good) {
		t.Fatalf("untrusted core must be re-seeded: %v", err)
	}
	// untrusted + seed unusable → clear error, no seed written
	writeFile(t, filepath.Join(dst, "sing-box"), []byte("tampered"))
	writeFile(t, filepath.Join(seed, "sing-box"), []byte("app updated, helper stale"))
	hashCache = map[string]hashEntry{}
	if _, err = ensureTrustedCore(dst, seed); err == nil || !strings.HasPrefix(err.Error(), "core-untrusted") {
		t.Fatalf("expected core-untrusted, got %v", err)
	}
	// untrusted lib next to a trusted core is removed
	writeFile(t, filepath.Join(dst, "sing-box"), good)
	writeFile(t, filepath.Join(dst, "libcronet.dylib"), []byte("evil lib"))
	hashCache = map[string]hashEntry{}
	if _, err = ensureTrustedCore(dst, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "libcronet.dylib")); err == nil {
		t.Fatal("untrusted lib must be removed")
	}
}

const flowzLikeConfig = `{
  "log": {"level": "info", "output": "%CONF%/singbox.log"},
  "experimental": {"cache_file": {"enabled": true, "path": "%CONF%/cache.db", "cache_id": "flowz-dns-v2"}},
  "endpoints": [{"type": "tailscale", "tag": "ts", "state_directory": "%CONF%/tailscale/abc"}],
  "services": [{"type": "api", "listen": "127.0.0.1", "listen_port": 9091,
     "dashboard": {"enabled": true, "path": "%UI%"}}],
  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "vless", "tag": "n1", "server": "1.2.3.4", "server_port": 443}],
  "route": {"rule_set": [{"tag": "geo", "type": "local", "format": "binary", "path": "/elsewhere/geo.srs"}], "final": "n1"}
}`

func cfgFor(conf, ui string) []byte {
	return []byte(strings.NewReplacer("%CONF%", conf, "%UI%", ui).Replace(flowzLikeConfig))
}

func TestSanitizeConfigAllowsFlowZConfig(t *testing.T) {
	conf, res := tdir(t), tdir(t)
	ui := filepath.Join(res, "dashboard")
	_ = os.MkdirAll(ui, 0o755)
	pol := configPolicy{allowedDirs: resolvedDirs(conf), uiDirs: resolvedDirs(ui)}
	in := cfgFor(conf, ui)
	out, warn, err := sanitizeConfig(in, pol)
	if err != nil || len(warn) != 0 || !bytes.Equal(in, out) {
		t.Fatalf("FlowZ config must pass unchanged: err=%v warn=%v", err, warn)
	}
	// dashboard override dir inside userData is fine too
	if _, _, err := sanitizeConfig(cfgFor(conf, filepath.Join(conf, "dashboard")), pol); err != nil {
		t.Fatal(err)
	}
}

func TestSanitizeConfigRejects(t *testing.T) {
	conf := tdir(t)
	outside := tdir(t)
	pol := configPolicy{allowedDirs: resolvedDirs(conf)}
	_ = os.Symlink(outside, filepath.Join(conf, "escape"))
	_ = os.Symlink(filepath.Join(outside, "nope"), filepath.Join(conf, "dangling.log"))
	cases := map[string]string{
		"tor outbound":     `{"outbounds":[{"type":"tor","tag":"t"}]}`,
		"tor endpoint":     `{"endpoints":[{"type":"TOR"}]}`,
		"executable_path":  `{"outbounds":[{"type":"direct","x":{"executable_path":"/bin/sh"}}]}`,
		"extra_args":       `{"extra_args":["-x"]}`,
		"torrc":            `{"a":[{"torrc":{}}]}`,
		"data_directory":   `{"data_directory":"/tmp"}`,
		"log outside":      `{"log":{"output":"/etc/sudoers"}}`,
		"log relative":     `{"log":{"output":"singbox.log"}}`,
		"log dotdot":       `{"log":{"output":"` + conf + `/../x.log"}}`,
		"log via symlink":  `{"log":{"output":"` + conf + `/escape/x.log"}}`,
		"dangling symlink": `{"log":{"output":"` + conf + `/dangling.log"}}`,
		"cache outside":    `{"experimental":{"cache_file":{"path":"/var/root/c.db"}}}`,
		"external_ui root": `{"experimental":{"clash_api":{"external_ui":"/"}}}`,
		"state_directory":  `{"endpoints":[{"type":"tailscale","state_directory":"/Library"}]}`,
		"not an object":    `[1]`,
		"trailing garbage": `{} {}`,
		"invalid json":     `{"log":`,
	}
	for name, c := range cases {
		if _, _, err := sanitizeConfig([]byte(c), pol); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	// dashboard outside allowed dirs → dropped (degrade), not refused
	out, warn, err := sanitizeConfig([]byte(`{"services":[{"type":"api","dashboard":{"enabled":true,"path":"/"}}],"n":12345678901}`), pol)
	if err != nil || len(warn) != 1 || bytes.Contains(out, []byte(`"path"`)) || !bytes.Contains(out, []byte("12345678901")) {
		t.Fatalf("dashboard path must be dropped: err=%v warn=%v out=%s", err, warn, out)
	}
}

func TestRelUnder(t *testing.T) {
	if relUnder("/a/b", "/a/b/c.log") != "c.log" || relUnder("/a/b", "/a/b/x/../c") != "c" {
		t.Error("inside paths")
	}
	for _, p := range []string{"/a/bc", "/a/b", "/a/b/../c", "rel", "/etc/passwd"} {
		if relUnder("/a/b", p) != "" {
			t.Errorf("%s must be outside", p)
		}
	}
}

func TestOpenLogUnder(t *testing.T) {
	conf, outside := tdir(t), tdir(t)
	old := confDir
	confDir = conf
	t.Cleanup(func() { confDir = old })

	f, err := openLogUnder(filepath.Join(conf, "singbox_startup.log"))
	if err != nil {
		t.Fatalf("log inside confDir must open: %v", err)
	}
	f.Close()
	if _, err := openLogUnder(filepath.Join(outside, "x.log")); err == nil {
		t.Error("log outside confDir must be refused")
	}
	target := filepath.Join(outside, "victim")
	writeFile(t, target, []byte("v"))
	_ = os.Symlink(target, filepath.Join(conf, "link.log"))
	if _, err := openLogUnder(filepath.Join(conf, "link.log")); err == nil {
		t.Error("symlinked log must be refused")
	}
	if err := os.Link(target, filepath.Join(conf, "hard.log")); err == nil {
		if _, err := openLogUnder(filepath.Join(conf, "hard.log")); err == nil {
			t.Error("hard-linked log must be refused")
		}
	}
	_ = os.Symlink(outside, filepath.Join(conf, "logs"))
	if _, err := openLogUnder(filepath.Join(conf, "logs", "new.log")); err == nil {
		t.Error("log through a symlinked dir escaping confDir must be refused")
	}
	if _, err := os.Stat(filepath.Join(outside, "new.log")); err == nil {
		t.Error("nothing may be created outside confDir")
	}
}

func TestChownRuntimeDirsWalk(t *testing.T) {
	conf, outside := tdir(t), tdir(t)
	old, oldUID, oldF := confDir, reclaimUID, fchownFile
	confDir = conf
	reclaimUID = uint32(os.Getuid()) // test files are ours; treat them as "root-created"
	var touched []string
	fchownFile = func(f *os.File, uid, gid int) error {
		rel, _ := filepath.Rel(conf, f.Name())
		touched = append(touched, rel)
		return nil
	}
	t.Cleanup(func() { confDir, reclaimUID, fchownFile = old, oldUID, oldF })

	ts := filepath.Join(conf, "tailscale", "n1")
	_ = os.MkdirAll(ts, 0o755)
	writeFile(t, filepath.Join(ts, "state"), []byte("s"))
	secret := filepath.Join(outside, "secret")
	writeFile(t, secret, []byte("s"))
	_ = os.Link(secret, filepath.Join(ts, "hardlink"))
	_ = os.Symlink(outside, filepath.Join(ts, "symdir"))
	_ = os.Symlink(secret, filepath.Join(conf, "ui"))

	chownRuntimeDirs()
	sort.Strings(touched)
	want := []string{"tailscale", "tailscale/n1", "tailscale/n1/state"}
	if strings.Join(touched, ",") != strings.Join(want, ",") {
		t.Fatalf("walk touched %v, want %v", touched, want)
	}
}

func TestBundledTrustFlag(t *testing.T) {
	cur := []byte("bundled core of this helper build")
	withCompiled(t, sha256Hex(cur), "")
	dir := tdir(t)
	newer := sha256Hex([]byte("bundled core of the next app release"))
	if bundledTrustFlag(dir, sha256Hex(cur)) != "1" {
		t.Error("own pin must be trusted")
	}
	if bundledTrustFlag(dir, newer) != "0" {
		t.Error("a newer app's bundled core must report untrusted (helper outdated)")
	}
	if err := os.WriteFile(filepath.Join(dir, allowlistName), []byte(newer+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if bundledTrustFlag(dir, newer) != "1" {
		t.Error("an admin-approved hash must report trusted")
	}
	if bundledTrustFlag(dir, "") != "-" {
		t.Error("no hash → -")
	}
}
