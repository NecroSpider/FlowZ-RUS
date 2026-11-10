//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// relUnder returns p relative to base when p is inside base (filepath.Rel is case-insensitive on Windows).
func relUnder(base, p string) string {
	if base == "" || p == "" || !filepath.IsAbs(p) {
		return ""
	}
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(p))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) || filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" {
		return ""
	}
	return rel
}

// readConfigUnder reads the config once through an os.Root on confDir (reparse points cannot escape it).
func readConfigUnder(cfg string) ([]byte, error) {
	rel := relUnder(confDir, cfg)
	if rel == "" {
		return nil, errors.New("config-path-denied")
	}
	rt, err := os.OpenRoot(confDir)
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	f, err := rt.Open(rel)
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

func configPolicyFor() configPolicy {
	pol := configPolicy{allowedDirs: resolvedDirs(confDir), foldCase: true}
	if bundledCorePath != "" {
		pol.uiDirs = resolvedDirs(filepath.Join(filepath.Dir(filepath.Dir(bundledCorePath)), "dashboard"))
	}
	return pol
}

// prepareRunConfig: validate, then run the core on a copy in <support>\run (SYSTEM/Administrators-only ACL
// inherited from the support dir), so the user file cannot be swapped after the check.
func prepareRunConfig(cfg string) (string, []string, error) {
	data, err := readConfigUnder(cfg)
	if err != nil {
		return "", nil, fmt.Errorf("config-read %v", err)
	}
	out, warnings, err := sanitizeConfig(data, configPolicyFor())
	if err != nil {
		return "", nil, err
	}
	dir := filepath.Join(supportDir, "run")
	if err := ensureCoreDir(dir); err != nil {
		return "", nil, fmt.Errorf("config-write %v", err)
	}
	if err := writeFileReplace(dir, "active-config.json", out, 0o600); err != nil {
		return "", nil, fmt.Errorf("config-write %v", err)
	}
	return filepath.Join(dir, "active-config.json"), warnings, nil
}

// openLogUnder: the early log must be inside confDir (opened through an os.Root), a regular file with exactly one
// link, and its final path must still be inside confDir.
func openLogUnder(logPath string) (*os.File, error) {
	rel := relUnder(confDir, logPath)
	if rel == "" {
		return nil, errors.New("log path outside the app data directory")
	}
	rt, err := os.OpenRoot(confDir)
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	f, err := rt.OpenFile(rel, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("log is not a regular file")
	}
	h := windows.Handle(f.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.NumberOfLinks != 1 {
		f.Close()
		return nil, errors.New("log has more than one link")
	}
	if final := finalPath(h); final == "" || !hasPathPrefix(final, firstNonEmpty(resolvedDirs(confDir)), true) {
		f.Close()
		return nil, errors.New("log resolves outside the app data directory")
	}
	return f, nil
}

func firstNonEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func finalPath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil || n == 0 || int(n) > len(buf) {
		return ""
	}
	p := windows.UTF16ToString(buf[:n])
	if strings.HasPrefix(p, `\\?\UNC\`) {
		return `\\` + p[len(`\\?\UNC\`):]
	}
	return strings.TrimPrefix(p, `\\?\`)
}

// ---- IP forwarding (allowLan) with restore ----

type regDword struct {
	known, existed bool
	val            uint64
}

var (
	fwdSaved *regDword
	fwdOwner interface{} // *exec.Cmd of the session that enabled forwarding
)

const tcpipParams = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

// enableIPForwarding: IPv4 IPEnableRouter=1 (persistent registry value) after saving the previous value once;
// IPv6 via netsh as before (best-effort, its previous state cannot be read reliably and is left as is).
func enableIPForwarding() {
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, tcpipParams, registry.QUERY_VALUE|registry.SET_VALUE); err == nil {
		if fwdSaved == nil {
			v, _, e := k.GetIntegerValue("IPEnableRouter")
			switch {
			case e == nil:
				fwdSaved = &regDword{known: true, existed: true, val: v}
			case errors.Is(e, registry.ErrNotExist):
				fwdSaved = &regDword{known: true}
			default:
				fwdSaved = &regDword{}
			}
		}
		_ = k.SetDWordValue("IPEnableRouter", 1)
		k.Close()
	}
	enableIPv6Forwarding()
}

// restoreIPForwarding puts IPEnableRouter back to what it was before the session. Caller holds mu.
func restoreIPForwarding() {
	if s := fwdSaved; s != nil && s.known {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipParams, registry.SET_VALUE); err == nil {
			if s.existed {
				_ = k.SetDWordValue("IPEnableRouter", uint32(s.val))
			} else {
				_ = k.DeleteValue("IPEnableRouter")
			}
			k.Close()
		}
	}
	fwdSaved, fwdOwner = nil, nil
}
