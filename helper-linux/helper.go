//go:build linux

// FlowZ Linux 提权 helper（生产版）：root systemd system service，监听 unix socket，按行协议驱动 sing-box 启停。
// 装一次（pkexec 一次授权）后，普通用户 app 经 socket 零提权启停 sing-box —— 切节点/停止/退出/崩溃回收/换核均免再次授权。
//
// 第一性设计（见 docs/design/flowz-linux-privileged-helper.md）：
//   - 能力挂进程不挂文件：start 时 helper 以 root fork，setuid 回**发起请求的登录用户** + AmbientCaps=CAP_NET_ADMIN
//     拉核。核仍以登录用户跑（读得到 userData 的 config/cache/log，属主天然对），cap 在进程 ambient set 上。
//   - **核二进制在 root-owned 受管目录（--coredir，安装时播种、install-core hash 校验更新）**，与 macOS 受保护目录 /
//     Windows 锁定 --singbox 一致：核不可被普通用户篡改，一份共享、版本一致。这根除了「哪个二进制可信持有 CAP_NET_ADMIN」
//     的问题——start 只跑锁定的 coreDir/sing-box，绝不跑客户端指定的任意路径。换核经 install-core 免密（socket 调用）。
//   - 鉴权 SO_PEERCRED（内核背书对端 uid）+ 授权 uid 列表，无 token。
//
// 安全边界：
//   - 只跑锁定的 coreDir/sing-box（root-owned，普通用户改不动）→ 杜绝「借 helper 给任意自有二进制赋 CAP_NET_ADMIN」。
//   - config 必须属于对端 uid（open+fstat，防读别人配置）。install-core 只写锁定的 coreDir，sha256 校验主二进制（防 TOCTOU）。
//   - 授权 uid 由 root-owned authfile 记录；freeport/cleanup 仅作用于对端 uid 自己的进程（不跨用户杀）。
//   - AmbientCaps 授 CAP_NET_ADMIN/NET_RAW/NET_BIND_SERVICE（与现役 setcap 授权一致，PlatformPrivilegeService.ts:191）。
//
// 协议（每行 \n 结尾，路径整行传递）：
//
//	行1: <command>   ping | version | status | start | stop | cleanup | freeport | install-core
//	start 追加: 行2=<singbox 路径，须==coreDir/sing-box> 行3=<cfg> 行4=<log，可空> 行5=<fwd:0|1> 行6=<父 app PID，可选>
//	freeport 追加: 行2=<port>
//	install-core 追加: 行2=<srcDir> 行3=<sha256(hex)>
//
// 鉴权无独立行：对端身份经 SO_PEERCRED 取得。仅依赖 Go 标准库（便于交叉编译与审计）。
package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 协议版本。v1：root 受管核 + install-core + 路径锁 + SO_PEERCRED + 授权列表 + 父死看护 + freeport。
// v2: install-core accepts only trusted binaries (hash compiled in at build time or listed in
// <coredir>/trusted-hashes, which only the pkexec elevated path writes; the client hash line is ignored);
// expected names only (sing-box, libcronet.*), regular files, never symlinks. core-info → "OK bundled=<h> core=<h>".
// The start log is opened next to the config, relative to that dir's fd, never chowning an existing file.
// IP forwarding is only touched when requested and restored on every child-exit path; watchParent also
// compares the parent's start time (PID reuse). Line layout unchanged → v1 clients keep working.
const protoVersion = "2"

// Linux capability 数值（<linux/capability.h>；纯标准库不引 x/sys/unix）。授权集与现役 setcap 一致（不推测削减）。
const (
	capNetBindService = 10
	capNetAdmin       = 12
	capNetRaw         = 13
)

var (
	sockPath string // 监听的 unix socket 路径
	authFile string // 授权 uid 列表文件（root 写；每行一个十进制 uid）
	coreDir  string // root-owned 受管核目录（只跑/只写此目录内的 sing-box，锁定）

	mu        sync.Mutex
	child     *exec.Cmd
	childDone chan struct{}
	reapWG    sync.WaitGroup // 在途后台收割（stop 的 terminateChild）：SIGTERM 退出前须等它们跑完，杜绝孤儿
)

// coreBin：锁定的受管核路径。start 只跑它，绝不跑客户端指定的任意二进制。
func coreBin() string { return filepath.Join(coreDir, "sing-box") }

func readLine(r *bufio.Reader) string {
	s, _ := r.ReadString('\n')
	return strings.TrimRight(s, "\r\n")
}

// peerCred 取对端进程凭据（SO_PEERCRED）。uid/gid 内核在 connect 时锁定、不可伪造，作鉴权与 setuid 的唯一依据。
func peerCred(conn net.Conn) (*syscall.Ucred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix conn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, cerr
}

// isAuthorized：uid 是否在授权列表。root(0) 恒授权。
func isAuthorized(uid uint32) bool {
	if uid == 0 {
		return true
	}
	data, err := os.ReadFile(authFile)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if n, err := strconv.Atoi(line); err == nil && n >= 0 && uint32(n) == uid {
			return true
		}
	}
	return false
}

// ownedBy：path 存在且属主 == uid（open 后对 fd fstat，杜绝 stat(path) 后被换的 TOCTOU；symlink 跟随到目标）。
func ownedBy(path string, uid uint32) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("no stat_t")
	}
	return st.Uid == uid, nil
}

// supplementaryGroups：登录用户 uid 的补充组 gid 列表（纯 Go 解析 /etc/group，CGO 关不含 NSS/SSSD）。
// 用于 setuid 拉核时保留补充组——否则 Credential{Uid,Gid} 默认 setgroups(0) 会清掉补充组，使核读不到 group-only
// 资源（如 ssl-cert 组证书 / 组共享规则文件），而直起路径（保留补充组）能读，造成 mode-specific 破坏。查不到→nil
// （退化为默认 setgroups(0)，不比修前差）。
func supplementaryGroups(uid uint32) []uint32 {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil
	}
	gidStrs, err := u.GroupIds()
	if err != nil {
		return nil
	}
	gids := make([]uint32, 0, len(gidStrs))
	for _, s := range gidStrs {
		if n, e := strconv.ParseUint(s, 10, 32); e == nil {
			gids = append(gids, uint32(n))
		}
	}
	return gids
}

// procUID：/proc/<pid> 的属主 uid（进程运行者）。用于 freeport 跨用户防误杀。
func procUID(pid string) (uint32, error) {
	fi, err := os.Stat(filepath.Join("/proc", pid))
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("no stat_t")
	}
	return st.Uid, nil
}

// IP forwarding: enabled only for an allowLan session; the previous values are saved first and restored when that
// session's child exits on any path (stop, crash, parent-death reap, helper shutdown). fwd=0 never touches it, so a
// host that already forwards (Docker, libvirt) is left alone. Guarded by mu.
var (
	fwdFiles = []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"}
	fwdSaved map[string]string
	fwdOwner *exec.Cmd
)

func enableForwarding() {
	if fwdSaved == nil {
		fwdSaved = map[string]string{}
		for _, f := range fwdFiles {
			if b, err := os.ReadFile(f); err == nil {
				if v := strings.TrimSpace(string(b)); v != "" {
					fwdSaved[f] = v
				}
			}
		}
	}
	for _, f := range fwdFiles {
		_ = os.WriteFile(f, []byte("1"), 0o644)
	}
}

func restoreForwarding() {
	for f, v := range fwdSaved {
		_ = os.WriteFile(f, []byte(v), 0o644)
	}
	fwdSaved, fwdOwner = nil, nil
}

// procStartTime: /proc/<pid>/stat starttime (clock ticks since boot) — a PID's identity across reuse. "" on failure.
func procStartTime(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	return parseProcStatStartTime(string(b))
}

// openLogForCaller opens the early stdout/stderr log for the core. It must sit directly in the config file's
// directory, which must be owned by the caller and not world-writable; the file is opened relative to that
// directory's fd with O_NOFOLLOW (no path re-resolution), must be a regular single-link file owned by the caller,
// and a missing file is created O_EXCL and handed to the caller by fd. An existing file is never chowned.
func openLogForCaller(cfg, logPath string, uid, gid uint32) (*os.File, error) {
	if logPath == "" || !filepath.IsAbs(logPath) || !filepath.IsAbs(cfg) {
		return nil, errors.New("bad log path")
	}
	dir := filepath.Dir(filepath.Clean(cfg))
	if filepath.Dir(filepath.Clean(logPath)) != dir {
		return nil, errors.New("log must be in the config directory")
	}
	name := filepath.Base(filepath.Clean(logPath))
	dfd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dfd)
	var dst syscall.Stat_t
	if err := syscall.Fstat(dfd, &dst); err != nil {
		return nil, err
	}
	if dst.Uid != uid || dst.Mode&0o002 != 0 {
		return nil, errors.New("config directory not owned by the caller")
	}
	flags := syscall.O_WRONLY | syscall.O_APPEND | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	fd, err := syscall.Openat(dfd, name, flags, 0)
	created := false
	if err == syscall.ENOENT {
		fd, err = syscall.Openat(dfd, name, flags|syscall.O_CREAT|syscall.O_EXCL, 0o644)
		created = err == nil
	}
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 {
		syscall.Close(fd)
		return nil, errors.New("log is not a regular single-link file")
	}
	if created {
		if err := syscall.Fchown(fd, int(uid), int(gid)); err != nil {
			syscall.Close(fd)
			return nil, err
		}
	} else if st.Uid != uid {
		syscall.Close(fd)
		return nil, errors.New("log not owned by the caller")
	}
	return os.NewFile(uintptr(fd), logPath), nil
}

func terminateChild(c *exec.Cmd, done <-chan struct{}) {
	if c == nil || c.Process == nil {
		return
	}
	_ = c.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = c.Process.Kill()
	}
}

func watchParent(ppid int, ppidStart string, c *exec.Cmd, done <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		mu.Lock()
		current := child == c
		mu.Unlock()
		if !current {
			return
		}
		// Dead parent: ESRCH, or the PID now belongs to a different process (start time changed → PID reuse).
		// An unreadable start time never counts as dead (no false kills).
		dead := false
		if err := syscall.Kill(ppid, 0); err == syscall.ESRCH {
			dead = true
		} else if err == nil && ppidStart != "" {
			if cur := procStartTime(ppid); cur != "" && cur != ppidStart {
				dead = true
			}
		}
		if dead {
			mu.Lock()
			if child != c {
				mu.Unlock()
				return
			}
			child, childDone = nil, nil
			mu.Unlock()
			terminateChild(c, done)
			return
		}
	}
}

var ssPidRe = regexp.MustCompile(`pid=(\d+)`)

// freePort：按端口找 LISTEN 持有者。**仅作用于对端 uid 自己的进程**（procUID==cred.Uid），是 sing-box 才 kill，
// 否则回报占用者名（不跨用户杀、不杀无辜）。ss 缺失/无占用 → OK free。
func freePort(port string, callerUID uint32) string {
	out, err := exec.Command("ss", "-H", "-ltnp", "sport = :"+port).Output()
	if err != nil {
		return "OK free"
	}
	pids := map[string]bool{}
	for _, m := range ssPidRe.FindAllStringSubmatch(string(out), -1) {
		pids[m[1]] = true
	}
	if len(pids) == 0 {
		return "OK free"
	}
	var killed, foreign []string
	for p := range pids {
		// 跨用户防误杀：非对端 uid 的进程一律不动，回报为 foreign。
		if uid, e := procUID(p); e != nil || uid != callerUID {
			foreign = append(foreign, "pid:"+p)
			continue
		}
		comm := ""
		if b, e := os.ReadFile(filepath.Join("/proc", p, "comm")); e == nil {
			comm = strings.TrimSpace(string(b))
		}
		if strings.Contains(comm, "sing-box") {
			if n, e := strconv.Atoi(p); e == nil {
				_ = syscall.Kill(n, syscall.SIGKILL)
			}
			killed = append(killed, p)
		} else {
			name := comm
			if name == "" {
				name = "pid:" + p
			}
			foreign = append(foreign, name)
		}
	}
	if len(foreign) > 0 {
		return "OK foreign " + strings.Join(foreign, " | ")
	}
	return "OK killed " + strings.Join(killed, ",")
}

func handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	cred, err := peerCred(conn)
	if err != nil || cred == nil {
		fmt.Fprintln(conn, "ERR peercred")
		return
	}
	r := bufio.NewReader(conn)
	cmd := readLine(r)

	switch cmd {
	case "ping":
		fmt.Fprintf(conn, "OK pong uid=%d v%s\n", os.Getuid(), protoVersion)
		return
	case "version":
		fmt.Fprintf(conn, "OK %s\n", protoVersion)
		return
	}

	if !isAuthorized(cred.Uid) {
		fmt.Fprintln(conn, "ERR unauthorized")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	switch cmd {
	case "status":
		if child != nil && child.Process != nil {
			fmt.Fprintf(conn, "OK running %d\n", child.Process.Pid)
		} else {
			fmt.Fprintln(conn, "OK stopped")
		}
	case "stop":
		if child != nil && child.Process != nil {
			pid := child.Process.Pid
			c, done := child, childDone
			child, childDone = nil, nil
			// forwarding is restored by the child's Wait goroutine once it has really exited
			reapWG.Add(1)
			go func() { defer reapWG.Done(); terminateChild(c, done) }()
			fmt.Fprintf(conn, "OK stopped %d\n", pid)
		} else {
			fmt.Fprintln(conn, "OK notrunning")
		}
	case "cleanup":
		if child != nil && child.Process != nil {
			_ = child.Process.Kill()
		}
		child, childDone = nil, nil
		if fwdSaved != nil {
			restoreForwarding()
		}
		_ = exec.Command("pkill", "-9", "-U", strconv.Itoa(int(cred.Uid)), "-f", "sing-box run").Run()
		fmt.Fprintln(conn, "OK cleaned")
	case "freeport":
		port := strings.TrimSpace(readLine(r))
		if port == "" || strings.IndexFunc(port, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			fmt.Fprintln(conn, "ERR bad-port")
			return
		}
		fmt.Fprintln(conn, freePort(port, cred.Uid))
	case "install-core":
		// line2=srcDir, line3=client hash (ignored since v2: a client-supplied hash proves nothing).
		src := readLine(r)
		_ = readLine(r)
		fmt.Fprintln(conn, installCoreFiles(src, coreDir))
	case "core-info":
		h, _ := fileHashCached(coreBin())
		b := normHash(bundledCoreSHA256)
		if b == "" {
			b = "-"
		}
		if h == "" {
			h = "-"
		}
		// optional line2 = the app's bundled-core pin → trusted=1|0|- (0 ⇒ client treats this helper as outdated)
		fmt.Fprintf(conn, "OK bundled=%s core=%s trusted=%s\n", b, h, bundledTrustFlag(coreDir, readLine(r)))
	case "start":
		singbox := strings.TrimSpace(readLine(r))
		cfg := readLine(r)
		logPath := readLine(r)
		fwd := readLine(r)
		ppid, _ := strconv.Atoi(readLine(r))

		if child != nil && child.Process != nil {
			fmt.Fprintf(conn, "OK already %d\n", child.Process.Pid)
			return
		}
		if cfg == "" {
			fmt.Fprintln(conn, "ERR bad-args")
			return
		}
		// 核路径锁：只跑锁定的 root-owned coreDir/sing-box。客户端传的 singbox 必须与之一致（否则拒绝，杜绝
		// 「让 helper 以特权跑任意自有二进制」）。config 必须属于对端 uid（防读别人配置）。
		if filepath.Clean(singbox) != coreBin() {
			fmt.Fprintf(conn, "ERR core-path-denied (want %s)\n", coreBin())
			return
		}
		if _, err := os.Stat(coreBin()); err != nil {
			fmt.Fprintf(conn, "ERR core-missing %v\n", err)
			return
		}
		if ok, e := ownedBy(cfg, cred.Uid); !ok {
			fmt.Fprintf(conn, "ERR config-not-owned %v\n", e)
			return
		}
		var ppidStart string
		if ppid > 0 {
			ppidStart = procStartTime(ppid)
		}
		if fwd == "1" {
			enableForwarding()
		} else if fwdSaved != nil {
			restoreForwarding() // a previous allowLan session's saved state (its child is gone)
		}

		c := exec.Command(coreBin(), "run", "-c", cfg)
		// 降权拉核：setuid/setgid 回对端登录用户 + AmbientCaps 保留 CAP_NET_ADMIN/RAW/BIND_SERVICE 建 TUN/改路由。
		// Go runtime 在 fork 后、execve 前编排 keep-caps→setuid→raise ambient（Go≥1.19；真机验证 ambient 继承，见设计 §13）。
		c.SysProcAttr = &syscall.SysProcAttr{
			// Groups 显式填登录用户补充组：否则默认 setgroups(0) 清掉补充组，核读不到 group-only 资源（见 supplementaryGroups）。
			Credential: &syscall.Credential{
				Uid:    cred.Uid,
				Gid:    cred.Gid,
				Groups: supplementaryGroups(cred.Uid),
			},
			AmbientCaps: []uintptr{capNetAdmin, capNetRaw, capNetBindService},
		}
		var logFile *os.File
		if logPath != "" {
			// v2: never open an arbitrary path as root or chown an existing file (log=/etc/passwd used to hand
			// /etc/passwd to the caller). A refused path only disables the early log.
			if lf, e := openLogForCaller(cfg, logPath, cred.Uid, cred.Gid); e == nil {
				logFile = lf
				c.Stdout = lf
				c.Stderr = lf
			} else {
				fmt.Fprintln(os.Stderr, "start log disabled:", e)
			}
		}
		if err := c.Start(); err != nil {
			if logFile != nil {
				logFile.Close()
			}
			if fwdSaved != nil && fwdOwner == nil {
				restoreForwarding()
			}
			fmt.Fprintf(conn, "ERR start %v\n", err)
			return
		}
		if logFile != nil {
			logFile.Close()
		}
		child = c
		if fwd == "1" {
			fwdOwner = c
		}
		done := make(chan struct{})
		childDone = done
		go func() {
			_ = c.Wait()
			close(done)
			mu.Lock()
			if child == c {
				child, childDone = nil, nil
			}
			// v2: restore forwarding on every exit path (stop, crash, watchParent reap).
			if fwdOwner == c {
				restoreForwarding()
			}
			mu.Unlock()
		}()
		if ppid > 0 {
			go watchParent(ppid, ppidStart, c, done)
		}
		fmt.Fprintf(conn, "OK started %d\n", c.Process.Pid)
	default:
		fmt.Fprintln(conn, "ERR unknown")
	}
}
