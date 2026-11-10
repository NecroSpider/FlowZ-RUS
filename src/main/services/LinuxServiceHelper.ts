/**
 * Linux 提权 helper 管理器（systemd system service）。
 *
 * 解决：Linux TUN 模式每次启停 sing-box（含切节点重启）都弹 pkexec 授权框——根因是 setcap 把能力挂在会被换核/更新
 *       替换的二进制 inode 上（security.capability xattr 随 inode 蒸发）。
 * 方案：一次性把一个 root helper 装成 systemd system service（见 helper-linux/），之后 app 经 SO_PEERCRED 鉴权的
 *       unix socket 零提权驱动 sing-box 启停。helper 收到 start 后 setuid 回**发起的登录用户** + AmbientCaps=
 *       CAP_NET_ADMIN 拉核——能力挂进程 ambient set 不挂文件，故换核/软件更新后**无需再次授权、无需 setcap**。
 *
 * 与 macOS HelperManager 的差异（见 docs/design/flowz-linux-privileged-helper.md）：
 *   - 无 token：Linux 用 SO_PEERCRED（内核背书对端 uid）鉴权，行协议首行即命令、无鉴权行。
 *   - **核在 root-owned 受管目录**（/usr/local/lib/flowz/core，安装时播种、install-core hash 校验更新），与 macOS
 *     受保护目录一致：核不可被普通用户篡改，一份共享、版本一致。helper 只跑锁定 coreDir/sing-box（路径锁）→ 根除
 *     「借 helper 给任意自有二进制赋 CAP_NET_ADMIN」的提权面。换核经 install-core 免密（socket 调用，无 pkexec）。
 *   - config/cache/log 仍按用户在 userData（核以登录用户跑，属主天然对）。
 *
 * 仅 linux 有意义；其余平台所有方法安全降级（supported=false / ready=false）。未装时由 ProxyManager 回退到
 * PlatformPrivilegeService.ensureCapabilities（setcap+pkexec，现状），零回归。
 */

import { spawn } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import type { HelperStatus } from '../../shared/types';
import type { IPrivilegedHelper, HelperStartResult } from './IPrivilegedHelper';
import type { ILogManager } from './LogManager';
import { resourceManager } from './ResourceManager';
import { shq } from '../utils/shell-quote';
import { REPOSITORY_URL } from '../../shared/repository';
import { sha256File } from '../../shared/file-hash';
import coreManifest from '../../shared/core-manifest.json';

const SERVICE_NAME = 'flowz-helper.service';
// 受管安装根（避开 /opt/FlowZ —— 那是 electron-builder deb 的应用目录，混放会与 dpkg 生命周期冲突）。
// FHS：本地管理员安装的软件归 /usr/local。helper 二进制 + root-owned 受管核都在此。
const INSTALL_DIR = '/usr/local/lib/flowz';
const HELPER_DEST = `${INSTALL_DIR}/flowz-helper`;
// root-owned 受管核目录（root:root 0755，普通用户改不动）：安装时播种随包核、install-core hash 校验更新。
// helper 只跑此目录内的 sing-box（路径锁），与 macOS 受保护目录 / Windows 锁定 --singbox 一致。
const CORE_DIR = `${INSTALL_DIR}/core`;
const CORE_BIN = `${CORE_DIR}/sing-box`;
const UNIT_PATH = `/etc/systemd/system/${SERVICE_NAME}`;
const STATE_DIR = '/var/lib/flowz';
const AUTH_FILE = `${STATE_DIR}/authorized-uids`;
const RUNTIME_DIR = '/run/flowz';
const SOCKET_PATH = `${RUNTIME_DIR}/helper.sock`;
// 与 helper-linux protoVersion 对应。proto ≥ MIN_USABLE 即 TUN 功能齐全；MIN_USABLE ≤ proto < EXPECTED → upgradeable
// （温和提示可升级）。v1 起 EXPECTED===MIN，故 upgradeable 恒 false（无历史包袱，尚无更旧可用版本）——**将来 helper 协议
// 加不兼容能力时，须把 EXPECTED_PROTO 提到新版号**，upgradeable 分支才会点亮「可升级」提示（对齐 Windows 同惯例）。
// v2: install-core accepts only trusted cores (compiled-in pin or trusted-hashes written by pkexec), safe start log,
// forwarding restore on every exit, PID-reuse-proof parent watch, core-info. v1 keeps working (upgradeable only).
const EXPECTED_PROTO = 2;
const MIN_USABLE_PROTO = 1;
/** polkit rules installed by the setcap/TUN path (PlatformPrivilegeService.ensureCapabilities); removed on uninstall. */
export const LINUX_POLKIT_RULE_FILES = [
  '/etc/polkit-1/rules.d/49-flowz-resolved.rules',
  '/etc/polkit-1/localauthority/50-local.d/49-flowz-resolved.pkla',
];

/**
 * pkexec argv that runs a user-written script without a TOCTOU window: root copies it into a root-only mktemp file,
 * checks the copy's SHA-256 against the hash computed when it was written, then runs the copy. The script path,
 * hash and interpreter are passed as positional arguments (never interpolated into the command).
 */
export function pkexecVerifiedArgs(
  scriptPath: string,
  sha256: string,
  interpreter: '/bin/sh' | '/bin/bash' = '/bin/sh'
): string[] {
  const cmd =
    'T=$(mktemp /tmp/flowz-root.XXXXXX) || exit 1; cat -- "$1" > "$T"; ' +
    'if [ "$(sha256sum "$T" | cut -d" " -f1)" = "$2" ]; then "$3" "$T"; R=$?; ' +
    'else echo "FlowZ: the elevation script was modified before it ran; aborted" >&2; R=90; fi; ' +
    'rm -f "$T"; exit $R';
  return ['/bin/sh', '-c', cmd, 'flowz-elevated', scriptPath, sha256, interpreter];
}

/** Write a script to a fresh private dir (mkdtemp 0700, exclusive create 0600). Caller removes `dir`. */
export function writePrivateScript(
  name: string,
  script: string
): { dir: string; scriptPath: string; sha256: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-elev-'));
  const scriptPath = path.join(dir, name);
  fs.writeFileSync(scriptPath, script, { mode: 0o600, flag: 'wx' });
  return { dir, scriptPath, sha256: createHash('sha256').update(script).digest('hex') };
}

/** Bundled-core pin of this app version (core-manifest; the Linux release is amd64 only). */
function expectedBundledCoreHash(): string {
  return String((coreManifest.coreBinarySha256 as Record<string, string>).linux || '')
    .replace(/^sha256:/, '')
    .toLowerCase();
}

export class LinuxServiceHelper implements IPrivilegedHelper {
  /** The user declined (or the reinstall failed) the "helper outdated for the bundled core" reinstall this session:
   *  do not prompt again on every (re)start; fall back to the non-helper path instead. */
  private staleReinstallDeclined = false;

  constructor(private logManager?: ILogManager | null) {}

  /** True only when a v2+ helper explicitly reports it would refuse this app's bundled core (helper outdated).
   *  v1 helpers / errors → false. */
  private async bundledCoreUntrusted(): Promise<boolean> {
    try {
      const resp = await this.sendCommand(['core-info', expectedBundledCoreHash()], 3000);
      return /^OK bundled=\S+ core=\S+ trusted=0/.test(resp);
    } catch {
      return false;
    }
  }

  /** Copy the bundled core (+ libcronet.so) to a private temp dir (AppImage mounts are not readable by root) and
   *  install it into the managed core dir over the socket — accepted only if it matches the helper's pin. */
  private async refreshManagedCoreFromBundle(): Promise<{ ok: boolean; error?: string }> {
    let dir: string | null = null;
    try {
      const bundled = resourceManager.getBundledSingBoxPath();
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-core-seed-'));
      fs.copyFileSync(bundled, path.join(dir, 'sing-box'));
      fs.chmodSync(path.join(dir, 'sing-box'), 0o755);
      const lib = path.join(path.dirname(bundled), 'libcronet.so');
      if (fs.existsSync(lib)) fs.copyFileSync(lib, path.join(dir, 'libcronet.so'));
      return await this.installCore(dir);
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    } finally {
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  private log(level: 'info' | 'warn' | 'error', message: string): void {
    this.logManager?.addLog(level, message, 'Helper');
  }

  private get supported(): boolean {
    return process.platform === 'linux';
  }

  // ── socket 客户端（行协议：cmd\n [args...]；鉴权走 SO_PEERCRED，无 token 行）────────────────
  private sendCommand(rest: string[], timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const sock = net.connect(SOCKET_PATH);
      let buf = '';
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error('helper socket timed out'));
      }, timeoutMs);
      sock.on('connect', () => {
        sock.end(rest.join('\n') + '\n');
      });
      sock.on('data', (d) => {
        buf += d.toString();
      });
      sock.on('end', () => {
        clearTimeout(timer);
        resolve(buf.trim());
      });
      sock.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  // ── 状态探测 ─────────────────────────────────────────────────────────────
  private filesPresent(): boolean {
    try {
      return fs.existsSync(HELPER_DEST) && fs.existsSync(UNIT_PATH);
    } catch {
      return false;
    }
  }

  /** 快速判定能否零提权驱动（ProxyManager 启动路由用）。 */
  async isReady(): Promise<boolean> {
    if (!this.supported || !this.filesPresent()) return false;
    try {
      const resp = await this.sendCommand(['ping'], 1500);
      const m = resp.match(/^OK pong uid=\d+ v(\d+)/);
      return !!m && parseInt(m[1], 10) >= MIN_USABLE_PROTO;
    } catch {
      return false;
    }
  }

  /** 完整状态：供设置页展示 + 安装/卸载按钮判态。backgroundDisabled/pathMismatch 为 macOS 专属，Linux 恒默认值。 */
  async getStatus(): Promise<HelperStatus> {
    if (!this.supported) {
      return {
        supported: false,
        installed: false,
        ready: false,
        upgradeable: false,
        version: null,
        loaded: null,
        needsRepair: false,
        backgroundDisabled: false,
        pathMismatch: false,
        installedSingboxPath: null,
      };
    }
    const installed = this.filesPresent();
    let version: string | null = null;
    let ready = false;
    let upgradeable = false;
    let stale = false;
    if (installed) {
      try {
        const resp = await this.sendCommand(['ping'], 1500);
        const m = resp.match(/^OK pong uid=\d+ v(\d+)/);
        if (m) {
          version = m[1];
          const pv = parseInt(version, 10);
          ready = !isNaN(pv) && pv >= MIN_USABLE_PROTO;
          upgradeable = ready && pv < EXPECTED_PROTO;
          // v2+: helper does not trust this app's bundled core → outdated. ready stays true so the next TUN start
          // reaches startCore, which runs the existing reinstall (one pkexec) before starting (see startCore).
          if (ready && pv >= 2 && (await this.bundledCoreUntrusted())) {
            stale = true;
            upgradeable = false;
          }
        }
      } catch {
        /* 未就绪：装了 unit 但 daemon 没起来（如刚 reboot 未起、被 mask）→ needsRepair 引导重装 */
      }
    }
    return {
      supported: true,
      installed,
      ready,
      upgradeable,
      version,
      loaded: installed ? true : null,
      needsRepair: installed && (!ready || stale),
      backgroundDisabled: false,
      pathMismatch: false,
      installedSingboxPath: null,
    };
  }

  // ── sing-box 启停（socket，零提权）────────────────────────────────────────
  /** 经 helper 启动 sing-box（以对端登录用户 + CAP_NET_ADMIN）。singbox 路径由 resourceManager 取——helper 就绪时
   *  getSingBoxPath 返回 root 受管核（coreDir/sing-box）；helper 侧路径锁校验 singbox==coreDir/sing-box、config 属主==对端 uid。 */
  async startCore(
    configPath: string,
    logPath: string,
    forward: boolean
  ): Promise<HelperStartResult> {
    try {
      // The helper does not trust this app's bundled core (app updated with a new core, helper still the old
      // build): starting now would run an older core than the config is generated for. Go through the existing
      // reinstall (one pkexec prompt), then refresh the managed core from the bundle. Declined/failed → report an
      // error so ProxyManager falls back to the non-helper (setcap) path, and do not ask again this session.
      if (await this.bundledCoreUntrusted()) {
        if (this.staleReinstallDeclined) {
          return {
            ok: false,
            error:
              "privileged helper is outdated for this app's bundled core (reinstall declined this session)",
          };
        }
        this.log(
          'warn',
          "Privileged helper is outdated for this app's bundled core: reinstalling it (one administrator prompt)"
        );
        const r = await this.install();
        if (!r.success) {
          this.staleReinstallDeclined = true;
          this.log(
            'warn',
            `Helper reinstall declined or failed (${r.error ?? 'unknown'}); using the non-helper TUN path this session`
          );
          return {
            ok: false,
            error: `helper reinstall declined or failed: ${r.error ?? 'unknown'}`,
          };
        }
        const seeded = await this.refreshManagedCoreFromBundle();
        if (!seeded.ok) {
          return {
            ok: false,
            error: `bundled core refresh after helper reinstall failed: ${seeded.error}`,
          };
        }
      }
      await this.sendCommand(['stop'], 3000).catch(() => ''); // 幂等清残留旧 child
      const singbox = resourceManager.getSingBoxPath();
      const resp = await this.sendCommand(
        ['start', singbox, configPath, logPath || '', forward ? '1' : '0', String(process.pid)],
        8000
      );
      const m = resp.match(/^OK (?:started|already) (\d+)/);
      if (m) return { ok: true, pid: parseInt(m[1], 10) };
      return { ok: false, error: resp || 'no response from helper' };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  async stopCore(): Promise<boolean> {
    try {
      const resp = await this.sendCommand(['stop'], 5000);
      return resp.startsWith('OK');
    } catch {
      return false;
    }
  }

  async cleanup(): Promise<boolean> {
    try {
      const resp = await this.sendCommand(['cleanup'], 5000);
      return resp.startsWith('OK');
    } catch {
      return false;
    }
  }

  async freePort(port: number): Promise<{ freed?: boolean; foreign?: string; error?: string }> {
    try {
      const resp = await this.sendCommand(['freeport', String(port)], 5000);
      if (resp.startsWith('OK free') || resp.startsWith('OK killed')) return { freed: true };
      const m = resp.match(/^OK foreign (.+)/);
      if (m) return { foreign: m[1].trim() };
      return { error: resp || 'no response from helper' };
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) };
    }
  }

  async coreStatus(): Promise<{ running: boolean; pid?: number }> {
    try {
      const resp = await this.sendCommand(['status'], 2000);
      const m = resp.match(/^OK running (\d+)/);
      return m ? { running: true, pid: parseInt(m[1], 10) } : { running: false };
    } catch {
      return { running: false };
    }
  }

  // 出口托管路由 / 停核补默认路由：macOS 专属善后，Linux 暂不需要 → no-op（proto 语义等价旧 helper 的 ERR unknown）。
  async routeAdd(_iface: string, _cidrs: string[]): Promise<{ ok: boolean; error?: string }> {
    return { ok: false, error: 'unsupported' };
  }
  async routeDel(_iface: string, _cidrs: string[]): Promise<{ ok: boolean; error?: string }> {
    return { ok: false, error: 'unsupported' };
  }
  async restoreDefaultRoute(_gateway: string): Promise<{ ok: boolean; error?: string }> {
    return { ok: false, error: 'unsupported' };
  }

  // ── 换核（install-core）──────────────────────────────────────────────────
  /** 经 helper（root）把 srcDir（含 sing-box + libcronet）原子写入锁定的 root 受管核目录。CoreUpdateService 落位时调。
   *  v2 helper: only the bundled core (compiled-in pin) or admin-approved hashes are accepted over the socket (the hash
   *  line is ignored; still sent for v1). An untrusted core → "ERR untrusted-hash …"; only a user-initiated change
   *  (allowElevation) then asks once via pkexec, which installs it and records its hash. Automatic paths never prompt. */
  async installCore(
    srcDir: string,
    opts?: { allowElevation?: boolean }
  ): Promise<{ ok: boolean; error?: string }> {
    try {
      const hash = sha256File(path.join(srcDir, 'sing-box'));
      const resp = await this.sendCommand(['install-core', srcDir, hash], 30_000);
      if (resp.startsWith('OK')) return { ok: true };
      if (/^ERR untrusted-hash/.test(resp) && opts?.allowElevation) {
        this.log(
          'info',
          `Core is not trusted by the helper yet (${resp}); asking for administrator approval`
        );
        return await this.installCoreElevated(srcDir);
      }
      return { ok: false, error: resp };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** One pkexec prompt: copy sing-box (+ libcronet.so) into the managed core dir, verify each copy against the
   *  app-computed hash and add it to trusted-hashes. */
  async installCoreElevated(srcDir: string): Promise<{ ok: boolean; error?: string }> {
    try {
      const items: { name: string; src: string; sha256: string }[] = [];
      for (const name of ['sing-box', 'libcronet.so']) {
        const src = path.join(srcDir, name);
        if (name === 'sing-box' || fs.existsSync(src))
          items.push({ name, src, sha256: sha256File(src) });
      }
      const r = await this.runPkexecScript(
        'flowz-linux-core-install.sh',
        this.buildElevatedCoreInstallScript(items)
      );
      return r.success ? { ok: true } : { ok: false, error: r.error };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  private buildElevatedCoreInstallScript(
    items: { name: string; src: string; sha256: string }[]
  ): string {
    const lines = [
      '#!/bin/sh',
      'set -e',
      'umask 022',
      `COREDIR=${shq(CORE_DIR)}`,
      'AL="$COREDIR/trusted-hashes"',
      'mkdir -p "$COREDIR"',
      'chown root:root "$COREDIR"; chmod 0755 "$COREDIR"',
      '[ -L "$AL" ] && rm -f "$AL"',
      'touch "$AL"; chown root:root "$AL"; chmod 0644 "$AL"',
      'install_one() {',
      '  TMP="$COREDIR/.$1.elevated.new"',
      '  rm -f "$TMP"',
      '  cat -- "$2" > "$TMP"',
      '  GOT=$(sha256sum "$TMP" | cut -d" " -f1)',
      '  if [ "$GOT" != "$3" ]; then rm -f "$TMP"; echo "FlowZ: $1 changed after it was checked; aborted" >&2; exit 4; fi',
      '  chmod 0755 "$TMP"',
      `  grep -qx "$GOT" "$AL" || printf '%s\\n' "$GOT" >> "$AL"`,
      '  mv -f "$TMP" "$COREDIR/$1"',
      '}',
    ];
    for (const it of items) {
      if (!/^(sing-box|libcronet\.so)$/.test(it.name) || !/^[0-9a-f]{64}$/.test(it.sha256)) {
        throw new Error(`refusing to build an elevated install for ${it.name}`);
      }
      lines.push(`install_one ${it.name} ${shq(it.src)} ${it.sha256}`);
    }
    lines.push('echo flowz-core-install-ok', '');
    return lines.join('\n');
  }

  // ── 安装 / 卸载（pkexec 一次授权）─────────────────────────────────────────
  /** 安装/修复 helper：pkexec 以 root 跑安装脚本（拷二进制 + 写授权 uid + 装 systemd unit + enable --now，弹一次密码框）。 */
  async install(): Promise<{ success: boolean; error?: string; status: HelperStatus }> {
    if (!this.supported) {
      return {
        success: false,
        error: 'The systemd helper is only supported on Linux',
        status: await this.getStatus(),
      };
    }
    const srcBinary = resourceManager.getLinuxHelperPath();
    if (!fs.existsSync(srcBinary)) {
      this.log('error', `helper binary missing: ${srcBinary}`);
      return {
        success: false,
        error: 'helper binary missing (not included in this build)',
        status: await this.getStatus(),
      };
    }
    // 授权 uid = 当前登录用户（app 进程 uid）。以 root 跑整 app 时 getuid()===0，helper 侧 root 恒授权。
    const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
    const bundledCore = resourceManager.getBundledSingBoxPath(); // 受管核种子源（随包核）

    const result = await this.runPkexecScript(
      'flowz-linux-helper-install.sh',
      this.buildInstallScript(srcBinary, uid, bundledCore)
    );
    if (!result.success) {
      return { success: false, error: result.error, status: await this.getStatus() };
    }
    // 等 daemon 起来绑定 socket，再确认就绪
    let status = await this.getStatus();
    for (let i = 0; i < 10 && !status.ready; i++) {
      await new Promise((r) => setTimeout(r, 300));
      status = await this.getStatus();
    }
    if (status.ready) this.log('info', 'helper installed and ready');
    else this.log('warn', 'helper installed but did not become ready in time');
    return { success: true, status };
  }

  /** 卸载 helper：pkexec 以 root 停服务 + 删 unit / 二进制 / 授权文件 / 运行目录（弹一次密码框）。 */
  async uninstall(): Promise<{ success: boolean; error?: string; status: HelperStatus }> {
    if (!this.supported) {
      return {
        success: false,
        error: 'The systemd helper is only supported on Linux',
        status: await this.getStatus(),
      };
    }
    const result = await this.runPkexecScript(
      'flowz-linux-helper-uninstall.sh',
      this.buildUninstallScript()
    );
    if (!result.success) {
      return { success: false, error: result.error, status: await this.getStatus() };
    }
    this.log('info', 'helper uninstalled');
    return { success: true, status: await this.getStatus() };
  }

  // ── 脚本生成 ─────────────────────────────────────────────────────────────
  private buildUnit(): string {
    // helper 本体以 root 跑（无 User=）：需 root 才能 setuid 拉 child + 穿越登录用户 userData 校验/重定向。child 的
    // CAP_NET_ADMIN 由 helper 代码经 SysProcAttr.AmbientCaps 赋予（不在 unit 层）。CapabilityBoundingSet 收紧留待
    // 真机验证后加（P3；过早收紧易踩 setuid/chown/dac_override 缺失）。singbox/authfile 路径不烧进 unit（多用户）。
    return `[Unit]
Description=FlowZ privileged network helper
Documentation=${REPOSITORY_URL}
After=network.target

[Service]
Type=simple
ExecStart=${HELPER_DEST} --socket=${SOCKET_PATH} --authfile=${AUTH_FILE} --coredir=${CORE_DIR}
RuntimeDirectory=flowz
RuntimeDirectoryMode=0755
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`;
  }

  private buildInstallScript(srcBinary: string, uid: number, bundledCore: string): string {
    // 单脚本一次 pkexec：拷 helper 二进制 → 播种 root 受管核（仅当尚无核，重装/修复不覆盖已 install-core 更新的核）
    // → 授权 uid **合并追加**（不覆写：多用户各自装/修复不互相抹掉授权）→ 装 unit → daemon-reload → enable --now。
    // uid 已是数字，安全内插。libcronet 若随包（naive 出站需）随核一并播种。
    const bundledDir = path.dirname(bundledCore);
    const bundledCronet = path.join(bundledDir, 'libcronet.so');
    return `#!/bin/sh
set -e
install -D -o root -g root -m 0755 ${shq(srcBinary)} ${shq(HELPER_DEST)}
mkdir -p ${shq(CORE_DIR)}
chown root:root ${shq(CORE_DIR)}
chmod 0755 ${shq(CORE_DIR)}
if [ ! -x ${shq(CORE_BIN)} ]; then
  install -o root -g root -m 0755 ${shq(bundledCore)} ${shq(CORE_BIN)}
  [ -f ${shq(bundledCronet)} ] && install -o root -g root -m 0755 ${shq(bundledCronet)} ${shq(CORE_DIR + '/libcronet.so')} || true
fi
mkdir -p ${shq(STATE_DIR)}
chmod 0755 ${shq(STATE_DIR)}
touch ${shq(AUTH_FILE)}
chmod 0644 ${shq(AUTH_FILE)}
grep -qxF '${uid}' ${shq(AUTH_FILE)} || printf '%s\\n' '${uid}' >> ${shq(AUTH_FILE)}
cat > ${shq(UNIT_PATH)} <<'FLOWZ_UNIT_EOF'
${this.buildUnit()}FLOWZ_UNIT_EOF
chmod 0644 ${shq(UNIT_PATH)}
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
# restart (not just enable --now): an already-running older helper must be replaced by the new binary now,
# otherwise a helper upgrade only takes effect after reboot.
systemctl restart ${SERVICE_NAME}
echo flowz-helper-install-ok
`;
  }

  private buildUninstallScript(): string {
    // 对称清理：停服务 + 删 unit + 删受管安装根（helper 二进制 + root 核）+ 状态/运行目录。INSTALL_DIR 是 flowz 专属
    // 目录（/usr/local/lib/flowz），整删安全，不碰 deb 的 /opt/FlowZ。
    return `#!/bin/sh
systemctl disable --now ${SERVICE_NAME} 2>/dev/null || true
rm -f ${shq(UNIT_PATH)}
rm -rf ${shq(INSTALL_DIR)} ${shq(STATE_DIR)} ${shq(RUNTIME_DIR)}
# resolve1 DNS polkit rule from the TUN setup (reinstalled on demand by ensureCapabilities if still needed)
rm -f ${LINUX_POLKIT_RULE_FILES.map(shq).join(' ')}
systemctl daemon-reload 2>/dev/null || true
echo flowz-helper-uninstall-ok
`;
  }

  /** pkexec 以 root 执行（弹一次密码框）。区分取消/无认证代理(126)与命令缺失(127)。
   *  Item-8 hardening: fresh mkdtemp dir + exclusive create (no fixed name in userData), and root runs a verified
   *  root-only copy (pkexecVerifiedArgs), so rewriting the file during the prompt does not change what runs. */
  private runPkexecScript(
    name: string,
    script: string
  ): Promise<{ success: boolean; error?: string }> {
    return new Promise((resolve) => {
      let w: { dir: string; scriptPath: string; sha256: string };
      try {
        w = writePrivateScript(name, script);
      } catch (e) {
        resolve({ success: false, error: e instanceof Error ? e.message : String(e) });
        return;
      }
      const proc = spawn('/usr/bin/pkexec', pkexecVerifiedArgs(w.scriptPath, w.sha256));
      let stderr = '';
      proc.stderr?.on('data', (d) => {
        stderr += d.toString();
      });
      proc.on('exit', (code) => {
        try {
          fs.rmSync(w.dir, { recursive: true, force: true });
        } catch {
          /* 忽略 */
        }
        if (code === 0) resolve({ success: true });
        else if (code === 126)
          resolve({
            success: false,
            error: 'Authorization was cancelled, or no polkit authentication agent is available',
          });
        else if (code === 127)
          resolve({ success: false, error: 'pkexec (polkit) is not installed' });
        else resolve({ success: false, error: stderr.trim() || `pkexec exit code ${code}` });
      });
      proc.on('error', (err) => {
        resolve({ success: false, error: err.message });
      });
    });
  }
}
