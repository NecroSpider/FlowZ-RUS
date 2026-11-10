/**
 * Windows 提权服务客户端（对齐 macOS HelperManager，实现 IPrivilegedHelper）。
 *
 * 解决：未签名应用在 TUN 模式下每次启停 sing-box（含切节点重启）都弹 UAC。
 * 方案：一次性安装一个 LocalSystem Windows 服务（Go 二进制，见 helper-win/），之后普通用户 app 经 token 鉴权的
 *       命名管道零提权驱动 sing-box 启停——切节点/停止/退出/崩溃回收均免再次 UAC。
 *
 * 仅 Windows 有意义；其余平台所有方法安全降级（supported=false / ready=false）。
 * 未安装时由 ProxyManager 回退到 buildWindowsUacLaunchCommand（每次 UAC）。
 *
 * 与 macOS HelperManager 的对应（协议/行协议/token 语义一致，便于共用上层逻辑）：
 *   launchd daemon → Windows 服务（SCM, LocalSystem, start=auto）
 *   unix socket    → 命名管道 \\.\pipe\flowz-helper（ACL：SYSTEM + 交互用户；token 为主鉴权边界）
 *   osascript 授权 → UAC（Start-Process -Verb RunAs）
 *   命令集取子集：ping/version/status/start/stop/cleanup/freeport（无 macOS 专属 install-core）。
 *
 * 服务 start=auto 常驻 → app 全程只对管道发命令、不 start/stop 服务 → 普通用户起核只依赖管道 ACL，
 * 不依赖给普通用户授 SCM 权限（核心卖点的去风险点）。
 */
import { execFile } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import { system32, powershellPath } from '../utils/win-system32';
import * as os from 'os';
import * as path from 'path';
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'crypto';
import type { HelperStatus } from '../../shared/types';
import type { ILogManager } from './LogManager';
import type { IPrivilegedHelper, HelperStartResult } from './IPrivilegedHelper';
import { resourceManager } from './ResourceManager';
import { getUserDataPath } from '../utils/paths';
import { sha256File } from '../../shared/file-hash';
import coreManifest from '../../shared/core-manifest.json';

/** SCM 服务名。 */
const SERVICE_NAME = 'FlowZHelper';
/** 命名管道路径（与 helper-win 默认一致）。Node net.connect 支持 \\.\pipe\ 形式。 */
const PIPE_PATH = '\\\\.\\pipe\\flowz-helper';
/** SYSTEM 侧支持目录：服务以 LocalSystem 读 helper.token；安装时 elevated 写入并设 ACL（SYSTEM + Administrators）。 */
const SUPPORT_DIR = path.join(process.env.ProgramData || 'C:\\ProgramData', 'FlowZ');
/**
 * icacls 授权主体用**众所周知 SID**（`*S-…`），不用账户名：账户名随系统语言本地化（ru「Администраторы」/「СИСТЕМА」、
 * de「Administratoren」…），英文名在非英文 Windows 上 icacls 报「无法映射账户名」→ 授权失败，而前一步 /inheritance:r
 * 已清空继承 ACE → 目录 DACL 为空、连 Admin 都进不去（真机：ru Windows「Отказано в доступе по пути …helper.token」）。
 */
const SID_SYSTEM = '*S-1-5-18';
const SID_ADMINISTRATORS = '*S-1-5-32-544';
/** sc query 不存在服务时的退出码（ERROR_SERVICE_DOES_NOT_EXIST）。 */
const ERROR_SERVICE_DOES_NOT_EXIST = 1060;
/** 与 helper-win 的 protoVersion 对应。Windows 独立谱系：v1 = ping/version/status/start/stop/cleanup/freeport。 */
const MIN_USABLE_PROTO = 1;
// Windows 禁 System（强制 gVisor）后，客户端只用 v1 命令：iface-metric（v3–v5）已删；route-add/del（v2）仅
// MeshExitRouteManager 调用，而其 win32 路径已 no-op 不可达。故期望 proto 降回 MIN_USABLE_PROTO → 不再对 v1–v4
// 旧 helper 弹「可升级」提示（那些高 proto 能力 Windows 已不调用）。将来若 Windows 重新启用 route 命令再上调。
// v6 (security): AUTH2 HMAC pipe auth, SYSTEM core only from the protected <SUPPORT_DIR>\core with core trust,
// config policy, safe log, IPEnableRouter restore. Older services keep working (TUN unaffected) but the user-writable
// core they run as SYSTEM is the reason v6 exists → EXPECTED raised so v1–v5 show the mild "upgrade" prompt.
const EXPECTED_PROTO = 6;
/** First proto with AUTH2, install-core / core-info and the protected core. */
const TRUST_PROTO = 6;
/** Protected core dir the v6 service runs the core from (inherits SUPPORT_DIR's SYSTEM/Administrators-only ACL). */
const CORE_DIR = path.join(SUPPORT_DIR, 'core');
/** Client-side marker: the installed service speaks AUTH2 → never send the token in clear again. */
const AUTH_MARKER = 'hmac1';

// ── AUTH2 (must match helper-win/auth.go; cross-checked by shared test vectors) ──────────────────────────
export function authServerProof(token: string, nc: string, ns: string): string {
  return createHmac('sha256', token).update(`flowz-helper-server\n${nc}\n${ns}`).digest('hex');
}
export function authClientProof(token: string, nc: string, ns: string, lines: string[]): string {
  return createHmac('sha256', token)
    .update(`flowz-helper-client\n${nc}\n${ns}\n${lines.join('\n')}`)
    .digest('hex');
}
/** Verify the server's "CHAL <ns> <proof>" line; returns ns when the server proved it knows the token. */
export function parseAuthChallenge(token: string, nc: string, line: string): string | null {
  const m = line.trim().match(/^CHAL ([0-9a-f]{32}) ([0-9a-f]{64})$/);
  if (!m) return null;
  const want = Buffer.from(authServerProof(token, nc, m[1]), 'hex');
  const got = Buffer.from(m[2], 'hex');
  return got.length === want.length && timingSafeEqual(got, want) ? m[1] : null;
}
/** The authenticated request: "<clientProof> <n>\n" + the n request lines. */
export function buildAuthRequest(token: string, nc: string, ns: string, lines: string[]): string {
  if (lines.some((l) => l.includes('\n'))) throw new Error('request line contains a newline');
  return `${authClientProof(token, nc, ns, lines)} ${lines.length}\n${lines.join('\n')}\n`;
}

/** Bundled-core hash this app version expects the service to carry (core-manifest pin). */
function expectedBundledCoreHash(): string {
  return String((coreManifest.coreBinarySha256 as Record<string, string>).win || '')
    .replace(/^sha256:/, '')
    .toLowerCase();
}

let activeInstance: WindowsServiceHelper | null = null;
/** The Windows helper the app constructed (CoreUpdateService uses it to sync the protected core after an update). */
export function getActiveWindowsServiceHelper(): WindowsServiceHelper | null {
  return activeInstance;
}

export class WindowsServiceHelper implements IPrivilegedHelper {
  /** 装/卸互斥期返回最近稳定快照，避免 TOCTOU 半态（对齐 HelperManager.lastStableStatus）。 */
  private lastStableStatus: HelperStatus | null = null;
  private mutationInFlight = false;
  /** Pipe path (overridable in tests only). */
  protected pipePath = PIPE_PATH;
  /** sha256 cache of the app's active core (path → size/mtime/hash) for the per-start protected-core sync. */
  private activeHashCache: { path: string; size: number; mtimeMs: number; hash: string } | null =
    null;
  /** Active-core hash the service already refused as untrusted (no point re-sending it on every start). */
  private refusedCoreHash: string | null = null;
  /** "service does not trust the bundled core" warning logged once per process. */
  private staleLogged = false;

  constructor(private logManager?: ILogManager | null) {
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- module-level handle for CoreUpdateService (see getActiveWindowsServiceHelper)
    activeInstance = this;
  }

  private log(level: 'info' | 'warn' | 'error', message: string): void {
    this.logManager?.addLog(level, message, 'Helper');
  }

  private get supported(): boolean {
    return process.platform === 'win32';
  }

  private notSupportedStatus(): HelperStatus {
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

  // ── token（app 侧客户端副本，与服务侧 helper.token 同值）─────────────────
  // 独立成文件（非 UserConfig 字段）：渲染端整体回写 config.json 时碰不到它，杜绝竞态（对齐 HelperManager）。
  private tokenFilePath(): string {
    return path.join(getUserDataPath(), 'helper-client.token');
  }

  protected token(): string {
    try {
      return fs.readFileSync(this.tokenFilePath(), 'utf8').trim();
    } catch {
      return '';
    }
  }

  private authMarkerPath(): string {
    return path.join(getUserDataPath(), 'helper-client.auth');
  }

  /** True once the installed service is known to speak AUTH2: the token is then never sent in clear. */
  private authMode(): boolean {
    try {
      return fs.readFileSync(this.authMarkerPath(), 'utf8').trim() === AUTH_MARKER;
    } catch {
      return false;
    }
  }

  private setAuthMode(on: boolean): void {
    try {
      if (on) fs.writeFileSync(this.authMarkerPath(), AUTH_MARKER);
      else fs.unlinkSync(this.authMarkerPath());
    } catch {
      /* best-effort */
    }
  }

  /** v6 service: switch this client to AUTH2 for good once an AUTH2 ping succeeds (no downgrade afterwards). */
  private async upgradeAuthMode(): Promise<boolean> {
    if (this.authMode()) return true;
    try {
      const resp = await this.sendCommandAuth2(['ping'], 1500);
      if (/^OK pong /.test(resp)) {
        this.setAuthMode(true);
        return true;
      }
    } catch {
      /* not an AUTH2 service (yet) */
    }
    return false;
  }

  // ── 命名管道客户端（行协议：token\n cmd\n [args...]，与 helper.go/HelperManager 同款）────────
  // protected 而非 private：便于单测注入脚本化应答覆盖 startCore 的重试/旧核残留守卫（真管道不可单测）。
  // v6: AUTH2 once the marker says the service supports it (the token never crosses the pipe, see helper-win/auth.go);
  // legacy token line only for services installed by older app versions.
  protected sendCommand(rest: string[], timeoutMs: number): Promise<string> {
    return this.authMode()
      ? this.sendCommandAuth2(rest, timeoutMs)
      : this.sendCommandLegacy(rest, timeoutMs);
  }

  /** AUTH2: the server must prove knowledge of the token before the request (MAC-bound to both nonces) is sent. */
  protected sendCommandAuth2(rest: string[], timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const token = this.token();
      if (!token) {
        reject(new Error('no helper token'));
        return;
      }
      const nc = randomBytes(16).toString('hex');
      const sock = net.connect(this.pipePath);
      let buf = '';
      let authed = false;
      let settled = false;
      const finish = (err: Error | null, value?: string): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) reject(err);
        else resolve(value ?? '');
      };
      const timer = setTimeout(() => {
        sock.destroy();
        finish(new Error('helper pipe timed out'));
      }, timeoutMs);
      sock.on('connect', () => {
        sock.write(`AUTH2 ${nc}\n`);
      });
      sock.on('data', (d) => {
        buf += d.toString();
        if (authed) return;
        const nl = buf.indexOf('\n');
        if (nl < 0) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        const ns = parseAuthChallenge(token, nc, line);
        if (!ns) {
          sock.destroy();
          finish(
            new Error(
              line.startsWith('ERR')
                ? `helper rejected authentication: ${line.trim()}`
                : 'helper pipe server failed authentication'
            )
          );
          return;
        }
        authed = true;
        try {
          sock.write(buildAuthRequest(token, nc, ns, rest));
        } catch (e) {
          sock.destroy();
          finish(e instanceof Error ? e : new Error(String(e)));
        }
      });
      sock.on('end', () => {
        if (!authed)
          finish(new Error(buf.trim() || 'helper closed the pipe during authentication'));
        else finish(null, buf.trim());
      });
      sock.on('error', (err) => finish(err));
    });
  }

  protected sendCommandLegacy(rest: string[], timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const sock = net.connect(this.pipePath);
      let buf = '';
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error('helper pipe timed out'));
      }, timeoutMs);
      sock.on('connect', () => {
        sock.write([this.token(), ...rest].join('\n') + '\n');
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

  // ── SCM 状态探测 ─────────────────────────────────────────────────────────
  /** sc query：服务是否存在 + 是否 RUNNING。不存在（exit 1060）→ {exists:false}。 */
  private queryService(): Promise<{ exists: boolean; running: boolean }> {
    return new Promise((resolve) => {
      execFile(
        system32('sc.exe'),
        ['query', SERVICE_NAME],
        { timeout: 4000, windowsHide: true },
        (err, stdout) => {
          const code = (err as { code?: number } | null)?.code;
          if (code === ERROR_SERVICE_DOES_NOT_EXIST) {
            return resolve({ exists: false, running: false });
          }
          const out = stdout || '';
          // 存在：无错误，或输出含 SERVICE_NAME 段（1060 以外的瞬时错误时尽量按存在处理，宁误判存在不误判缺失）
          const exists = !err || /SERVICE_NAME/i.test(out);
          const running = /STATE\s*:\s*\d+\s+RUNNING/i.test(out);
          resolve({ exists, running });
        }
      );
    });
  }

  /** 快速判定能否零提权驱动（ProxyManager 启动路由用）。 */
  async isReady(): Promise<boolean> {
    if (!this.supported || !this.token()) return false;
    try {
      const resp = await this.sendCommand(['ping'], 1500);
      const m = resp.match(/^OK pong uid=-?\d+ v(\d+)/);
      if (!m) return false;
      const pv = parseInt(m[1], 10);
      if (pv < MIN_USABLE_PROTO) return false;
      // outdated v6+ service (does not trust this app's bundled core) → not ready: never run an older core silently
      return !(pv >= TRUST_PROTO && (await this.bundledCoreUntrusted()));
    } catch {
      return false;
    }
  }

  /** 完整状态：供设置页展示 + 安装/卸载按钮判态。装/卸互斥期返回最近稳定快照。 */
  async getStatus(force = false): Promise<HelperStatus> {
    if (this.mutationInFlight && this.lastStableStatus) return this.lastStableStatus;
    const s = await this.computeStatus(force);
    if (this.mutationInFlight && this.lastStableStatus) return this.lastStableStatus;
    this.lastStableStatus = s;
    return s;
  }

  private async computeStatus(_force = false): Promise<HelperStatus> {
    if (!this.supported) return this.notSupportedStatus();
    const { exists: installed, running } = await this.queryService();
    let version: string | null = null;
    let ready = false;
    let upgradeable = false;
    if (installed && this.token()) {
      try {
        const resp = await this.sendCommand(['ping'], 1500);
        const m = resp.match(/^OK pong uid=-?\d+ v(\d+)/);
        if (m) {
          version = m[1];
          const pv = parseInt(version, 10);
          ready = !isNaN(pv) && pv >= MIN_USABLE_PROTO;
          upgradeable = ready && pv < EXPECTED_PROTO;
          if (ready && pv >= TRUST_PROTO) {
            await this.upgradeAuthMode();
            // The service does not trust THIS app's bundled core (built for an older one, hash not admin-approved):
            // it would keep running an older core than the config is generated for → treat as outdated
            // (not ready + needsRepair → the existing repair gate, one UAC; "Use UAC" falls back as today).
            if (await this.bundledCoreUntrusted()) {
              ready = false;
              upgradeable = false;
            }
          }
        }
      } catch {
        /* 未就绪 */
      }
    }
    return {
      supported: true,
      installed,
      ready,
      upgradeable,
      version,
      // SCM RUNNING 即「已加载」；未安装为 null（对齐 HelperManager.loaded 语义）。
      loaded: installed ? running : null,
      needsRepair: installed && !ready,
      // 以下为 macOS 专属字段，Windows 恒默认值（消费方契约：先判 backgroundDisabled 再判 needsRepair）。
      backgroundDisabled: false,
      // 已知限制（待真机/后续）：Windows 核更新（Portable 模式写 userData/core_update）后，服务 binPath
      // 仍指向安装时锁定的 sing-box，此处不检测漂移（恒 false）→ 不触发修复 gate。后续可比对服务 ImagePath 的 --singbox
      // 段 vs 当前 getSingBoxPath() 实现之；当前 Windows 核更新走 app 侧、非 helper，影响有限。
      pathMismatch: false,
      installedSingboxPath: null,
    };
  }

  // ── sing-box 启停（管道，零提权）──────────────────────────────────────────
  /** 经服务以 SYSTEM 启动 sing-box（已提权，无内层 UAC）。行6=父 app PID（父死看护）。 */
  async startCore(
    configPath: string,
    logPath: string,
    forward: boolean
  ): Promise<HelperStartResult> {
    try {
      // 先停旧核，并**确认**停成功：重试瞬态管道失败。不确认会踩这个坑——stop 静默失败（旧核仍在），
      // 随后 start 被 helper 判为「OK already <旧pid>」，被误读成「以新配置启动成功」，而实际跑的还是旧核。
      let stopped = false;
      for (let i = 0; i < 3 && !stopped; i++) {
        if (i > 0) await new Promise((r) => setTimeout(r, 100));
        const resp = await this.sendCommand(['stop'], 3000).catch(() => '');
        stopped = resp.startsWith('OK');
      }
      // 管道实例生命周期抖动缓冲：给服务侧断开并重新排队 ConnectNamedPipe 留出短延时
      await new Promise((r) => setTimeout(r, 60));
      // v6: the service runs only its protected copy. Bring it in line with the app's active core when that core is
      // trusted (bundled / admin-approved) — silent, never prompts; an unapproved core just keeps the protected one.
      await this.syncProtectedCore().catch(() => undefined);
      let reseeded = false;
      for (let attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) await new Promise((r) => setTimeout(r, 100));
        try {
          const resp = await this.sendCommand(
            ['start', configPath, logPath || '', forward ? '1' : '0', String(process.pid)],
            8000
          );
          // v6: protected core missing/untrusted and the install-time bundle path is gone (portable / moved):
          // re-seed it from the current bundle (accepted only if it hashes to the service's pin), then retry.
          if (!reseeded && /^ERR core-(missing|untrusted)/.test(resp)) {
            reseeded = true;
            this.log(
              'warn',
              `Helper refused the protected core (${resp}); re-seeding the bundled core`
            );
            const r = await this.reseedBundledCore();
            if (!r.ok) return { ok: false, error: `${resp} (re-seed: ${r.error ?? 'failed'})` };
            attempt--;
            continue;
          }
          const m = resp.match(/^OK (?:started|already) (\d+)/);
          if (m) {
            // stop 未确认 + helper 报 already ⇒ 这个 pid 极可能是没被杀掉的旧核（非本次新配置）→ 如实报失败，
            // 不用「OK already」冒充成功。stop 确认过时 already 只可能来自本循环前一次尝试，属正常重连。
            if (!stopped && /^OK already/.test(resp)) {
              return {
                ok: false,
                error:
                  'helper did not confirm stopping the old core (a stale core may remain); not reporting this start as successful',
              };
            }
            return { ok: true, pid: parseInt(m[1], 10) };
          }
          if (resp && resp.startsWith('ERR')) {
            return { ok: false, error: resp };
          }
        } catch {
          /* 瞬态管道重连异常，在循环内重试 */
        }
      }
      return { ok: false, error: 'no response from helper' };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** 经服务停止 sing-box（SYSTEM），零提权。 */
  async stopCore(): Promise<boolean> {
    try {
      const resp = await this.sendCommand(['stop'], 5000);
      return resp.startsWith('OK');
    } catch {
      return false;
    }
  }

  /** v6 core-info: compiled-in bundled hash + protected core hash (null on older services / errors). */
  private async coreInfo(): Promise<{
    bundled: string;
    core: string;
    trusted: boolean | null;
  } | null> {
    try {
      // line3 = this app's bundled-core pin (always sent: a legacy-mode request must not leave the server waiting)
      const resp = await this.sendCommand(['core-info', expectedBundledCoreHash()], 5000);
      const m = resp.match(/^OK bundled=(\S+) core=(\S+)(?: trusted=([01-]))?/);
      if (!m) return null;
      const norm = (v: string): string => (v === '-' ? '' : v.toLowerCase());
      const trusted = m[3] === '1' ? true : m[3] === '0' ? false : null;
      return { bundled: norm(m[1]), core: norm(m[2]), trusted };
    } catch {
      return null;
    }
  }

  /** True only when a v6+ service explicitly reports it would refuse this app's bundled core (service outdated).
   *  Unknown/unreachable → false (a transient error never becomes a prompt). */
  private async bundledCoreUntrusted(): Promise<boolean> {
    const info = await this.coreInfo();
    if (info?.trusted !== false) return false;
    if (!this.staleLogged) {
      this.staleLogged = true;
      this.log(
        'warn',
        `Installed helper service does not trust this app's bundled core (service pin ${info.bundled || '-'}); treating it as outdated → repair needed (one UAC prompt)`
      );
    }
    return true;
  }

  private activeCoreHash(p: string): string {
    const st = fs.statSync(p);
    const c = this.activeHashCache;
    if (c && c.path === p && c.size === st.size && c.mtimeMs === st.mtimeMs) return c.hash;
    const hash = sha256File(p);
    this.activeHashCache = { path: p, size: st.size, mtimeMs: st.mtimeMs, hash };
    return hash;
  }

  /**
   * v6: copy the app's active core (userData core_update or bundled) into the service's protected dir when it
   * differs. The service accepts it over the pipe only if trusted; otherwise, only for a user-initiated core change
   * (allowElevation), one UAC prompt installs it and records its hash. Never prompts from connect/start.
   */
  async syncProtectedCore(opts?: {
    allowElevation?: boolean;
  }): Promise<{ ok: boolean; error?: string }> {
    if (!this.supported) return { ok: false, error: 'unsupported' };
    const info = await this.coreInfo();
    if (!info) return { ok: false, error: 'helper does not support core sync (proto < 6)' };
    const active = resourceManager.getSingBoxPath();
    const want = this.activeCoreHash(active);
    if (info.core === want) return { ok: true };
    if (!opts?.allowElevation && this.refusedCoreHash === want) {
      return { ok: false, error: 'active core is not approved for the helper' };
    }
    const r = await this.installCore(path.dirname(active), opts);
    if (!r.ok && /untrusted-hash/.test(r.error ?? '')) {
      this.refusedCoreHash = want;
      this.log(
        'warn',
        'The active core is not approved for the privileged service; TUN keeps using the previously installed core (re-apply the core update to approve it)'
      );
    } else if (r.ok) {
      this.refusedCoreHash = null;
    }
    return r;
  }

  /** Re-seed the protected core from the app's bundled core dir (accepted only if it matches the service's pin). */
  private async reseedBundledCore(): Promise<{ ok: boolean; error?: string }> {
    try {
      return await this.installCore(path.dirname(resourceManager.getBundledSingBoxPath()));
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** v6 install-core over the pipe (trusted binaries only); allowElevation → UAC fallback for an untrusted core. */
  async installCore(
    srcDir: string,
    opts?: { allowElevation?: boolean }
  ): Promise<{ ok: boolean; error?: string }> {
    try {
      const resp = await this.sendCommand(['install-core', srcDir, ''], 30_000);
      if (resp.startsWith('OK')) return { ok: true };
      if (/^ERR untrusted-hash/.test(resp) && opts?.allowElevation) {
        this.log(
          'info',
          `Core is not trusted by the service yet (${resp}); asking for UAC approval`
        );
        return await this.installCoreElevated(srcDir);
      }
      return { ok: false, error: resp || 'no response from helper' };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** One UAC prompt: the elevated script reads each file once, refuses it unless it still has the hash the app
   *  computed, writes it into the protected core dir and appends the hash to trusted-hashes. */
  async installCoreElevated(srcDir: string): Promise<{ ok: boolean; error?: string }> {
    try {
      const items: { name: string; src: string; sha256: string }[] = [];
      for (const name of ['sing-box.exe', 'libcronet.dll']) {
        const src = path.join(srcDir, name);
        if (name === 'sing-box.exe' || fs.existsSync(src))
          items.push({ name, src, sha256: sha256File(src) });
      }
      const r = await this.runElevatedPowerShell(this.buildElevatedCoreInstallScript(items));
      if (r.success) this.refusedCoreHash = null;
      return r.success ? { ok: true } : { ok: false, error: r.error };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  private buildElevatedCoreInstallScript(
    items: { name: string; src: string; sha256: string }[]
  ): string {
    const lines = [
      `$core = '${this.psq(CORE_DIR)}'`,
      'New-Item -ItemType Directory -Force -Path $core | Out-Null',
      "$al = Join-Path $core 'trusted-hashes'",
      'function Install-One([string]$name, [string]$src, [string]$want) {',
      '  $bytes = [System.IO.File]::ReadAllBytes($src)',
      '  $sha = [System.Security.Cryptography.SHA256]::Create()',
      "  $got = ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()",
      '  if ($got -ne $want) { throw "$name changed after it was checked; aborted" }',
      "  $tmp = Join-Path $core ('.' + $name + '.elevated.new')",
      '  [System.IO.File]::WriteAllBytes($tmp, $bytes)',
      '  $dst = Join-Path $core $name',
      '  if (Test-Path -LiteralPath $dst) {',
      "    try { [System.IO.File]::Delete($dst) } catch { [System.IO.File]::Move($dst, $dst + '.old-' + [guid]::NewGuid().ToString('N')) }",
      '  }',
      '  [System.IO.File]::Move($tmp, $dst)',
      '  $have = @()',
      '  if (Test-Path -LiteralPath $al) { $have = @(Get-Content -LiteralPath $al) }',
      '  if ($have -notcontains $got) { Add-Content -LiteralPath $al -Value $got -Encoding ascii }',
      '}',
    ];
    for (const it of items) {
      if (!/^(sing-box\.exe|libcronet\.dll)$/.test(it.name) || !/^[0-9a-f]{64}$/.test(it.sha256)) {
        throw new Error(`refusing to build an elevated install for ${it.name}`);
      }
      lines.push(`Install-One '${it.name}' '${this.psq(it.src)}' '${it.sha256}'`);
    }
    return lines.join('\n');
  }

  /** 经服务(SYSTEM)在内核接口装/删路由（出口托管）。proto<2 旧服务回 ERR unknown → {ok:false}。 */
  async routeAdd(iface: string, cidrs: string[]): Promise<{ ok: boolean; error?: string }> {
    return this.route('route-add', iface, cidrs);
  }
  async routeDel(iface: string, cidrs: string[]): Promise<{ ok: boolean; error?: string }> {
    return this.route('route-del', iface, cidrs);
  }
  private async route(
    cmd: 'route-add' | 'route-del',
    iface: string,
    cidrs: string[]
  ): Promise<{ ok: boolean; error?: string }> {
    if (!cidrs.length) return { ok: true };
    try {
      const resp = await this.sendCommand([cmd, iface, cidrs.join(',')], 5000);
      return resp.startsWith('OK') ? { ok: true } : { ok: false, error: resp.trim() };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** No-op：sing-tun setRoutes EEXIST 误删 en0 全局 default 的 bug 仅 macOS，Windows 不需要补回默认路由。 */
  async restoreDefaultRoute(_gateway: string): Promise<{ ok: boolean; error?: string }> {
    return { ok: true };
  }

  /** 经服务杀掉所有 sing-box（含孤儿），零提权。 */
  async cleanup(): Promise<boolean> {
    try {
      const resp = await this.sendCommand(['cleanup'], 5000);
      return resp.startsWith('OK');
    } catch {
      return false;
    }
  }

  /** 经服务按端口清占用者：是 sing-box 才杀，否则回报 foreign（不杀无辜，对齐 macOS v4）。 */
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

  /** 服务当前是否在托管一个 sing-box（孤儿探测）。 */
  async coreStatus(): Promise<{ running: boolean; pid?: number }> {
    try {
      const resp = await this.sendCommand(['status'], 2000);
      const m = resp.match(/^OK running (\d+)/);
      return m ? { running: true, pid: parseInt(m[1], 10) } : { running: false };
    } catch {
      return { running: false };
    }
  }

  // ── 安装 / 卸载（一次 UAC）─────────────────────────────────────────────────
  /**
   * 安装/修复服务：生成随机 token + UAC 提权跑 sc create/start。
   * ⚠️ 真机必验：sc create binPath= 含空格路径的引号语义、helper.token ACL、UAC 取消回退、非管理员经已装服务起核。
   */
  async install(): Promise<{ success: boolean; error?: string; status: HelperStatus }> {
    if (!this.supported) {
      return {
        success: false,
        error: 'The privileged service is only supported on Windows',
        status: await this.computeStatus(),
      };
    }
    this.mutationInFlight = true;
    try {
      const exe = resourceManager.getWinHelperPath();
      if (!fs.existsSync(exe)) {
        this.log('error', `helper binary missing: ${exe}`);
        return {
          success: false,
          error: 'helper binary missing (not included in this build)',
          status: await this.computeStatus(),
        };
      }
      // v6: the service runs its protected copy; the bundled core is only the (hash-verified) seed source.
      const bundledCore = resourceManager.getBundledSingBoxPath();
      const confDir = getUserDataPath();

      // token：复用已有，否则生成并写入客户端副本；UAC 脚本把同值写 SYSTEM 侧 helper.token。
      let token = this.token();
      if (!token) {
        token = randomBytes(16).toString('hex');
        try {
          fs.writeFileSync(this.tokenFilePath(), token);
        } catch (e) {
          return {
            success: false,
            error: `Failed to write token: ${e instanceof Error ? e.message : String(e)}`,
            status: await this.computeStatus(),
          };
        }
      }

      const script = this.buildInstallScript(exe, bundledCore, confDir, token);
      const result = await this.runElevatedPowerShell(script);
      if (!result.success) {
        return { success: false, error: result.error, status: await this.computeStatus() };
      }
      // v6: switch to AUTH2 as soon as the new service answers, before any plaintext probe.
      for (let i = 0; i < 10 && !(await this.upgradeAuthMode()); i++) {
        await new Promise((r) => setTimeout(r, 300));
      }

      // 等服务起来绑定管道，再确认就绪（对齐 macOS install 的 10×300ms 就绪等待）。
      let status = await this.computeStatus();
      for (let i = 0; i < 10 && !status.ready; i++) {
        await new Promise((r) => setTimeout(r, 300));
        status = await this.computeStatus();
      }
      if (status.ready) this.log('info', 'helper service installed and ready');
      else this.log('warn', 'helper service installed but did not become ready in time');
      this.lastStableStatus = status;
      return { success: true, status };
    } finally {
      this.mutationInFlight = false;
    }
  }

  /**
   * 卸载服务。优先**管道 uninstall（零 UAC）**：helper 以 SYSTEM 收割 child → 派生旁路自停删服务 + 删 ProgramData
   * （含外置 helper.exe 自身 + helper.token，见 helper.go uninstall / winproc.go spawnSelfUninstall）→ 轮询确认服务真消失。
   * 管道不可用 / 自卸载未在预期内完成 → 回退**提权 PS（一次 UAC）**兜底（sc stop/delete + 删 ProgramData）。
   * 最后删客户端 token 副本。镜像「日常启停零提权」的同一 token 鉴权边界（卸载也走零提权主路径）。
   */
  async uninstall(): Promise<{ success: boolean; error?: string; status: HelperStatus }> {
    if (!this.supported) {
      return {
        success: false,
        error: 'The privileged service is only supported on Windows',
        status: await this.computeStatus(),
      };
    }
    this.mutationInFlight = true;
    try {
      // 1) 管道自卸载（零 UAC）。仅 helper 就绪（有 token + 管道可达）时可行。
      let done = false;
      if (this.token()) {
        try {
          const resp = await this.sendCommand(['uninstall'], 5000);
          if (resp.startsWith('OK')) {
            // 自卸载是异步收尾（helper ~800ms 后自退 → 旁路 ping 延迟后 sc delete + rmdir，合计约 3-4s）。
            // 轮询至多 ~6s 确认服务真从 SCM 消失，再判成功，避免「OK 但服务残留」被当成功。
            for (let i = 0; i < 15; i++) {
              await new Promise((r) => setTimeout(r, 400));
              if (!(await this.queryService()).exists) {
                done = true;
                break;
              }
            }
          }
        } catch {
          /* 管道不可用（未装/未就绪/超时）→ 回退提权 */
        }
      }
      // 2) 回退：提权 PS（管道路径不可用，或自卸载未在预期内完成 → 诚实兜底，宁可一次 UAC 也要真卸干净）。
      if (!done) {
        const result = await this.runElevatedPowerShell(this.buildUninstallScript());
        if (!result.success) {
          return { success: false, error: result.error, status: await this.computeStatus() };
        }
      }
      try {
        fs.unlinkSync(this.tokenFilePath());
      } catch {
        /* 不存在则忽略 */
      }
      this.setAuthMode(false);
      this.log(
        'info',
        done
          ? 'helper service uninstalled itself via the pipe (no elevation)'
          : 'helper service uninstalled (elevated fallback)'
      );
      const status = await this.computeStatus();
      this.lastStableStatus = status;
      return { success: true, status };
    } finally {
      this.mutationInFlight = false;
    }
  }

  // ── 提权脚本生成 + 执行 ────────────────────────────────────────────────────
  /** PowerShell 单引号字符串转义（'' 转义单引号；防注入）。 */
  private psq(s: string): string {
    return s.replace(/'/g, "''");
  }

  /**
   * 安装脚本体（在 runElevatedPowerShell 的 $ErrorActionPreference=Stop + try/catch 包裹内跑）：**锁目录 ACL**
   * （$support 去继承、仅 SYSTEM/Admin 私有，机密性的唯一来源）→ 删旧+写 token（继承目录锁、刻意不单独只读，否则
   * 重装 Set-Content 覆盖被拒——真机根因）→ 幂等清旧服务并**轮询等其真正消失** → **把 helper.exe 外置复制到
   * ProgramData 并锁 ACL**（与 app 生命周期解耦的根因修复）→ New-Service **1072 退避重试**创建（BinaryPathName
   * 单一 .NET 字符串直达 CreateService，真双引号锁定 exe + 三参，默认 LocalSystem，Automatic 开机自启）→ sc start。
   * 全程幂等可重入：重装/修复覆盖旧 token、停删旧服务、覆盖旧外置副本，均能自愈已损状态。
   */
  private buildInstallScript(
    exe: string,
    bundledCore: string,
    confDir: string,
    token: string
  ): string {
    // 外置 helper.exe 到 ProgramData（根因修复）：旧实现把服务 binPath 指向 **app 目录内**的 helper.exe，致
    //   ① app 更新：NSIS 覆盖被「正在运行的服务锁定」的 helper.exe → 占用失败/残留；
    //   ② app 卸载：NSIS 删 app 文件却留下仍指向已删路径的 SCM 服务（孤儿服务 + 残留 ProgramData token）。
    // 镜像 macOS「把 helper 复制出 .app 到 /Library/PrivilegedHelperTools」范式：安装期把 helper.exe 复制到
    // SUPPORT_DIR（ProgramData\FlowZ），服务 binPath 指向该**外置副本** → 二进制与 app 目录彻底解耦，
    // 更新随便覆盖 app、卸载由 helper 自卸载/NSIS 钩子清服务+ProgramData（见 helper.go uninstall / 卸载钩子）。
    // 用 path.win32.basename 取末段：exe 恒为 Windows 反斜杠路径，在 POSIX 测试宿主上普通 path.basename 不识别
    // 反斜杠会整串返回；win32 变体在两种宿主都正确剥出 com.flowz.helper.exe（与 getWinHelperPath 的名字保持耦合）。
    const helperDst = path.join(SUPPORT_DIR, path.win32.basename(exe));
    // BinaryPathName(ImagePath)：各含空格路径用**真双引号**包裹，经 New-Service 单一字符串直达 Win32 CreateService。
    // 不可用 `sc.exe create binPath= "\"..\""`：PS 原样把 `\"` 传给 sc → 服务启动经 CommandLineToArgvW 时 `\"`
    // 退化为字面引号 → 含空格安装路径（默认 C:\Program Files\FlowZ）下 argv 碎裂、flag 值带字面引号 → 服务侧
    // singboxBin/confDir/supportDir 全污染（isLockedSingbox/cfgAllowed/tokenValue 全失效）。
    // 注：binPath 指向 ProgramData 外置副本（$helperDst，无空格）；--singbox 仍可能含空格（app 安装目录）→ 仍需真双引号。
    // v6: --singbox/--coredir name the protected copy (SYSTEM/Administrators-only); the user-writable bundled /
    // userData core is never executed by the service — --bundledcore is only the seed, accepted by hash.
    const protectedCore = path.join(CORE_DIR, 'sing-box.exe');
    const binPath =
      `"${helperDst}" --singbox "${protectedCore}" --coredir "${CORE_DIR}" ` +
      `--bundledcore "${bundledCore}" --confdir "${confDir}" --support "${SUPPORT_DIR}"`;
    const tokenFile = path.join(SUPPORT_DIR, 'helper.token');
    const icacls = system32('icacls.exe');
    const takeown = system32('takeown.exe');
    // icacls 是外部命令：非零退出不受 $ErrorActionPreference=Stop 约束 → 显式查 $LASTEXITCODE 并 throw，
    // 否则授权失败被静默吞掉、直到后续 Set-Content 才以「拒绝访问」这种远离根因的报错暴露。
    const icaclsCheck = (what: string): string =>
      `if ($LASTEXITCODE -ne 0) { throw "icacls ${what} failed (exit code $LASTEXITCODE)" }`;
    return [
      `$support = '${this.psq(SUPPORT_DIR)}'`,
      `$tokenFile = '${this.psq(tokenFile)}'`,
      `$helperSrc = '${this.psq(exe)}'`,
      `$helperDst = '${this.psq(helperDst)}'`,
      `$bp = '${this.psq(binPath)}'`,
      'New-Item -ItemType Directory -Force -Path $support | Out-Null',
      // 先锁**目录**ACL（防本地提权 + 闭 token TOCTOU）：ProgramData 默认 ACL 经继承给 Users「创建文件」+ 父级
      // FILE_DELETE_CHILD + CREATOR OWNER 完全控制 → 普通用户能删/替换这个以 SYSTEM 运行的 helper.exe（重启即 SYSTEM
      // 任意码执行，Pritunl/NetBird 同类 CVE）。文件级 ACL 挡不住：删子文件由父目录 FILE_DELETE_CHILD 授权，非文件自身
      // DACL。故去继承（清掉 CREATOR OWNER + Users 创建/删子权）、仅留 SYSTEM/Administrators 完全控制并以 (OI)(CI)
      // 下传 → 目录内 token/exe **出生即** SYSTEM/Admin 私有（Users 无任何访问：既不能替换 exe，也读不到 token，
      // 无「写后到设 ACL 之间 token 短暂可读」的竞态窗口）。对齐 macOS helper 落在 root-only 写的受保护目录。
      // 顺序：**先授权、后去继承**——授权失败时目录仍保留继承 ACE（可用、可重试），而不是被清成空 DACL 锁死。
      // 已被旧版锁死（空 DACL）的目录也能自愈：属主隐含 WRITE_DAC，授权可直接补回 SYSTEM/Admin。
      // 属主可能已不是 Admin（真机：用户在资源管理器里改过属主/权限后，提权 icacls 仍退出码 5）→ 先 takeown /A 以
      // SeTakeOwnershipPrivilege 把属主夺回 Administrators（特权路径，不看 DACL；不带 /R，免本地化的 /D 确认提示）。
      `& '${takeown}' /F $support /A | Out-Null`,
      `& '${icacls}' $support /grant:r "${SID_SYSTEM}:(OI)(CI)(F)" "${SID_ADMINISTRATORS}:(OI)(CI)(F)" | Out-Null`,
      // 仍授权失败（属主夺不回 / 子项传播被拒等）→ 把整个旧目录挪开、新建干净目录：重命名只需 ProgramData 上的
      // FILE_DELETE_CHILD（Admin 默认完全控制），不依赖旧目录自身的 ACL/属主。旧目录内只有失效 token 与非服务的 exe，
      // 且 Users 对其零访问，留作残骸无安全影响。
      '$grantCode = $LASTEXITCODE',
      'if ($grantCode -ne 0) {',
      "  $broken = $support + '.broken-' + (Get-Date -Format 'yyyyMMddHHmmss')",
      '  try { [System.IO.Directory]::Move($support, $broken) }',
      '  catch { throw "icacls grant on $support failed (exit code $grantCode), and the old directory could not be moved aside: $($_.Exception.Message)" }',
      '  New-Item -ItemType Directory -Force -Path $support | Out-Null',
      `  & '${icacls}' $support /grant:r "${SID_SYSTEM}:(OI)(CI)(F)" "${SID_ADMINISTRATORS}:(OI)(CI)(F)" | Out-Null`,
      `  ${icaclsCheck('grant on $support')}`,
      '}',
      `& '${icacls}' $support /inheritance:r | Out-Null`,
      icaclsCheck('inheritance removal on $support'),
      // 先删任何残留旧 token 再写：重装/修复时旧 token 可能是「Admin 只读」（旧版 ACL）或部分失败安装的残留，
      // 而 Set-Content 覆盖一个 Admin 只读的现存文件会被拒（真机实测「对…helper.token 的访问被拒绝」的根因）。
      // 经目录 Admin 的 FILE_DELETE_CHILD 删旧文件**不受其自身只读 DACL 阻挡** → 随后 Set-Content 必成（自愈已损状态）。
      // 用 .NET File.Delete（不存在不抛）而非 Remove-Item -Force：后者会先改文件属性（需文件自身的写属性权限），
      // 对 DACL 为空/只读的残留文件恰恰失败，且 SilentlyContinue 把失败吞成后续 Set-Content 的「拒绝访问」。
      '[System.IO.File]::Delete($tokenFile)',
      // 写 token（无 BOM ASCII）。机密性由**目录锁**保证（Users 对 $support 零访问，根本进不来读）→ token 继承目录的
      // SYSTEM/Admin 全权即可：SYSTEM 可读（服务鉴权用）、Admin 可写（**重装可覆盖**）。刻意不再单独给 token 上「只读」
      // ACL——只读对机密性零增益（Users 已被目录挡死），却会令重装时 Set-Content 覆盖被拒（即上面那个真机根因）。
      `Set-Content -Path $tokenFile -Value '${this.psq(token)}' -NoNewline -Encoding ascii`,
      // 幂等重装：停 + 删旧服务（按名）
      `& '${system32('sc.exe')}' stop ${SERVICE_NAME} 2>$null | Out-Null`,
      `& '${system32('sc.exe')}' delete ${SERVICE_NAME} 2>$null | Out-Null`,
      // sc delete 是异步「标记删除」（须等所有句柄关闭 + 进程停才移除）→ 轮询等服务真消失，否则 New-Service 撞
      // 1072 ERROR_SERVICE_MARKED_FOR_DELETE（重装真机高概率命中）。注：服务注销与进程映像完全解除映射之间仍有 ms 级
      // 窗口，故旧副本解锁**靠下方 Copy-Item 的退避重试兜底**、而非仅靠本轮询（勿据此误删重试）。
      '$deadline = (Get-Date).AddSeconds(15)',
      `while ((Get-Service -Name ${SERVICE_NAME} -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }`,
      // 外置复制：旧服务已停删 → ProgramData 旧副本（若有）已解锁 → -Force 覆盖。带退避重试兜「文件仍被占用」
      // 的解锁窗口竞态（sc delete 后进程退出有微小延迟）。失败 fail-loud（不静默留旧副本跑老逻辑）。
      // 自愈旧版残留：按账户名授权的旧脚本在本地化 Windows 上给副本留下**空 DACL**（SYSTEM 无法执行 → 服务永不就绪；
      // 修复时 Copy-Item 覆盖被拒，手动也删不掉——真机 ru Windows）。属主（Admin）隐含 WRITE_DAC → 先补回授权；
      // 再经目录的 FILE_DELETE_CHILD 先删后拷（即使补授权失败，删除也不看文件自身 DACL）。补授权失败不致命，不查退出码。
      'if (Test-Path -LiteralPath $helperDst) {',
      `  & '${icacls}' $helperDst /grant:r "${SID_SYSTEM}:(F)" "${SID_ADMINISTRATORS}:(F)" | Out-Null`,
      '}',
      '$copied = $false',
      '$copyErr = $null',
      'for ($i = 0; $i -lt 10 -and -not $copied; $i++) {',
      '  try { [System.IO.File]::Delete($helperDst); Copy-Item -LiteralPath $helperSrc -Destination $helperDst -Force; $copied = $true }',
      '  catch { $copyErr = $_; Start-Sleep -Milliseconds 300 }',
      '}',
      'if (-not $copied) { throw "Failed to copy helper.exe to ProgramData (the old service binary may still be in use; try again later, or reboot and reinstall): $($copyErr.Exception.Message)" }',
      // 显式收紧外置副本 ACL（兜底）：目录已锁 SYSTEM/Admin 私有、本副本继承之即足够；这里再去继承 + 仅 SYSTEM/Admin
      // 完全控制，确保 Users 对这个**以 SYSTEM 运行**的二进制零访问（不可写/不可替换 → 杜绝本地提权）。
      `& '${icacls}' $helperDst /grant:r "${SID_SYSTEM}:(F)" "${SID_ADMINISTRATORS}:(F)" | Out-Null`,
      icaclsCheck('grant on $helperDst'),
      `& '${icacls}' $helperDst /inheritance:r | Out-Null`,
      icaclsCheck('inheritance removal on $helperDst'),
      // New-Service 退避重试兜底（删除标记态 1072 窗口期）：BinaryPathName 单一字符串直达 CreateService；
      // 默认账户即 LocalSystem；-StartupType Automatic = 开机自启常驻（app 全程只发管道命令、不 start/stop 服务）。
      '$created = $false',
      '$lastErr = $null',
      'for ($i = 0; $i -lt 10 -and -not $created; $i++) {',
      `  try { New-Service -Name ${SERVICE_NAME} -BinaryPathName $bp -StartupType Automatic | Out-Null; $created = $true }`,
      '  catch { $lastErr = $_; Start-Sleep -Milliseconds 500 }',
      '}',
      // 失败抛**真实异常**（不用硬编码 1072 文案盖掉真因——非 1072 失败如路径非法/权限也要透出真原因）
      `if (-not $created) { throw "New-Service failed after 10 retries (usually the sc delete marked-for-deletion 1072 race; reboot if it persists): $($lastErr.Exception.Message)" }`,
      `& '${system32('sc.exe')}' start ${SERVICE_NAME} | Out-Null`,
    ].join('\n');
  }

  /** 卸载脚本体（在 runElevatedPowerShell 的 Stop + try/catch 包裹内跑）：停 + 删服务 + 删受保护 token/目录。
   *  对「服务/目录不存在」容错（sc 外部命令不受 Stop 影响、不抛；Remove-Item 显式 SilentlyContinue）。 */
  private buildUninstallScript(): string {
    return [
      `& '${system32('sc.exe')}' stop ${SERVICE_NAME} 2>$null | Out-Null`,
      'Start-Sleep -Milliseconds 300',
      `& '${system32('sc.exe')}' delete ${SERVICE_NAME} 2>$null | Out-Null`,
      // 先递归补回 Admin 权限：旧版在本地化 Windows 上可能留下空 DACL 的目录/副本，否则 Remove-Item 静默删不掉。
      `& '${system32('icacls.exe')}' '${this.psq(SUPPORT_DIR)}' /grant:r "${SID_ADMINISTRATORS}:(OI)(CI)(F)" /T /C | Out-Null`,
      `Remove-Item -Recurse -Force -Path '${this.psq(SUPPORT_DIR)}' -ErrorAction SilentlyContinue`,
    ].join('\n');
  }

  /**
   * 提权 .ps1 文件内容（$ErrorActionPreference=Stop + try/catch 包裹 inner，回写 flag/err）。
   * **必须带 UTF-8 BOM**：Windows PowerShell 5.1 把无 BOM 的 .ps1 按系统 ANSI 代码页解码（ru=cp1251、en=cp1252），
   * 脚本内中文 throw 文案 / 含西里尔等非 ASCII 的用户目录路径被拆成单字节乱码，其中 0x82/0x84/0x91–0x94 恰被读成
   * ‚ „ ‘ ’ “ ”——PS 词法把它们当引号 → 整个脚本解析失败、一行不执行（服务装不上，只回「未写回结果」，每次启动重弹安装引导）。
   */
  private buildElevatedScriptFile(inner: string, flagPath: string, errPath: string): string {
    return (
      '\ufeff' +
      [
        "$ErrorActionPreference = 'Stop'",
        'try {',
        inner,
        `  "0" | Out-File -FilePath '${this.psq(flagPath)}' -Encoding ascii`,
        '} catch {',
        // 用 .NET WriteAllText（默认 UTF-8 无 BOM）写异常信息——避免 PS5.1 `Out-File -Encoding utf8` 的 BOM
        // 在 app 回传文案前残留零宽字符。
        `  [System.IO.File]::WriteAllText('${this.psq(errPath)}', $_.Exception.Message)`,
        `  "1" | Out-File -FilePath '${this.psq(flagPath)}' -Encoding ascii`,
        '}',
      ].join('\n')
    );
  }

  /**
   * 以一次 UAC 跑 PowerShell 脚本：写临时 .ps1 → 外层 Start-Process -Verb RunAs -Wait 触发 UAC。
   * 内层以 $ErrorActionPreference=Stop + try/catch 包裹脚本体：成功写 flag "0"；失败把**异常信息**写 .err + flag "1"，
   * 供 app 回传具体失败原因（对齐「失败须带原因」——否则只见「退出码 N」无法区分 1072 竞态 / 路径错 / ACL 失败）。
   * UAC 取消 → Start-Process 抛错 → 外层 exit 1。
   * ⚠️ 真机必验：UAC 弹窗/取消、-Wait 完成语义、flag/err 回写时序、sc delete→New-Service 重装竞态命中率。
   */
  private runElevatedPowerShell(inner: string): Promise<{ success: boolean; error?: string }> {
    return new Promise((resolve) => {
      // Item-8 hardening: fresh private dir (mkdtemp) + exclusive create; the elevated side reads the script bytes
      // once, checks their SHA-256 against the hash computed here and runs exactly those bytes (no -File re-read),
      // so rewriting the file while the UAC prompt is open changes nothing.
      let dir: string;
      let scriptPath: string;
      let flagPath: string;
      let errPath: string;
      let content: string;
      try {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-helper-'));
        scriptPath = path.join(dir, 'flowz-helper.ps1');
        flagPath = path.join(dir, 'flowz-helper.done');
        errPath = path.join(dir, 'flowz-helper.err');
        content = this.buildElevatedScriptFile(inner, flagPath, errPath);
        fs.writeFileSync(scriptPath, content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
      } catch (e) {
        return resolve({
          success: false,
          error: `Failed to write the elevation script: ${String(e)}`,
        });
      }
      const sha = createHash('sha256').update(Buffer.from(content, 'utf8')).digest('hex');
      const encoded = Buffer.from(
        this.buildVerifiedLoader(scriptPath, sha, flagPath, errPath),
        'utf16le'
      ).toString('base64');
      // -EncodedCommand（base64 仅 [A-Za-z0-9+/=]）：无引号/空格/非 ASCII 路径拼接问题。
      const outer =
        `try { Start-Process '${powershellPath()}' -Verb RunAs -WindowStyle Hidden -Wait ` +
        `-ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','${encoded}'; exit 0 } ` +
        `catch { exit 1 }`;
      execFile(
        powershellPath(),
        ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', outer],
        { timeout: 120000, windowsHide: true },
        (err) => {
          let success = false;
          let error: string | undefined;
          if (err) {
            error = 'UAC was cancelled or elevation failed';
          } else {
            let code = '';
            try {
              code = fs.readFileSync(flagPath, 'utf8').trim();
            } catch {
              /* 未写回 */
            }
            if (code === '0') {
              success = true;
            } else {
              let detail = '';
              try {
                detail = fs.readFileSync(errPath, 'utf8').trim();
              } catch {
                /* 无具体原因 */
              }
              error =
                detail ||
                (code === ''
                  ? 'The elevation script reported no result (possibly cancelled)'
                  : `The elevation script failed (code ${code})`);
            }
          }
          try {
            fs.rmSync(dir, { recursive: true, force: true });
          } catch {
            /* ignore */
          }
          resolve({ success, error });
        }
      );
    });
  }

  /** Elevated loader (passed via -EncodedCommand): read the script once, verify its SHA-256, run those bytes. */
  private buildVerifiedLoader(
    scriptPath: string,
    sha256: string,
    flagPath: string,
    errPath: string
  ): string {
    return [
      "$ErrorActionPreference = 'Stop'",
      `$b = [System.IO.File]::ReadAllBytes('${this.psq(scriptPath)}')`,
      "$h = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($b))).Replace('-', '').ToLowerInvariant()",
      `if ($h -ne '${sha256}') {`,
      `  [System.IO.File]::WriteAllText('${this.psq(errPath)}', 'The elevation script was modified before it ran; aborted')`,
      `  "1" | Out-File -FilePath '${this.psq(flagPath)}' -Encoding ascii`,
      '  exit 90',
      '}',
      '$t = [System.Text.Encoding]::UTF8.GetString($b).TrimStart([char]0xFEFF)',
      '& ([ScriptBlock]::Create($t))',
    ].join('\n');
  }
}
