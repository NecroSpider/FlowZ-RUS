/**
 * macOS 提权 helper 管理器
 *
 * 解决：未签名应用在 TUN 模式下每次启停 sing-box（含切节点重启）都弹 osascript 管理员授权框。
 * 方案：一次性安装一个 root LaunchDaemon（Go 二进制，见 helper/helper.go），之后 app 经 token 鉴权的
 *       unix socket 零提权驱动 sing-box 启停。本类负责安装/卸载/状态探测 + socket 客户端（行协议）。
 *
 * 仅 macOS 有意义；其余平台所有方法均安全降级（supported=false / ready=false）。
 * 未安装时由 ProxyManager 回退到 PR-M1 的 root 看护脚本（osascript 启动一次授权）。
 */

import { app } from 'electron';
import { spawn, execFile } from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { randomBytes, createHash } from 'crypto';
import type { HelperStatus } from '../../shared/types';
import type { IPrivilegedHelper, HelperStartResult } from './IPrivilegedHelper';
import type { ILogManager } from './LogManager';
import { resourceManager } from './ResourceManager';
import { getUserDataPath } from '../utils/paths';
import { shq } from '../utils/shell-quote';
import { sha256File } from '../../shared/file-hash';
import coreManifest from '../../shared/core-manifest.json';

// .btm(NSKeyedArchiver) 结构化解析：plist 原为 electron-builder 间接依赖，已提升为直接 dependency 确保打包入 asar。
// 解析输入是本机 root 写的 plutil xml1（可信源），无类型定义故 require + 最小类型注解（与本类内既有 require 风格一致）。

const plist: { parse(xml: string): unknown } = require('plist');

const LABEL = 'com.flowz.helper';
const HELPER_DEST = `/Library/PrivilegedHelperTools/${LABEL}`;
const PLIST_PATH = `/Library/LaunchDaemons/${LABEL}.plist`;
const SYSTEM_SUPPORT = '/Library/Application Support/FlowZ';
const SOCKET_PATH = `${SYSTEM_SUPPORT}/helper.sock`;
/** 与 helper.go 的 protoVersion 对应。**分级**（v5 起）：proto ≥ MIN_USABLE 即 TUN 功能齐全（可用，不报需修复）；
 *  MIN_USABLE ≤ proto < EXPECTED → upgradeable（旧版仍能 TUN，仅温和提示可升级、不强制重装）；proto < MIN_USABLE 才 needsRepair。
 *  v3=SIGTERM 收割 child；v4=freeport；v5=install-core（root 写受保护目录持久化内核 + 哈希校验防 TOCTOU）；
 *  v6=chownRuntimeDirs（root 跑的 sing-box 退出后归还 tailscale/dashboard/ui 属主给登录用户，根治跨提权态属主冲突）；
 *  v7=route-add/route-del（出口托管 ifscope 拆半默认路由）；v8=default-restore（停核补回被 EEXIST 善后误删的全局 default）；
 *  v9=flush-dns（root 刷系统 DNS 缓存：dscacheutil + HUP mDNSResponder 两层全清）。
 *  v10=core trust (install-core accepts only the compiled-in bundled core hash or admin-approved trusted-hashes;
 *  the helper verifies/re-seeds the protected core before every start), config policy + root-only config copy,
 *  safe log open, forwarding restore, fd-based runtime-dir hand-back, core-info. v4–v9 keep working for TUN
 *  (upgradeable toast only, no prompt). */
const EXPECTED_PROTO = '10';
const MIN_USABLE_PROTO = 4;
/** First proto whose install-core enforces core trust (and that answers core-info). */
const TRUST_PROTO = 10;

/** Compiled-in bundled-core hash this app version expects the helper to carry (core-manifest pin). */
function expectedBundledCoreHash(): string {
  const key = process.arch === 'arm64' ? 'mac-arm64' : 'mac-x64';
  return String((coreManifest.coreBinarySha256 as Record<string, string>)[key] || '')
    .replace(/^sha256:/, '')
    .toLowerCase();
}

/** One file an elevated core install copies into the protected core dir. */
export interface ElevatedCoreItem {
  /** Source file (user-writable location). */
  src: string;
  /** Destination file name inside the core dir (sing-box / libcronet.*). */
  name: string;
  /** SHA-256 the app computed from the file it validated; the root script refuses any other content. */
  sha256: string;
  /** Ad-hoc re-sign after copying (arm64 needs a valid signature; the allowlisted hash is the post-sign one). */
  codesign?: boolean;
}

/**
 * Root script (macOS) that installs core files into the protected core dir and records each final hash in
 * <coreDir>/trusted-hashes — the allowlist the helper (proto ≥10) trusts besides its compiled-in hash. Only this
 * admin-password path writes the allowlist, so a token holder cannot make root run an arbitrary binary.
 * Each source is copied once, the copy is hashed and must equal the app-computed hash before it is used.
 */
export function buildMacElevatedCoreInstallScript(
  coreDir: string,
  items: ElevatedCoreItem[],
  opts?: { pkillCore?: boolean }
): string {
  const lines = [
    '#!/bin/bash',
    'set -e',
    'umask 022',
    `COREDIR=${shq(coreDir)}`,
    'AL="$COREDIR/trusted-hashes"',
    'mkdir -p "$COREDIR"',
    'chown root:wheel "$COREDIR"; chmod 755 "$COREDIR"',
    '[ -L "$AL" ] && rm -f "$AL"',
    'touch "$AL"; chown root:wheel "$AL"; chmod 644 "$AL"',
    'install_one() {',
    '  TMP="$COREDIR/.$1.elevated.new"',
    '  rm -f "$TMP"',
    '  /bin/cp -X "$2" "$TMP"',
    '  GOT=$(/usr/bin/shasum -a 256 "$TMP" | /usr/bin/awk \'{print $1}\')',
    '  if [ "$GOT" != "$3" ]; then rm -f "$TMP"; echo "FlowZ: $1 changed after it was checked; aborted" >&2; exit 4; fi',
    '  chown root:wheel "$TMP"; chmod 755 "$TMP"',
    '  if [ "$4" = 1 ]; then /usr/bin/codesign --force --sign - "$TMP" >/dev/null 2>&1 || true; fi',
    '  FINAL=$(/usr/bin/shasum -a 256 "$TMP" | /usr/bin/awk \'{print $1}\')',
    '  grep -qx "$FINAL" "$AL" || printf \'%s\\n\' "$FINAL" >> "$AL"',
    '  mv -f "$TMP" "$COREDIR/$1"',
    '}',
  ];
  if (opts?.pkillCore) lines.push('pkill -x sing-box 2>/dev/null || true');
  for (const it of items) {
    if (!/^(sing-box|libcronet\.dylib)$/.test(it.name) || !/^[0-9a-f]{64}$/.test(it.sha256)) {
      throw new Error(`refusing to build an elevated install for ${it.name}`);
    }
    lines.push(`install_one ${it.name} ${shq(it.src)} ${it.sha256} ${it.codesign ? 1 : 0}`);
  }
  lines.push('echo flowz-core-install-ok', '');
  return lines.join('\n');
}

/**
 * Shell command (run as root by osascript) that executes a user-written script without a TOCTOU window: root copies
 * the script into a root-only mktemp file, checks the copy's SHA-256 against the hash computed when it was written,
 * and only then runs the copy. Rewriting the original while the password dialog is open no longer helps.
 */
export function macVerifiedRunCommand(scriptPath: string, sha256: string): string {
  return (
    'T=$(/usr/bin/mktemp /tmp/flowz-root.XXXXXX) || exit 1; ' +
    `/bin/cat ${shq(scriptPath)} > "$T"; ` +
    `if echo "${sha256}  $T" | /usr/bin/shasum -a 256 -c - >/dev/null 2>&1; then /bin/bash "$T"; R=$?; ` +
    'else echo "FlowZ: the elevation script was modified before it ran; aborted" >&2; R=90; fi; ' +
    '/bin/rm -f "$T"; exit $R'
  );
}

/**
 * Write `script` to a fresh private dir (mkdtemp 0700, exclusive create 0600) and run it as root through one
 * osascript admin prompt, via macVerifiedRunCommand. Cancel (-128) and failures are reported separately.
 */
export function runMacRootScript(
  name: string,
  script: string
): Promise<{ success: boolean; error?: string }> {
  return new Promise((resolve) => {
    let dir: string;
    let scriptPath: string;
    try {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-elev-'));
      scriptPath = path.join(dir, name);
      fs.writeFileSync(scriptPath, script, { mode: 0o600, flag: 'wx' });
    } catch (e) {
      resolve({ success: false, error: e instanceof Error ? e.message : String(e) });
      return;
    }
    const sha = createHash('sha256').update(script).digest('hex');
    const cmd = macVerifiedRunCommand(scriptPath, sha).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const proc = spawn('/usr/bin/osascript', [
      '-e',
      `do shell script "${cmd}" with administrator privileges`,
    ]);
    let stderr = '';
    proc.stderr?.on('data', (d) => {
      stderr += d.toString();
    });
    const cleanup = (): void => {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    };
    proc.on('exit', (code) => {
      cleanup();
      if (code === 0) resolve({ success: true });
      else if (/-128|User canceled/i.test(stderr))
        resolve({ success: false, error: 'Administrator authorization cancelled' });
      else resolve({ success: false, error: stderr.trim() || `osascript exit code ${code}` });
    });
    proc.on('error', (err) => {
      cleanup();
      resolve({ success: false, error: err.message });
    });
  });
}
/** launchctl 加载态探测缓存 TTL：getStatus 被首页/设置页高频轮询，避免每次都 spawn launchctl。 */
const LOADED_PROBE_TTL_MS = 10_000;
/** SMAppService 上次权威读数(1/2)的保持窗口：sm 偶发返回 0(NotRegistered，多在装卸过渡期)/3/null 时，30s 内仍用上次
 *  权威值、跳过 BTM/launchctl 启发式（消除装卸瞬间「修复」按钮抖动）。须 > TTL(10s)+卡片轮询(5s)×2，保证稳态自动续期。 */
const SM_HOLD_MS = 30_000;
/** SMAppService 探测缓存 TTL：3s（与设置卡轮询同步）。比 launchctl 的 10s 短——开关变化要尽快反映，osascript ~33ms 廉价。 */
const SM_CACHE_TTL_MS = 3_000;

export class HelperManager implements IPrivilegedHelper {
  /** 路径不符 warn 仅首次记（getStatus 被设置页/首页高频调用，避免刷屏）。 */
  private pathMismatchWarned = false;
  /** "helper does not trust the bundled core" warning logged once per process. */
  private staleLogged = false;

  // ── 「允许在后台」检测状态（仅 macOS）──────────────────────────────────
  /** launchctl 探测结果缓存（TTL 见 LOADED_PROBE_TTL_MS；null=探测不可用）。 */
  private loadedProbe: { value: boolean | null; at: number } | null = null;
  /** 去抖：首次 fresh 探测到 not-loaded 的时刻（连续 ≥2 次、跨 ≥3s 均 not-loaded 才判 backgroundDisabled）。 */
  private firstNotLoadedAt: number | null = null;
  /** 连续 fresh 探测到 not-loaded 的次数（缓存命中不计；探测到已加载/未知即清零）。 */
  private notLoadedProbes = 0;
  /** BTM disposition 缓存，key=最新 .btm 的 path:mtime:size（失效条件与数据变化精确对齐 → 根治旧 TTL 缓存的 null
   *  毒化 + 落盘窗口：btmd 改写 .btm 后 mtime 变、缓存下次访问即失效重读；plutil 执行失败不写缓存，留待回退启发式）。 */
  private dispositionCache: { key: string; value: number | null } | null = null;
  /** SMAppService.statusForLegacyURL 缓存（backgroundDisabled 的权威首通道，TTL 同 LOADED_PROBE_TTL_MS）。 */
  private smStatusCache: { value: number | null; at: number } | null = null;
  /** 诊断单次日志闸（高频 getStatus 防刷屏）：sm 上次已记的值 / BTM 直读失败已记一次。 */
  private smLoggedValue: number | null = null;
  private btmReadFailLogged = false;
  /** SMAppService 最近一次权威读数(1/2)：仅 fresh 探测写入，供 sm 偶发 0/3/null 时在 SM_HOLD_MS 内保持（消抖）。 */
  private smLastAuthoritative: { value: 1 | 2; at: number } | null = null;
  /** 装/卸互斥窗口：getStatus 在 install/uninstall 进行中、或本次探测跨越了一次装卸(epoch 变)时，返回最近稳定快照而非
   *  半拆的 TOCTOU 快照（修「卸载 bootout→rm 区间被并发 getStatus 采样拼出 installed∧!ready∧!disabled → 修复按钮闪现」）。 */
  private mutationEpoch = 0;
  private mutationInFlight = false;
  private lastStableStatus: HelperStatus | null = null;

  constructor(private logManager?: ILogManager | null) {}

  private log(level: 'info' | 'warn' | 'error', message: string): void {
    this.logManager?.addLog(level, message, 'Helper');
  }

  private get supported(): boolean {
    return process.platform === 'darwin';
  }

  // ── token ──────────────────────────────────────────────────────────────
  // 刻意独立成文件（非 UserConfig 字段）：渲染端 saveConfig 整体回写 config.json 时永远碰不到它，
  // 杜绝「装好后 token 被携旧快照的 saveConfig 清零 → 需修复」的竞态；也避免 token 经 IPC 全量下发渲染端。
  private tokenFilePath(): string {
    return path.join(getUserDataPath(), 'helper-client.token');
  }

  /** app 侧持有的 socket 鉴权 token（与 root 侧 helper.token 同值）。 */
  private token(): string {
    try {
      return fs.readFileSync(this.tokenFilePath(), 'utf8').trim();
    } catch {
      return '';
    }
  }

  // ── 状态探测 ─────────────────────────────────────────────────────────────
  private filesPresent(): boolean {
    try {
      return fs.existsSync(HELPER_DEST) && fs.existsSync(PLIST_PATH);
    } catch {
      return false;
    }
  }

  /**
   * daemon 是否被 launchd 加载：`launchctl print system/<LABEL>` 退出码 0=已加载，非零=未加载
   * （「允许在后台」被关 → BTM 阻止 bootstrap → 不在 system 域）。普通用户可读 system 域单服务，无需 root。
   * 返回 null=探测不可用（超时/spawn 失败），调用方不得据此判定 backgroundDisabled。
   * 带 ~10s TTL 缓存（仅 supported && installed && !ready 路径会调用，见 getStatus）。
   * 注意：退出码语义须 Mac 真机验证（macOS 13/14/15 可能有差异），见设计文档必测项 1。
   */
  private probeLoaded(): Promise<boolean | null> {
    const cached = this.loadedProbe;
    if (cached && Date.now() - cached.at < LOADED_PROBE_TTL_MS) {
      return Promise.resolve(cached.value);
    }
    return new Promise((resolve) => {
      execFile('/usr/bin/launchctl', ['print', `system/${LABEL}`], { timeout: 2000 }, (err) => {
        let value: boolean | null;
        if (!err) {
          value = true; // 退出码 0 → 已加载
        } else if (err.killed || typeof (err as { code?: unknown }).code !== 'number') {
          value = null; // 超时被杀 / spawn 失败（如 ENOENT，code 为字符串）→ 未知，不参与判定
        } else {
          value = false; // 非零退出码 → 未加载
        }
        this.loadedProbe = { value, at: Date.now() };
        // 去抖计数仅随 fresh 探测推进：TTL ≥10s 保证两次 fresh 探测天然跨 ≥3s
        if (value === false) {
          if (this.firstNotLoadedAt === null) this.firstNotLoadedAt = Date.now();
          this.notLoadedProbes += 1;
        } else {
          this.firstNotLoadedAt = null;
          this.notLoadedProbes = 0;
        }
        resolve(value);
      });
    });
  }

  /** 完整状态：供设置页展示 + 安装/卸载按钮判态。装/卸互斥期返回最近稳定快照，避免 TOCTOU 半拆快照（见字段注释）。 */
  async getStatus(force = false): Promise<HelperStatus> {
    if (this.mutationInFlight && this.lastStableStatus) return this.lastStableStatus;
    const epoch = this.mutationEpoch;
    const s = await this.computeStatus(force);
    // 探测期间发生过装/卸（epoch 变）或 mutation 仍在途 → 本快照可能跨越互斥区，作废、返回上一稳定快照
    if ((this.mutationInFlight || this.mutationEpoch !== epoch) && this.lastStableStatus) {
      return this.lastStableStatus;
    }
    this.lastStableStatus = s;
    return s;
  }

  /** 实际计算状态（无互斥保护）。force=true 强制 sm fresh（窗口 focus：用户切回 app=刚改过开关，立即绕缓存重读）。 */
  private async computeStatus(force = false): Promise<HelperStatus> {
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
    let upgradeable = false; // 可用但有新版 helper（v5 install-core）：proto ≥ MIN_USABLE 且 < EXPECTED
    if (installed && this.token()) {
      try {
        const resp = await this.sendCommand(['ping'], 1500);
        const m = resp.match(/^OK pong uid=\d+ v(\S+)/);
        if (m) {
          version = m[1];
          const pv = parseInt(version, 10);
          ready = !isNaN(pv) && pv >= MIN_USABLE_PROTO; // proto ≥ 最低可用即 TUN 齐全，不再要求精确 EXPECTED
          upgradeable = ready && pv < parseInt(EXPECTED_PROTO, 10); // 可用但有新版 → 温和提示可升级
          // v10+: if this helper does not trust THIS app's bundled core (helper built for an older bundled core
          // and the hash is not admin-approved), it would keep running an older core than the one the config is
          // generated for → treat it as outdated: not ready + needsRepair → the existing repair/reinstall gate
          // (one admin prompt) on the next TUN start; declining falls back to the osascript path as today.
          if (ready && pv >= TRUST_PROTO && (await this.bundledCoreUntrusted())) {
            ready = false;
            upgradeable = false;
          }
        }
      } catch {
        /* 未就绪 */
      }
    }

    // 「允许在后台」backgroundDisabled 判定三级链（按可靠性降序），与 ready/loaded 解耦（install-over-top 让 daemon
    // 在跑 ready=true 但开关仍关的混合态）：
    //  1) SMAppService.statusForLegacyURL（macOS 13+，权威、无 FDA 依赖）：2=RequiresApproval 即开关关、1=开关开。
    //     这是首通道——BTM .btm 目录受 TCC Full Disk Access 保护、GUI 进程读不到（btmDisposition 在生产恒 null，
    //     R4 起「0 条 [BTM] 日志」的真根因），而 SMAppService 查框架不读受保护文件、零 FDA、~30ms。
    //  2) BTM disposition 直读（FDA 环境/dev/SSH 仍有效，bit 级细节）。
    //  3) launchctl 去抖启发式（仅 1+2 双不可用才兜底）。
    let loaded: boolean | null = installed ? true : null;
    let backgroundDisabled = false;
    if (installed) {
      const sm = await this.smLegacyStatus(force || !ready); // force(focus) 或 !ready → 强制 fresh,拿最新 sm
      const held = this.smLastAuthoritative;
      if (sm === 1 || sm === 2) {
        // 权威即时：2=需批准=开关关；1=已启用=开关开（开关切换零延迟反映）
        backgroundDisabled = sm === 2;
        if (!ready) loaded = await this.probeLoaded();
        this.firstNotLoadedAt = null;
        this.notLoadedProbes = 0;
      } else if (held && Date.now() - held.at < SM_HOLD_MS) {
        // sm 偶发 0/3/null（多在装卸过渡）且 SM_HOLD_MS 内有过权威读数 → 保持上次值，跳过 BTM/启发式（消抖）
        backgroundDisabled = held.value === 2;
        if (!ready) loaded = await this.probeLoaded();
        this.firstNotLoadedAt = null;
        this.notLoadedProbes = 0;
      } else if (sm === 0) {
        // 稳态「无注册记录」（开关关时 SM 返 2 而非 0）：不是 backgroundDisabled；installed 但注册丢失 → 经 needsRepair
        // 引导「修复」(reinstall 重新 bootstrap) 才是正解，不该误导用户去系统设置找不存在的条目。
        backgroundDisabled = false;
        if (!ready) loaded = await this.probeLoaded();
        this.firstNotLoadedAt = null;
        this.notLoadedProbes = 0;
      } else {
        // sm === 3(NotFound 框架错误态) 或 null（探测不可用）→ 落 BTM 直读 → launchctl 去抖启发式
        const d = await this.btmDisposition();
        if (d !== null) {
          backgroundDisabled = (d & 0x3) !== 0x3;
          if (!ready) loaded = await this.probeLoaded();
          this.firstNotLoadedAt = null;
          this.notLoadedProbes = 0;
        } else if (!ready) {
          loaded = await this.probeLoaded();
          backgroundDisabled =
            loaded === false &&
            this.notLoadedProbes >= 2 &&
            this.firstNotLoadedAt !== null &&
            Date.now() - this.firstNotLoadedAt >= 3000;
        } else {
          this.firstNotLoadedAt = null;
          this.notLoadedProbes = 0;
        }
      }
    } else {
      this.firstNotLoadedAt = null;
      this.notLoadedProbes = 0;
    }

    // 烧录路径不符检测（仅打包版）：app 被移动后 plist 里烧死的 --singbox 路径会指向旧位置 → TUN
    // 免提权启动静默失败。dev 跑 repo 路径必然与生产安装不同，属预期差异，且 dev「修复」会把 repo
    // 路径烧进生产 plist 弄坏它，故 app.isPackaged 闸门跳过。plist 644 可读，无需 root。
    let installedSingboxPath: string | null = null;
    let pathMismatch = false;
    if (installed && app.isPackaged) {
      installedSingboxPath = this.installedSingboxPath();
      if (installedSingboxPath) {
        const expected = resourceManager.getSingBoxPath();
        // App Translocation：带 quarantine 的未签名 app 从 Downloads 直接打开会被挪到随机临时路径，
        // 每次启动都不同 → 报 mismatch 修复也只会烧进临时路径、下次又不符（死循环）。此时不报 mismatch
        // （真正解法是把 app 移入「应用程序」去 translocation，移好后再正常检测）。
        const translocated = expected.includes('/AppTranslocation/');
        pathMismatch =
          !translocated &&
          path.resolve(installedSingboxPath).toLowerCase() !== path.resolve(expected).toLowerCase();
        if (pathMismatch && !this.pathMismatchWarned) {
          this.pathMismatchWarned = true; // 状态高频刷新，仅首次记日志
          this.log(
            'warn',
            `Helper baked-in path mismatch: plist=${installedSingboxPath} current=${expected}`
          );
        }
      }
    }

    return {
      supported: true,
      installed,
      ready,
      upgradeable,
      version,
      loaded,
      needsRepair: installed && (!ready || pathMismatch),
      backgroundDisabled,
      pathMismatch,
      installedSingboxPath,
    };
  }

  /** v10 core-info: compiled-in bundled hash + protected core hash (null on older helpers / errors). */
  private async coreInfo(): Promise<{
    bundled: string;
    core: string;
    trusted: boolean | null;
  } | null> {
    try {
      // line3 = this app's bundled-core pin; the helper answers whether it would accept that core
      const resp = await this.sendCommand(['core-info', expectedBundledCoreHash()], 3000);
      const m = resp.match(/^OK bundled=(\S+) core=(\S+)(?: trusted=([01-]))?/);
      if (!m) return null;
      const norm = (v: string): string => (v === '-' ? '' : v.toLowerCase());
      const trusted = m[3] === '1' ? true : m[3] === '0' ? false : null;
      return { bundled: norm(m[1]), core: norm(m[2]), trusted };
    } catch {
      return null;
    }
  }

  /** True only when a v10+ helper explicitly reports it would refuse this app's bundled core (helper outdated).
   *  Unknown/unreachable → false (never turn a transient error into a prompt). */
  private async bundledCoreUntrusted(): Promise<boolean> {
    const info = await this.coreInfo();
    if (info?.trusted === false) {
      if (!this.staleLogged) {
        this.staleLogged = true;
        this.log(
          'warn',
          `Installed helper does not trust this app's bundled core (helper pin ${info.bundled || '-'}); treating the helper as outdated → reinstall needed (one administrator prompt)`
        );
      }
      return true;
    }
    return false;
  }

  /** 快速判定能否零提权驱动（ProxyManager 启动路由用）。 */
  async isReady(): Promise<boolean> {
    if (!this.supported || !this.filesPresent() || !this.token()) return false;
    try {
      const resp = await this.sendCommand(['ping'], 1500);
      const m = resp.match(/^OK pong uid=\d+ v(\d+)/);
      if (!m) return false;
      const pv = parseInt(m[1], 10);
      if (pv < MIN_USABLE_PROTO) return false; // proto ≥ 最低可用即可零提权驱动 TUN
      // outdated v10+ helper (does not trust this app's bundled core) → not ready: never run an older core silently
      return !(pv >= TRUST_PROTO && (await this.bundledCoreUntrusted()));
    } catch {
      return false;
    }
  }

  // ── sing-box 启停（socket，零提权）────────────────────────────────────────
  /** 经 helper 启动 sing-box（root）。logPath 为早期 stdout 重定向目标；forward=allowLan。 */
  async startCore(
    configPath: string,
    logPath: string,
    forward: boolean
  ): Promise<HelperStartResult> {
    try {
      // 起前先停掉可能残留的旧 child（app 上次崩溃 → daemon 仍托管着旧 sing-box），幂等。
      await this.sendCommand(['stop'], 3000).catch(() => '');
      // 行6=父 app PID（helper v2 父死看护：本进程消失 → helper 自行 TERM→KILL 收割 sing-box）。
      // HelperManager 跑在 Electron 主进程内，process.pid 即 GUI 父 PID → ProxyManager 零改动。
      const startArgs = [
        'start',
        configPath,
        logPath || '',
        forward ? '1' : '0',
        String(process.pid),
      ];
      let resp = await this.sendCommand(startArgs, 8000);
      // v10: the helper refused the protected core (missing, or untrusted e.g. left by an older helper) and could
      // not re-seed it from the bundle path recorded at install time (app moved). Re-seed from the current bundle
      // over the socket — the helper accepts it only if it hashes to its compiled-in pin; no prompt — then retry.
      if (/^ERR core-(missing|untrusted)/.test(resp)) {
        this.log(
          'warn',
          `Helper refused the protected core (${resp}); re-seeding the bundled core`
        );
        const r = await this.installCore(path.dirname(resourceManager.getBundledSingBoxPath()));
        if (r.ok) resp = await this.sendCommand(startArgs, 8000);
        else this.log('warn', `Bundled core re-seed failed: ${r.error ?? ''}`);
      }
      const m = resp.match(/^OK (?:started|already) (\d+)/);
      if (m) return { ok: true, pid: parseInt(m[1], 10) };
      return { ok: false, error: resp || 'no response from helper' };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** 经 helper 停止 sing-box（root），零提权。 */
  async stopCore(): Promise<boolean> {
    try {
      const resp = await this.sendCommand(['stop'], 5000);
      return resp.startsWith('OK');
    } catch {
      return false;
    }
  }

  /** 经 helper(root) 在内核接口装/删受约束路由（出口托管）。proto<7 旧 helper 回 ERR unknown → {ok:false}。 */
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

  /** 经 helper(root, v8) 补回被 sing-tun setRoutes EEXIST 善后误删的 en0 全局默认路由（停核后断网安全网）。
   *  proto<8 旧 helper 回 ERR unknown → {ok:false}。 */
  async restoreDefaultRoute(gateway: string): Promise<{ ok: boolean; error?: string }> {
    try {
      const resp = await this.sendCommand(['default-restore', gateway], 5000);
      return resp.startsWith('OK') ? { ok: true } : { ok: false, error: resp.trim() };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** 经 helper(root, v9) 刷系统 DNS 缓存（dscacheutil + killall -HUP mDNSResponder，两层全清）。
   *  dscacheutil 成功而 HUP 失败时 helper 回 `OK flushed-partial <原因>` → {ok:true, partial:应答原文}（不降级：
   *  用户级同样无权 HUP，重复无益；partial 供调用方降格 warn 留痕）；proto<9 旧 helper 回 ERR unknown →
   *  {ok:false}，调用方（os-dns-flush）降级用户级 dscacheutil。 */
  async flushDns(): Promise<{ ok: boolean; partial?: string; error?: string }> {
    try {
      const resp = await this.sendCommand(['flush-dns'], 5000);
      if (resp.startsWith('OK flushed-partial')) return { ok: true, partial: resp.trim() };
      return resp.startsWith('OK') ? { ok: true } : { ok: false, error: resp.trim() };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  /** 经 helper 以 root 杀掉所有 sing-box（含外部 osascript 路径遗留的孤儿），零提权。 */
  async cleanup(): Promise<boolean> {
    try {
      const resp = await this.sendCommand(['cleanup'], 5000);
      return resp.startsWith('OK');
    } catch {
      return false;
    }
  }

  /** 经 helper root 侧按端口清占用者（v4 freeport）：占用者是 sing-box 则 kill，否则回报名字（不杀）。
   *  返回 freed=true（已空闲/已杀）/ foreign=占用者名（非 sing-box，未杀）/ error。彻底摆脱 cmdline 匹配（L2）。 */
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

  /** helper 当前是否在托管一个 sing-box（孤儿探测）。 */
  async coreStatus(): Promise<{ running: boolean; pid?: number }> {
    try {
      const resp = await this.sendCommand(['status'], 2000);
      const m = resp.match(/^OK running (\d+)/);
      return m ? { running: true, pid: parseInt(m[1], 10) } : { running: false };
    } catch {
      return { running: false };
    }
  }

  /** 经 helper（root, v5）把源目录 srcDir（含 sing-box + libcronet 等配套）写入锁定的受保护目录（install-core，
   *  B 块持久化更新）。proto<5 的 helper 不认（返回 ERR unknown）→ 调用方据 status.upgradeable/ready 走 fallback。
   *  v10: the helper accepts only the bundled core (compiled-in hash) or admin-approved hashes and ignores the hash
   *  line (still sent for v5–v9 helpers). Any other core answers "ERR untrusted-hash …"; then, only when the caller
   *  says this is a user-initiated core change (allowElevation), one admin-password prompt installs it and records
   *  its hash. Startup/automatic paths never pass allowElevation → never prompt. */
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

  /** One admin prompt: copy the core (and libcronet.dylib if present) into the protected dir, ad-hoc sign it and
   *  add its final hash to trusted-hashes (buildMacElevatedCoreInstallScript). */
  async installCoreElevated(srcDir: string): Promise<{ ok: boolean; error?: string }> {
    try {
      const items: ElevatedCoreItem[] = [];
      const sb = path.join(srcDir, 'sing-box');
      items.push({ src: sb, name: 'sing-box', sha256: sha256File(sb), codesign: true });
      const lib = path.join(srcDir, 'libcronet.dylib');
      if (fs.existsSync(lib))
        items.push({ src: lib, name: 'libcronet.dylib', sha256: sha256File(lib) });
      const script = buildMacElevatedCoreInstallScript(
        resourceManager.getProtectedCoreDir(),
        items
      );
      const r = await runMacRootScript('flowz-core-install.sh', script);
      return r.success ? { ok: true } : { ok: false, error: r.error };
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  // ── socket 客户端（行协议：token\n cmd\n [args...]）────────────────────────
  private sendCommand(rest: string[], timeoutMs: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const sock = net.connect(SOCKET_PATH);
      let buf = '';
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error('helper socket timed out'));
      }, timeoutMs);
      sock.on('connect', () => {
        sock.end([this.token(), ...rest].join('\n') + '\n');
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

  // ── 安装 / 卸载（osascript 一次授权）──────────────────────────────────────
  /** 安装/修复 helper：生成随机 token 并持久化，osascript 以 root 跑安装脚本（弹一次密码框）。 */
  async install(): Promise<{ success: boolean; error?: string; status: HelperStatus }> {
    if (!this.supported) {
      return {
        success: false,
        error: 'The privileged helper is only supported on macOS',
        status: await this.computeStatus(),
      };
    }
    this.mutationInFlight = true;
    this.mutationEpoch++;
    try {
      const srcBinary = resourceManager.getMacHelperPath();
      if (!fs.existsSync(srcBinary)) {
        this.log('error', `helper binary missing: ${srcBinary}`);
        return {
          success: false,
          error: 'helper binary missing (not included in this build)',
          status: await this.computeStatus(),
        };
      }

      // token：复用已有，否则生成并写入独立 token 文件(0600)；root 侧安装脚本写同值。
      let token = this.token();
      if (!token) {
        token = randomBytes(16).toString('hex');
        try {
          fs.writeFileSync(this.tokenFilePath(), token, { mode: 0o600 });
        } catch (e) {
          return {
            success: false,
            error: `Failed to write token: ${e instanceof Error ? e.message : String(e)}`,
            status: await this.computeStatus(),
          };
        }
      }

      const confDir = getUserDataPath();
      const script = this.buildInstallScript(
        srcBinary,
        resourceManager.getBundledSingBoxPath(),
        confDir,
        token,
        resourceManager.getProtectedCoreDir()
      );

      const result = await this.runRootScript('flowz-helper-install.sh', script);
      if (!result.success) {
        return { success: false, error: result.error, status: await this.computeStatus() };
      }
      // 刚 bootstrap 过 → 作废探测缓存与去抖计数（注册被重写，旧 sm 权威值/disposition 失义，不让 stale 值误导）
      this.loadedProbe = null;
      this.smStatusCache = null;
      this.smLastAuthoritative = null;
      this.firstNotLoadedAt = null;
      this.notLoadedProbes = 0;

      // 等 daemon 起来绑定 socket，再确认就绪
      let status = await this.computeStatus();
      for (let i = 0; i < 10 && !status.ready; i++) {
        await new Promise((r) => setTimeout(r, 300));
        status = await this.computeStatus();
      }
      if (status.ready) this.log('info', 'helper installed and ready');
      else this.log('warn', 'helper installed but did not become ready in time');
      // BTM 落盘延迟由 dispositionCache mtime-key 自动处理；UI 后续 getStatus（聚焦/轮询）会读准 backgroundDisabled，
      // 仍「后台被禁用」则引导去系统设置手动开启（不走 deepRepair 自动恢复）。
      this.lastStableStatus = status; // mutation 结束后的新稳定基准
      return { success: true, status };
    } finally {
      this.mutationInFlight = false;
      this.mutationEpoch++;
    }
  }

  /** 卸载 helper：osascript 以 root 注销 daemon 并删除文件（弹一次密码框）。 */
  async uninstall(): Promise<{ success: boolean; error?: string; status: HelperStatus }> {
    if (!this.supported) {
      return {
        success: false,
        error: 'The privileged helper is only supported on macOS',
        status: await this.computeStatus(),
      };
    }
    this.mutationInFlight = true;
    this.mutationEpoch++;
    try {
      const result = await this.runRootScript(
        'flowz-helper-uninstall.sh',
        this.buildUninstallScript()
      );
      if (!result.success) {
        return { success: false, error: result.error, status: await this.computeStatus() };
      }
      // 已 bootout → 作废探测缓存（未安装态 loaded=null，旧 sm 权威值失义）
      this.loadedProbe = null;
      this.smStatusCache = null;
      this.smLastAuthoritative = null;
      this.firstNotLoadedAt = null;
      this.notLoadedProbes = 0;
      // 清掉 app 侧 token 文件（重装会重新生成）
      try {
        fs.unlinkSync(this.tokenFilePath());
      } catch {
        /* 不存在则忽略 */
      }
      this.log('info', 'helper uninstalled');
      const status = await this.computeStatus();
      this.lastStableStatus = status; // mutation 结束后的新稳定基准（已卸载态）
      return { success: true, status };
    } finally {
      this.mutationInFlight = false;
      this.mutationEpoch++;
    }
  }

  /**
   * 后台开关状态的**权威首通道**（macOS 13+）：经 osascript JXA 调 SMAppService.statusForLegacyURL 查本 helper plist
   * 的注册状态。返回 0=NotRegistered 1=Enabled(开关开) 2=RequiresApproval(开关关) 3=NotFound；旧系统/超时/解析失败
   * → null（落到 BTM 直读）。**不读 BTM .btm 目录**——该目录受 TCC Full Disk Access 保护、GUI 进程无 FDA 恒读不到
   * （btmDisposition 在生产恒 null = R4 起「0 条 [BTM] 日志」的真根因），SMAppService 查框架零 FDA、~30ms。TTL 缓存。
   */
  private smLegacyStatus(force = false): Promise<number | null> {
    const c = this.smStatusCache;
    // force=true（!ready 时）绕 TTL 缓存强制 fresh：daemon 不运行往往是用户刚关「允许在后台」，须拿最新 sm 而非缓存
    // 旧值（否则关开关后 10s 内缓存的旧 1 会使 backgroundDisabled 误判 false → 闪「修复」按钮，过缓存窗口才转正）。
    if (!force && c && Date.now() - c.at < SM_CACHE_TTL_MS) return Promise.resolve(c.value);
    return new Promise((resolve) => {
      const js =
        `ObjC.import("ServiceManagement"); ` +
        `$.SMAppService.statusForLegacyURL($.NSURL.fileURLWithPath(${JSON.stringify(PLIST_PATH)}))`;
      execFile(
        '/usr/bin/osascript',
        ['-l', 'JavaScript', '-e', js],
        { timeout: 4000 },
        (err, stdout) => {
          let value: number | null = null;
          if (!err) {
            const n = parseInt((stdout || '').trim(), 10);
            if (!Number.isNaN(n)) value = n;
          }
          this.smStatusCache = { value, at: Date.now() };
          // 仅权威读数(1/2)记为「上次有效值」，供 computeStatus 在 sm 偶发 0/3/null 时保持（消抖，见 SM_HOLD_MS）
          if (value === 1 || value === 2) this.smLastAuthoritative = { value, at: Date.now() };
          if (value !== null && value !== this.smLoggedValue) {
            this.smLoggedValue = value;
            this.log(
              'info',
              `[SM] statusForLegacyURL=${value} (0=not registered 1=enabled 2=requires approval / "Allow in the Background" off 3=not found)`
            );
          }
          resolve(value);
        }
      );
    });
  }

  /** 找最新（mtime 最大）的 .btm 文件元信息；目录不可读/无文件返回 null。替代旧的 shell `ls -t`（少一次 spawn）。 */
  private findNewestBtm(): { path: string; mtimeMs: number; size: number } | null {
    try {
      const dir = '/private/var/db/com.apple.backgroundtaskmanagement';
      let best: { path: string; mtimeMs: number; size: number } | null = null;
      for (const f of fs.readdirSync(dir)) {
        if (!/^BackgroundItems-v\d+\.btm$/.test(f)) continue;
        const p = path.join(dir, f);
        const st = fs.statSync(p);
        if (!best || st.mtimeMs > best.mtimeMs)
          best = { path: p, mtimeMs: st.mtimeMs, size: st.size };
      }
      return best;
    } catch (e) {
      // 观测性：生产 GUI 无 TCC 完全磁盘访问 → EPERM/EACCES（btmDisposition 恒 null，已由 SMAppService 兜住）。单次记。
      const code = (e as { code?: string })?.code;
      if (!this.btmReadFailLogged) {
        this.btmReadFailLogged = true;
        const fda = code === 'EPERM' || code === 'EACCES';
        this.log(
          'warn',
          `[BTM] Failed to read the .btm directory code=${code ?? '?'}${fda ? ' (no Full Disk Access/TCC, direct BTM read unavailable; using SMAppService for the background toggle)' : ''}`
        );
      }
      return null;
    }
  }

  /**
   * disposition 直读（带 mtime-key 缓存）。「允许在后台」(BTM allowed 位) 与「launchd 是否加载」是独立维度——
   * install-over-top 会让 loaded=true 但 allowed 位仍被清，故必须直读 disposition 判后台开关、不能用 loaded 当代理。
   * 缓存以最新 .btm 的 path:mtime:size 为 key：文件未变返缓存，btmd 改写（mtime 变）后下次访问自动失效重读 → 根治旧
   * TTL 缓存的「落盘窗口内缓存 null 毒化 ~10s」。plutil 执行/解析失败返 null 且不缓存（留待回退启发式）。
   */
  private async btmDisposition(): Promise<number | null> {
    const f = this.findNewestBtm();
    if (!f) return null; // 无文件：不缓存
    const key = `${f.path}:${f.mtimeMs}:${f.size}`;
    if (this.dispositionCache?.key === key) return this.dispositionCache.value;
    const r = await this.btmDispositionFresh(f.path);
    if (r.ok) this.dispositionCache = { key, value: r.disp }; // 仅执行成功才缓存（含「成功但无记录」=null）
    return r.ok ? r.disp : null;
  }

  /**
   * 结构化解析 .btm（NSKeyedArchiver）取本 helper 的 disposition（0x1=enabled, 0x2=allowed/「允许在后台」开关）：
   * plutil 转 xml1 → plist.parse → 遍历 $objects，对每个含 disposition 的 record 解引用其 identifier(CF$UID) 字符串、
   * 匹配本 LABEL 命中读其内联 disposition。不可用「就近 disposition」文本启发式（$objects 扁平去重、identifier 串与
   * record dict 位置无关，就近取必张冠李戴，真机实证）。多条记录（gc 窗口内新旧并存）取 generation 最大者，gen 并列
   * 取含 allowed 位者（乐观：误报<漏报）。返回 {ok:false}=plutil 执行/解析失败（回退启发式、不缓存）；{ok:true,disp:null}
   * =成功但无本 helper 记录；{ok:true,disp:N}=命中。plutil -convert json 对 CF$UID 报错，必须 xml1。.btm 644 可读零 root。
   */
  private btmDispositionFresh(
    btmPath: string
  ): Promise<{ ok: true; disp: number | null } | { ok: false }> {
    return new Promise((resolve) => {
      execFile(
        '/usr/bin/plutil',
        ['-convert', 'xml1', '-o', '-', btmPath],
        { timeout: 4000, maxBuffer: 16 * 1024 * 1024 },
        (err, stdout) => {
          if (err || !stdout) {
            if (!this.btmReadFailLogged) {
              this.btmReadFailLogged = true;
              const k = (err as { code?: unknown })?.code;
              this.log(
                'warn',
                `[BTM] plutil failed to read .btm code=${k ?? '?'} (expected for the production GUI without FDA; using SMAppService for the background toggle)`
              );
            }
            resolve({ ok: false });
            return;
          }
          try {
            const root = plist.parse(stdout) as { $objects?: unknown[] };
            const objs = root?.$objects;
            if (!Array.isArray(objs)) {
              resolve({ ok: false });
              return;
            }
            const deref = (v: unknown): unknown =>
              v && typeof v === 'object' && 'CF$UID' in (v as Record<string, unknown>)
                ? objs[(v as { CF$UID: number })['CF$UID']]
                : v;
            const hits: { gen: number; disp: number }[] = [];
            for (const o of objs) {
              if (
                o &&
                typeof o === 'object' &&
                typeof (o as Record<string, unknown>).disposition === 'number' &&
                'identifier' in (o as Record<string, unknown>)
              ) {
                const rec = o as { disposition: number; identifier: unknown; generation?: unknown };
                const ident = deref(rec.identifier);
                if (typeof ident === 'string' && ident.includes(LABEL)) {
                  hits.push({
                    gen: typeof rec.generation === 'number' ? rec.generation : -1,
                    disp: rec.disposition,
                  });
                }
              }
            }
            if (hits.length === 0) {
              resolve({ ok: true, disp: null }); // 成功解析、无本 helper 记录
              return;
            }
            // generation 降序；gen 并列时含 allowed 位(0x2)者优先（乐观取值）
            hits.sort((a, b) => b.gen - a.gen || (b.disp & 0x2) - (a.disp & 0x2));
            const best = hits[0];
            this.log(
              'info',
              hits.length > 1
                ? `[BTM] multiple records matched=${hits.length}: ${hits
                    .map((h) => `gen${h.gen}=${h.disp}`)
                    .join(',')} -> using disp=${best.disp}`
                : `[BTM] disposition=${best.disp} (0x1=enabled 0x2=allowed; &0x3===0x3 means the toggle is on)`
            );
            resolve({ ok: true, disp: best.disp });
          } catch {
            resolve({ ok: false });
          }
        }
      );
    });
  }

  // ── 脚本生成 ─────────────────────────────────────────────────────────────
  private xmlEscape(s: string): string {
    return s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /** xmlEscape 的逆（plist 由本类生成，仅这四个实体；&amp; 最后解，避免二次替换）。 */
  private xmlUnescape(s: string): string {
    return s
      .replace(/&quot;/g, '"')
      .replace(/&gt;/g, '>')
      .replace(/&lt;/g, '<')
      .replace(/&amp;/g, '&');
  }

  /** 读已装 plist 中烧录的 --singbox 路径；不存在/解析失败返回 null（视为未知，不报 mismatch）。 */
  private installedSingboxPath(): string | null {
    try {
      const xml = fs.readFileSync(PLIST_PATH, 'utf8');
      const m = xml.match(/<string>--singbox<\/string>\s*<string>([^<]*)<\/string>/);
      return m ? this.xmlUnescape(m[1]) : null;
    } catch {
      return null;
    }
  }

  private buildInstallScript(
    srcBinary: string,
    bundledSingbox: string,
    confDir: string,
    token: string,
    coreDir: string
  ): string {
    // plist 在 JS 侧完整成形（含转义），脚本用「带引号 heredoc」原样写出，避免 shell 二次展开。
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${this.xmlEscape(HELPER_DEST)}</string>
    <string>--singbox</string><string>${this.xmlEscape(coreDir + '/sing-box')}</string>
    <string>--confdir</string><string>${this.xmlEscape(confDir)}</string>
    <string>--support</string><string>${this.xmlEscape(SYSTEM_SUPPORT)}</string>
    <string>--coredir</string><string>${this.xmlEscape(coreDir)}</string>
    <string>--bundledcore</string><string>${this.xmlEscape(bundledSingbox)}</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
</dict>
</plist>`;

    return `#!/bin/bash
set -e
umask 077
SRC=${shq(srcBinary)}
DEST=${shq(HELPER_DEST)}
SUPPORT=${shq(SYSTEM_SUPPORT)}
PLIST=${shq(PLIST_PATH)}
mkdir -p /Library/PrivilegedHelperTools "$SUPPORT"
# Important: umask 077 would create these dirs as 700 -> a regular-user app could not traverse them to reach the socket (EACCES).
# The dirs must be 755 so they can be traversed (the socket itself is still protected by token auth + a 600 token file).
chmod 755 /Library/PrivilegedHelperTools "$SUPPORT"
cp "$SRC" "$DEST"
chown root:wheel "$DEST"; chmod 755 "$DEST"
printf '%s' ${shq(token)} > "$SUPPORT/helper.token"
chown root:wheel "$SUPPORT/helper.token"; chmod 600 "$SUPPORT/helper.token"
# Protected core dir (root:wheel 755). The helper (proto >=10) seeds it itself from --bundledcore and only if the
# bundle bytes hash to the core pin compiled into the helper; a core the user installed earlier stays if it is
# still trusted (compiled pin or trusted-hashes). No unverified cp / re-sign here any more.
COREDIR=${shq(coreDir)}
BUNDLED_SB=${shq(bundledSingbox)}
mkdir -p "$COREDIR"
chown root:wheel "$COREDIR"; chmod 755 "$COREDIR"
# Only if nothing is there yet, so the protected path exists right after install (the app's path checks expect
# it); the helper re-verifies this copy against its compiled pin before every start and replaces it if needed.
if [ ! -e "$COREDIR/sing-box" ]; then
  cp -X "$BUNDLED_SB" "$COREDIR/.sing-box.seed.new"
  chown root:wheel "$COREDIR/.sing-box.seed.new"; chmod 755 "$COREDIR/.sing-box.seed.new"
  mv -f "$COREDIR/.sing-box.seed.new" "$COREDIR/sing-box"
fi
cat > "$PLIST" <<'FLOWZ_PLIST_EOF'
${plist}
FLOWZ_PLIST_EOF
chown root:wheel "$PLIST"; chmod 644 "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
# launchctl enable clears the launchd override layer (/var/db/com.apple.xpc.launchd/disabled.*.plist),
# **not** the BTM layer (the "Login Items & Extensions" toggle, stored in /var/db/com.apple.backgroundtaskmanagement/).
# Effect: together with the following bootstrap, this session can spawn and the daemon runs even if the BTM disposition is disallowed.
# But it does **not** restore the toggle in System Settings (it still shows off and may not auto-load after a reboot) - the app
# cannot flip a BTM allowed bit the user turned off (Apple SMAppService has no API for it); the user must re-enable it in
# "System Settings > General > Login Items & Extensions". Idempotent, no side effects.
launchctl enable system/${LABEL} 2>/dev/null || true
launchctl bootstrap system "$PLIST"
echo installed-ok
`;
  }

  private buildUninstallScript(): string {
    return `#!/bin/bash
PLIST=${shq(PLIST_PATH)}
launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST" ${shq(HELPER_DEST)}
rm -rf ${shq(SYSTEM_SUPPORT)}
echo uninstalled-ok
`;
  }

  /** Run a root script with one admin prompt (runMacRootScript: private mkdtemp + exclusive create + root-side
   *  hash check of a root-only copy, so rewriting the script while the password dialog is open does not help). */
  private runRootScript(
    name: string,
    script: string
  ): Promise<{ success: boolean; error?: string }> {
    return runMacRootScript(name, script);
  }
}
