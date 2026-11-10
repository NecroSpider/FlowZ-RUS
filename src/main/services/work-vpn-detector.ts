/**
 * 「与工作 VPN 共存」的系统探测层（macOS + Windows）：读路由表 / DNS / 本机接口 / VPN 客户端配置文件，
 * 交 shared/work-vpn 的纯函数识别。全部 best-effort：任何命令失败都返回空结果，绝不阻断起核。
 */

import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import * as os from 'os';
import * as path from 'path';
import { promises as fsp, type Dirent } from 'fs';
import { lookup } from 'dns/promises';
import {
  detectWorkVpn,
  parseMacNetstatRoutes,
  parseScutilDictionaries,
  storeDnsEntries,
  parseScutilDnsResolvers,
  parseOpenVpnRemotes,
  parseWinNetSnapshot,
  type DnsResolverEntry,
  type WorkVpnSnapshot,
} from '../../shared/work-vpn';
import { isIpv4, cidrOverlapsAny } from '../../shared/ip';
import { dedupe } from '../../shared/collections';
import { powershellPath } from '../utils/win-system32';

const execFileAsync = promisify(execFile);
const CMD_TIMEOUT_MS = 4000;
const TUNNEL_IFACE_RE = /^(utun|ipsec|ppp|tun|tap|gpd|wg|zt|feth)\d+$/;

export interface WorkVpnHostContext {
  ownTunAddrs: string[];
  ownMeshCidrs: string[];
  ownTunExcludes: string[];
  /** Windows：FlowZ 自家 TUN 网卡名（resolveWinTunInterfaceName）。 */
  ownTunName?: string;
}

/** scutil 交互模式：命令经 stdin 喂入（list/show 不能走 argv）。 */
function runScutil(script: string): Promise<string> {
  return new Promise((resolve) => {
    let out = '';
    let done = false;
    const finish = (): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(out);
    };
    const child = spawn('/usr/sbin/scutil', [], { stdio: ['pipe', 'pipe', 'ignore'] });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish();
    }, CMD_TIMEOUT_MS);
    child.stdout.on('data', (c: Buffer) => (out += c.toString()));
    child.on('error', finish);
    child.on('close', finish);
    child.stdin.end(`${script}\nquit\n`);
  });
}

async function readDnsEntries(): Promise<DnsResolverEntry[]> {
  const keysOut = await runScutil(
    'list State:/Network/Service/[^/]+/DNS\nlist Setup:/Network/Service/[^/]+/DNS'
  );
  const keys = dedupe(
    keysOut
      .split('\n')
      .map((l) => /=\s*((?:State|Setup):\/Network\/Service\/[^/\s]+\/DNS)\s*$/.exec(l)?.[1])
      .filter((k): k is string => !!k)
  ).slice(0, 64);
  const entries: DnsResolverEntry[] = [];
  if (keys.length > 0) {
    const shown = await runScutil(keys.map((k) => `show ${k}`).join('\n'));
    entries.push(...storeDnsEntries(parseScutilDictionaries(shown)));
  }
  try {
    const { stdout } = await execFileAsync('/usr/sbin/scutil', ['--dns'], {
      timeout: CMD_TIMEOUT_MS,
    });
    entries.push(...parseScutilDnsResolvers(String(stdout)));
  } catch {
    /* scutil --dns 失败 → 只用动态库条目 */
  }
  return entries;
}

function ifaceIpv4Map(): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  try {
    for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
      out[name] = (addrs ?? [])
        .filter((a) => !a.internal && isIpv4(a.address))
        .map((a) => a.address);
    }
  } catch {
    /* 取不到接口 → 空 */
  }
  return out;
}

/** 识别当前的外部 VPN（macOS / Windows；其它平台或失败 → null）。 */
export function detectHostWorkVpn(ctx: WorkVpnHostContext): Promise<WorkVpnSnapshot | null> {
  if (process.platform === 'win32') return detectWinWorkVpn(ctx);
  return detectMacWorkVpn(ctx);
}

async function detectMacWorkVpn(ctx: WorkVpnHostContext): Promise<WorkVpnSnapshot | null> {
  if (process.platform !== 'darwin') return null;
  try {
    const [routesOut, dnsEntries] = await Promise.all([
      execFileAsync('/usr/sbin/netstat', ['-rn', '-f', 'inet'], { timeout: CMD_TIMEOUT_MS }),
      readDnsEntries(),
    ]);
    return detectWorkVpn({
      routes: parseMacNetstatRoutes(String(routesOut.stdout)),
      ifaceAddrs: ifaceIpv4Map(),
      ownTunAddrs: ctx.ownTunAddrs,
      ownMeshCidrs: ctx.ownMeshCidrs,
      ownTunExcludes: ctx.ownTunExcludes,
      dnsEntries,
    });
  } catch {
    return null;
  }
}

/**
 * Windows 网络快照：一次 PowerShell 拿齐网卡 / 地址 / 路由 / DNS / NRPT（每起一次 PowerShell 约 0.7–1 s，
 * 见 win-tun-adapter）。-Command 明文传参（-EncodedCommand 会被杀软深扫、冻结主进程）。网卡名可能是西里尔字母等，
 * 而 ConvertTo-Json 不转义非 ASCII、控制台代码页又随系统语言变 → 脚本自己把非 ASCII 转成 \uXXXX，输出纯 ASCII。
 */
const WIN_NET_SNAPSHOT_PS = [
  "$ErrorActionPreference = 'SilentlyContinue'",
  '$o = [ordered]@{',
  '  adapters = @(Get-NetAdapter -IncludeHidden | ForEach-Object { @{ n = $_.Name; d = $_.InterfaceDescription; status = [string]$_.Status } })',
  '  addrs = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { @{ n = $_.InterfaceAlias; a = $_.IPAddress } })',
  '  routes = @(Get-NetRoute -AddressFamily IPv4 | ForEach-Object { @{ n = $_.InterfaceAlias; p = $_.DestinationPrefix; g = $_.NextHop } })',
  '  dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { @{ n = $_.InterfaceAlias; s = @($_.ServerAddresses) } })',
  '  suffix = @(Get-DnsClient | ForEach-Object { @{ n = $_.InterfaceAlias; d = $_.ConnectionSpecificSuffix } })',
  // Effective NRPT may return System.Net.IPAddress objects. Emit strings before JSON serialization.
  '  nrpt = @(Get-DnsClientNrptPolicy -Effective | ForEach-Object { @{ ns = @($_.Namespace); s = @($_.NameServers | ForEach-Object { [string]$_ }) } })',
  '}',
  '$j = ConvertTo-Json -InputObject $o -Depth 4 -Compress',
  "'WORKVPN_JSON:' + [regex]::Replace($j, '[^\\x00-\\x7F]', { param($m) '\\u{0:x4}' -f [int][char]$m.Value })",
  // 被吞掉的非终止错误照样会让 powershell.exe 以 1 退出（见 win-tun-adapter），execFile 随之 reject。
  'exit 0',
].join('\n');
const WIN_PS_TIMEOUT_MS = 8000;

async function detectWinWorkVpn(ctx: WorkVpnHostContext): Promise<WorkVpnSnapshot | null> {
  if (process.platform !== 'win32') return null;
  try {
    const stdout = await execFileAsync(
      powershellPath(),
      ['-NoProfile', '-NonInteractive', '-Command', WIN_NET_SNAPSHOT_PS],
      { timeout: WIN_PS_TIMEOUT_MS, windowsHide: true, maxBuffer: 16 * 1024 * 1024 }
    ).then(
      (r) => String(r.stdout),
      (err: { stdout?: unknown }) => String(err?.stdout ?? '')
    );
    const line = stdout.split(/\r?\n/).find((l) => l.startsWith('WORKVPN_JSON:'));
    if (!line) return null;
    const parsed = parseWinNetSnapshot(line.slice('WORKVPN_JSON:'.length), ctx.ownTunName ?? '');
    if (!parsed) return null;
    return detectWorkVpn({
      ...parsed,
      ownTunAddrs: ctx.ownTunAddrs,
      ownMeshCidrs: ctx.ownMeshCidrs,
      ownTunExcludes: ctx.ownTunExcludes,
    });
  } catch {
    return null;
  }
}

/** 本机物理网卡（非隧道、非回环）网段：VPN 网段与之相交时不排除出 TUN（见 shared/work-vpn）。 */
export function getPhysicalLanCidrs(): string[] {
  const out: string[] = [];
  try {
    for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
      if (TUNNEL_IFACE_RE.test(name)) continue;
      for (const a of addrs ?? []) {
        if (!a.internal && a.cidr && isIpv4(a.address)) out.push(a.cidr);
      }
    }
  } catch {
    /* 取不到接口 → 空 */
  }
  return dedupe(out);
}

const MAX_PROFILE_FILES = 200;
const MAX_PROFILE_BYTES = 512 * 1024;

async function listProfileFiles(): Promise<string[]> {
  const home = os.homedir();
  const files: string[] = [];
  if (process.platform === 'win32') {
    await listWinProfileFiles(home, files);
    return files.slice(0, MAX_PROFILE_FILES);
  }
  const addDir = async (dir: string, match: RegExp): Promise<void> => {
    try {
      for (const name of await fsp.readdir(dir)) {
        if (match.test(name)) files.push(path.join(dir, name));
      }
    } catch {
      /* 客户端未安装 */
    }
  };
  const addNested = async (dir: string, inner: (entry: string) => string): Promise<void> => {
    try {
      for (const name of await fsp.readdir(dir)) files.push(path.join(dir, inner(name)));
    } catch {
      /* 客户端未安装 */
    }
  };
  // OpenVPN Connect
  await addDir(path.join(home, 'Library/Application Support/OpenVPN Connect/profiles'), /\.ovpn$/i);
  // Tunnelblick（私有 + 共享配置）
  const tblk = (n: string): string => path.join(n, 'Contents/Resources/config.ovpn');
  await addNested(path.join(home, 'Library/Application Support/Tunnelblick/Configurations'), tblk);
  await addNested('/Library/Application Support/Tunnelblick/Shared', tblk);
  // Viscosity
  await addNested(path.join(home, 'Library/Application Support/Viscosity/OpenVPN'), (n) =>
    path.join(n, 'config.conf')
  );
  return files.slice(0, MAX_PROFILE_FILES);
}

/** Windows：OpenVPN Connect、OpenVPN GUI（用户 / 全局配置目录，含一层子目录）、Viscosity。 */
async function listWinProfileFiles(home: string, files: string[]): Promise<void> {
  const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
  const ovpn = /\.ovpn$/i;
  const scan = async (dir: string, depth: number): Promise<void> => {
    let entries: Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return; // 客户端未安装
    }
    for (const e of entries) {
      if (files.length >= MAX_PROFILE_FILES) return;
      const full = path.join(dir, e.name);
      if (e.isFile() && ovpn.test(e.name)) files.push(full);
      else if (e.isDirectory() && depth > 0) await scan(full, depth - 1);
    }
  };
  await scan(path.join(appData, 'OpenVPN Connect', 'profiles'), 0);
  await scan(path.join(home, 'OpenVPN', 'config'), 1);
  await scan(path.join(programFiles, 'OpenVPN', 'config'), 1);
  await scan(path.join(programFiles, 'OpenVPN', 'config-auto'), 1);
  try {
    const dir = path.join(appData, 'Viscosity', 'OpenVPN');
    for (const name of await fsp.readdir(dir)) files.push(path.join(dir, name, 'config.conf'));
  } catch {
    /* Viscosity 未安装 */
  }
}

/** 本机 VPN 客户端配置文件里的服务器（remote）主机：IP 与域名。 */
export async function readVpnProfileRemotes(): Promise<string[]> {
  if (process.platform !== 'darwin' && process.platform !== 'win32') return [];
  const hosts: string[] = [];
  for (const file of await listProfileFiles()) {
    try {
      const st = await fsp.stat(file);
      if (!st.isFile() || st.size > MAX_PROFILE_BYTES) continue;
      hosts.push(...parseOpenVpnRemotes(await fsp.readFile(file, 'utf-8')));
    } catch {
      /* 读不了就跳过 */
    }
  }
  return dedupe(hosts);
}

/**
 * 解析 VPN 服务器域名为 IPv4（用于排除出 TUN）。丢弃 fakeip 段结果：FlowZ TUN 还在时系统解析可能拿到假 IP，
 * 那一轮先不排除（DNS 规则已让这些域名走真实解析，下次起核就能拿到真 IP）。
 */
export async function resolveVpnServerHosts(
  hosts: string[],
  fakeipRanges: string[],
  timeoutMs = 2000
): Promise<string[]> {
  const domains = hosts.filter((h) => !isIpv4(h)).slice(0, 32);
  const results = await Promise.all(
    domains.map(
      (h) =>
        new Promise<string[]>((resolve) => {
          const timer = setTimeout(() => resolve([]), timeoutMs);
          lookup(h, { family: 4, all: true })
            .then((addrs) => resolve(addrs.map((a) => a.address)))
            .catch(() => resolve([]))
            .finally(() => clearTimeout(timer));
        })
    )
  );
  return dedupe(results.flat()).filter(
    (ip) => isIpv4(ip) && !cidrOverlapsAny(`${ip}/32`, fakeipRanges)
  );
}
