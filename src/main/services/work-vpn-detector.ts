/**
 * 「与工作 VPN 共存」的系统探测层（macOS）：读路由表 / scutil DNS / 本机接口 / VPN 客户端配置文件，
 * 交 shared/work-vpn 的纯函数识别。全部 best-effort：任何命令失败都返回空结果，绝不阻断起核。
 */

import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import * as os from 'os';
import * as path from 'path';
import { promises as fsp } from 'fs';
import { lookup } from 'dns/promises';
import {
  detectWorkVpn,
  parseMacNetstatRoutes,
  parseScutilDictionaries,
  storeDnsEntries,
  parseScutilDnsResolvers,
  parseOpenVpnRemotes,
  type DnsResolverEntry,
  type WorkVpnSnapshot,
} from '../../shared/work-vpn';
import { isIpv4, cidrOverlapsAny } from '../../shared/ip';
import { dedupe } from '../../shared/collections';

const execFileAsync = promisify(execFile);
const CMD_TIMEOUT_MS = 4000;
const TUNNEL_IFACE_RE = /^(utun|ipsec|ppp|tun|tap|gpd|wg|zt|feth)\d+$/;

export interface WorkVpnHostContext {
  ownTunAddrs: string[];
  ownMeshCidrs: string[];
  ownTunExcludes: string[];
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

/** 识别当前的外部 VPN（非 macOS / 失败 → null）。 */
export async function detectMacWorkVpn(ctx: WorkVpnHostContext): Promise<WorkVpnSnapshot | null> {
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

/** 本机 VPN 客户端配置文件里的服务器（remote）主机：IP 与域名。 */
export async function readVpnProfileRemotes(): Promise<string[]> {
  if (process.platform !== 'darwin') return [];
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
