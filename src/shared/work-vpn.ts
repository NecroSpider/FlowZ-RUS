/**
 * 「与工作 VPN 共存」纯逻辑（macOS + Windows）：识别 OpenVPN / Cisco / Tunnelblick 等**外部** VPN 隧道下发的路由与 DNS，
 * 让 FlowZ 与其并行工作而不互相干扰。真机现象（OpenVPN Connect + FlowZ TUN，2026-11-02）：
 *  - VPN 连在 FlowZ 之后时，OpenVPN 为服务器装的旁路路由走的是 FlowZ 的 TUN 网关（`<server>/32 → 172.19.0.1`），
 *    VPN 自身的传输层穿过 sing-box，FlowZ 一重启 / 该 IP 落到代理规则，VPN 就断；服务器域名还可能拿到 fakeip。
 *  - VPN 推送的网段可能是公网段（如 175.175.0.0/16）：凡经 FlowZ 进入 sing-box 的流量（fakeip / 本地代理口）
 *    都会按规则走代理节点或被 auto_detect_interface 绑到物理网卡，内部资源不可达。
 *  - 系统 DNS 由「后启动的一方」接管：FlowZ 接管时内部域名被解析成 fakeip → 走代理。
 *
 * 对策（均为 sing-box 配置层，由 applyWorkVpnToSingBoxConfig 注入）：
 *  1. VPN 网段 + VPN 服务器 IP 进 TUN route_exclude_address —— OS 直接交给 VPN，FlowZ 不再碰它们；
 *  2. 经 sing-box 的 VPN 网段 / 内部域名流量 → 绑定 VPN 接口的 direct 出站（TUN 下必须显式绑，否则被绑到物理网卡）；
 *  3. 内部域名 → VPN 推送的 DNS（绑定 VPN 接口）；VPN 不推域名时用 evaluate 探测：先问 VPN DNS，
 *     答案落在 VPN 网段才采纳，否则继续 FlowZ 原有解析（fakeip 等），无需用户手填域名；
 *  4. VPN 服务器域名走真实解析 + 直连，VPN 客户端进程直连。
 */

import { isIpv4, cidrContains, cidrOverlapsAny } from './ip';
import { dedupe } from './collections';

// ── 路由表（netstat -rn -f inet）────────────────────────────────────────────────────────────

export interface RouteEntry {
  /** 规范 CIDR（a.b.c.d/n）。 */
  cidr: string;
  gateway: string;
  flags: string;
  iface: string;
}

/** 有类网络的自然掩码（netstat 对自然掩码的网络不打印 /n）。 */
function classfulPrefix(firstOctet: number): number {
  if (firstOctet < 128) return 8;
  if (firstOctet < 192) return 16;
  if (firstOctet < 224) return 24;
  return 32;
}

/**
 * netstat 的目的地列 → 规范 CIDR。BSD netstat 会截掉尾部 0 段，且自然掩码不打印前缀：
 * `default`→0.0.0.0/0、`1`→1.0.0.0/8、`175.175`→175.175.0.0/16、`10.175/24`→10.175.0.0/24、
 * `192.168.252`→192.168.252.0/24；带 H 标志的是主机路由（/32）。IPv6 / 无法识别 → null。
 */
export function netstatDestinationToCidr(dest: string, flags: string): string | null {
  const d = dest.trim();
  if (!d) return null;
  if (d === 'default') return '0.0.0.0/0';
  if (d.includes(':') || d.includes('%')) return null;
  const [addr, prefixPart] = d.split('/');
  const octets = addr.split('.');
  if (octets.length < 1 || octets.length > 4 || octets.some((o) => !/^\d{1,3}$/.test(o))) {
    return null;
  }
  const nums = octets.map(Number);
  if (nums.some((n) => n > 255)) return null;
  while (nums.length < 4) nums.push(0);
  let prefix: number;
  if (prefixPart !== undefined) {
    prefix = Number(prefixPart);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  } else if (flags.includes('H') || octets.length === 4) {
    // 主机路由；或四段齐全却无前缀（网络地址的尾 0 段会被截掉，四段齐全只可能是主机）。
    prefix = 32;
  } else {
    prefix = classfulPrefix(nums[0]);
  }
  return `${nums.join('.')}/${prefix}`;
}

/** 解析 `netstat -rn -f inet` 输出（只取 Internet 段的数据行）。 */
export function parseMacNetstatRoutes(stdout: string): RouteEntry[] {
  const out: RouteEntry[] = [];
  for (const raw of stdout.split('\n')) {
    const cols = raw.trim().split(/\s+/);
    if (cols.length < 4 || cols[0] === 'Destination' || cols[0] === 'Routing') continue;
    const [dest, gateway, flags, iface] = cols;
    if (!/^[a-z]+\d*$/.test(iface)) continue;
    const cidr = netstatDestinationToCidr(dest, flags);
    if (!cidr) continue;
    out.push({ cidr, gateway, flags, iface });
  }
  return out;
}

// ── DNS（scutil）───────────────────────────────────────────────────────────────────────────

export interface DnsResolverEntry {
  servers: string[];
  domains: string[];
  /** true = 仅对 domains 生效的补充解析器（SupplementalMatchDomains / scutil --dns 的 `domain`）。 */
  supplemental: boolean;
}

/**
 * 解析 scutil 交互模式 `show <key>` 打印的若干 `<dictionary> { … }`（仅取一层标量与字符串数组，足够读 DNS 键）。
 * 输入可为多个字典首尾相接。返回每个字典的键值表。
 */
export function parseScutilDictionaries(stdout: string): Array<Record<string, string | string[]>> {
  const dicts: Array<Record<string, string | string[]>> = [];
  let cur: Record<string, string | string[]> | null = null;
  let arrKey: string | null = null;
  let depth = 0;
  for (const raw of stdout.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('<dictionary>') && depth === 0) {
      cur = {};
      dicts.push(cur);
      depth = 1;
      continue;
    }
    if (!cur) continue;
    if (line === '}') {
      if (arrKey) arrKey = null;
      depth--;
      if (depth <= 0) cur = null;
      continue;
    }
    const m = /^([^:]+?)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const [, key, value] = m;
    if (arrKey && /^\d+$/.test(key)) {
      (cur[arrKey] as string[]).push(value);
      continue;
    }
    if (value.startsWith('<array>')) {
      arrKey = key;
      cur[key] = [];
      depth++;
    } else if (value.startsWith('<dictionary>')) {
      depth++; // 嵌套字典不展开（DNS 键不需要）
    } else if (depth === 1) {
      cur[key] = value;
    }
  }
  return dicts;
}

const asList = (v: string | string[] | undefined): string[] =>
  v === undefined ? [] : Array.isArray(v) ? v : [v];

/** 动态库 `State:/Setup:/Network/Service/<id>/DNS` 字典 → 解析器条目（补充域名与全局条目各一条）。 */
export function storeDnsEntries(
  dicts: Array<Record<string, string | string[]>>
): DnsResolverEntry[] {
  const out: DnsResolverEntry[] = [];
  for (const d of dicts) {
    const servers = asList(d.ServerAddresses).filter(isIpv4);
    if (servers.length === 0) continue;
    const supplementalDomains = asList(d.SupplementalMatchDomains);
    if (supplementalDomains.length > 0) {
      out.push({ servers, domains: supplementalDomains, supplemental: true });
    }
    out.push({
      servers,
      domains: [...asList(d.SearchDomains), ...asList(d.DomainName)],
      supplemental: false,
    });
  }
  return out;
}

/**
 * `scutil --dns` → 只取带 `domain` 的补充解析器（per-domain 分流 DNS，NetworkExtension 型 VPN 常只出现在这里）。
 * 全局解析器的 search domain 是主服务合并来的，不能据此认定归属 VPN，故不收。
 */
export function parseScutilDnsResolvers(stdout: string): DnsResolverEntry[] {
  const out: DnsResolverEntry[] = [];
  for (const block of stdout.split(/\nresolver #\d+\n/).slice(1)) {
    const servers: string[] = [];
    let domain: string | null = null;
    let mdns = false;
    for (const raw of block.split('\n')) {
      const line = raw.trim();
      if (line.startsWith('DNS configuration')) break;
      const ns = /^nameserver\[\d+\]\s*:\s*(\S+)/.exec(line);
      if (ns && isIpv4(ns[1])) servers.push(ns[1]);
      const dm = /^domain\s*:\s*(\S+)/.exec(line);
      if (dm) domain = dm[1];
      if (/^options\s*:.*mdns/.test(line)) mdns = true;
    }
    if (domain && !mdns && servers.length > 0) {
      out.push({ servers, domains: [domain], supplemental: true });
    }
  }
  return out;
}

/** 规范化内部域名：小写、去首尾点；拒 IP、.local / .arpa（各有专门解析路径）与非法字符。 */
export function normalizeWorkDomain(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  const d = raw
    .trim()
    .toLowerCase()
    .replace(/^\*?\.+/, '')
    .replace(/\.+$/, '');
  if (!d || d.length > 253) return null;
  if (isIpv4(d) || d.includes(':')) return null;
  if (!/^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(d)) return null;
  if (d === 'local' || d.endsWith('.arpa') || d === 'arpa') return null;
  return d;
}

// ── 识别 ───────────────────────────────────────────────────────────────────────────────────

/** 外部隧道接口名（OpenVPN/Tunnelblick=utun|tun|tap，IPsec/L2TP=ipsec|ppp，GlobalProtect=gpd，ZeroTier=feth|zt）。 */
const TUNNEL_IFACE_RE = /^(utun|ipsec|ppp|tun|tap|gpd|wg|zt|feth)\d+$/;

/** 不当作 VPN 网段的地址：链路本地 / 组播 / 广播 / 回环 / 0 段。 */
const IGNORED_CIDRS = ['169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '127.0.0.0/8', '0.0.0.0/8'];

/** 前缀短于 /8 视为全隧道（0/1+128/1、default），不当作「VPN 网段」排除/直连。 */
const MIN_VPN_PREFIX = 8;

export interface WorkVpnInterface {
  name: string;
  addresses: string[];
  /** VPN 推送的网段（已去重、去掉被同接口更大网段包含的子段）。 */
  cidrs: string[];
  /** 属于该 VPN 的 DNS 服务器（IPv4，按发现顺序）。 */
  dnsServers: string[];
  /** VPN 下发的内部域名（规范化）。 */
  domains: string[];
  /** 该接口承载 0/1+128/1 / default（全隧道 VPN）。 */
  fullTunnel: boolean;
}

export interface WorkVpnSnapshot {
  interfaces: WorkVpnInterface[];
  /**
   * 经 FlowZ 自家 TUN 网关的 /32 主机路由 = 外部 VPN 客户端在 FlowZ 之后连上时为其服务器装的旁路路由
   * （它以为默认网关是 FlowZ 的 TUN）。只用于下次起核时把这些 IP 排除出 TUN。
   */
  serverIps: string[];
}

export interface WorkVpnDetectInput {
  routes: RouteEntry[];
  /** 接口名 → 其 IPv4 地址（os.networkInterfaces）。 */
  ifaceAddrs: Record<string, string[]>;
  /** FlowZ 自家 TUN 的 IPv4 地址（不带掩码；含本会话用过的全部）。 */
  ownTunAddrs: string[];
  /** FlowZ 自家组网系统接口（WG/Tailscale system interface）的地址段：落在其中的接口不是外部 VPN。 */
  ownMeshCidrs: string[];
  /** FlowZ 当前 TUN 的 route_exclude_address：用于认出 sing-tun 自己拆出来的 /32 补集路由。 */
  ownTunExcludes: string[];
  dnsEntries: DnsResolverEntry[];
  /** 外部隧道接口名单（Windows 按网卡驱动描述认出，见 parseWinNetSnapshot）；缺省按 macOS 接口名正则认。 */
  tunnelIfaces?: string[];
}

function ipv4ToInt(ip: string): number {
  const o = ip.split('.').map(Number);
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

function intToIpv4(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function prefixOf(cidr: string): number {
  return Number(cidr.split('/')[1]);
}

/** 去掉被同组更大网段包含的子段，保持原顺序。 */
function collapseContained(cidrs: string[]): string[] {
  const uniq = dedupe(cidrs);
  return uniq.filter((c) => !uniq.some((o) => o !== c && cidrContains(o, c)));
}

/** ip 命中的最长前缀 VPN 接口名；无 → null。 */
function vpnIfaceForIp(ip: string, ifaces: WorkVpnInterface[]): string | null {
  let best: { name: string; prefix: number } | null = null;
  for (const it of ifaces) {
    for (const c of it.cidrs) {
      if (cidrContains(c, `${ip}/32`) && (!best || prefixOf(c) > best.prefix)) {
        best = { name: it.name, prefix: prefixOf(c) };
      }
    }
  }
  return best?.name ?? null;
}

export function detectWorkVpn(input: WorkVpnDetectInput): WorkVpnSnapshot {
  const ownTun = new Set(input.ownTunAddrs.filter(isIpv4));
  const isOwnAddr = (addr: string): boolean =>
    ownTun.has(addr) || cidrOverlapsAny(`${addr}/32`, input.ownMeshCidrs);

  const isTunnel = (name: string): boolean =>
    input.tunnelIfaces ? input.tunnelIfaces.includes(name) : TUNNEL_IFACE_RE.test(name);
  const vpnIfaces = new Map<string, WorkVpnInterface>();
  for (const [name, addrs] of Object.entries(input.ifaceAddrs)) {
    const v4 = (addrs || []).filter(isIpv4);
    if (!isTunnel(name) || v4.length === 0) continue;
    if (v4.some(isOwnAddr)) continue;
    vpnIfaces.set(name, {
      name,
      addresses: v4,
      cidrs: [],
      dnsServers: [],
      domains: [],
      fullTunnel: false,
    });
  }

  const serverIps: string[] = [];
  for (const r of input.routes) {
    const vpn = vpnIfaces.get(r.iface);
    if (vpn) {
      // 先剔整段落在忽略区里的（Windows 每张网卡都挂 224.0.0.0/4 组播路由，前缀 /4 会被误当全隧道）；
      // 只剔「被包含」的，0/1、default 与 0.0.0.0/8 相交但不被包含，仍要标全隧道。
      if (IGNORED_CIDRS.some((ig) => cidrContains(ig, r.cidr))) continue;
      const prefix = prefixOf(r.cidr);
      if (prefix < MIN_VPN_PREFIX) {
        vpn.fullTunnel = true;
        continue;
      }
      if (cidrOverlapsAny(r.cidr, IGNORED_CIDRS)) continue;
      const host = r.cidr.split('/')[0];
      if (prefix === 32 && vpn.addresses.includes(host)) continue;
      vpn.cidrs.push(r.cidr);
      continue;
    }
    // 经 FlowZ TUN 网关的 /32：外部 VPN 客户端的服务器旁路路由。sing-tun 拆排除段时也会产出 /32 补集片，
    // 它们的「兄弟」/32 必然落在某个排除段里 —— 据此区分，不把自家路由误当 VPN 服务器。
    if (prefixOf(r.cidr) !== 32 || !ownTun.has(r.gateway)) continue;
    const ip = r.cidr.split('/')[0];
    if (ownTun.has(ip)) continue;
    const sibling = `${intToIpv4(ipv4ToInt(ip) ^ 1)}/32`;
    if (cidrOverlapsAny(sibling, input.ownTunExcludes)) continue;
    serverIps.push(ip);
  }

  const ifaces = Array.from(vpnIfaces.values()).filter((v) => v.cidrs.length > 0 || v.fullTunnel);
  for (const v of ifaces) v.cidrs = collapseContained(v.cidrs);

  // DNS 归属：补充解析器（只管特定域名）里落在 VPN 网段的服务器即 VPN DNS；全局条目须**全部**服务器都走 VPN
  // 才算 VPN 自己的（办公网 DHCP 下发的 [内网 DNS, 网关, 8.8.8.8] 这类混合条目不算，哪怕其中一个碰巧被 VPN 路由）。
  for (const e of input.dnsEntries) {
    const owners = e.servers.map((s) => vpnIfaceForIp(s, ifaces));
    if (!e.supplemental && owners.some((o) => o === null)) continue;
    e.servers.forEach((server, i) => {
      const owner = owners[i];
      if (!owner) return;
      const it = ifaces.find((v) => v.name === owner);
      if (!it) return;
      if (!it.dnsServers.includes(server)) it.dnsServers.push(server);
      for (const raw of e.domains) {
        const d = normalizeWorkDomain(raw);
        if (d && !it.domains.includes(d)) it.domains.push(d);
      }
    });
  }

  ifaces.sort((a, b) => a.name.localeCompare(b.name));
  return { interfaces: ifaces, serverIps: dedupe(serverIps) };
}

// ── Windows（PowerShell NetTCPIP / DnsClient 快照）──────────────────────────────────────────

/**
 * 外部 VPN 虚拟网卡的驱动描述（InterfaceDescription 是驱动字符串，不随系统语言本地化；网卡名则可能是
 * 「Ethernet 2」「Подключение по локальной сети 2」之类，认不出来）。
 */
const WIN_VPN_ADAPTER_RE =
  /tap-windows|wintun|openvpn|wireguard|anyconnect|cisco|fortinet|forticlient|pangp|globalprotect|juniper|pulse secure|ivanti|sonicwall|netextender|check ?point|zerotier|wan miniport|tunnel/i;

/** work-vpn-detector 的 PowerShell 脚本输出的 JSON（键名缩写；任一段取不到即缺省）。 */
interface WinNetSnapshotJson {
  adapters?: Array<{ n?: string; d?: string }>;
  addrs?: Array<{ n?: string; a?: string }>;
  routes?: Array<{ n?: string; p?: string; g?: string }>;
  dns?: Array<{ n?: string; s?: string[] }>;
  suffix?: Array<{ n?: string; d?: string }>;
  nrpt?: Array<{ ns?: string[]; s?: string[] }>;
}

export interface WinWorkVpnInputs {
  routes: RouteEntry[];
  ifaceAddrs: Record<string, string[]>;
  tunnelIfaces: string[];
  dnsEntries: DnsResolverEntry[];
}

const asArray = <T>(v: T[] | T | undefined | null): T[] =>
  v === undefined || v === null ? [] : Array.isArray(v) ? v : [v];

/**
 * 解析 Windows 网络快照（Get-NetAdapter / Get-NetIPAddress / Get-NetRoute / Get-DnsClientServerAddress /
 * Get-DnsClient / Get-DnsClientNrptPolicy）。外部 VPN 网卡 = 驱动描述命中 WIN_VPN_ADAPTER_RE，或不在网卡列表里却有
 * 地址（系统自带 IKEv2/L2TP/SSTP 等 RAS 连接不是 NDIS 网卡）；FlowZ 自家 TUN 按名排除。
 * DNS：VPN 网卡上配置的服务器 + 连接专用后缀、NRPT 分域规则，都按补充解析器处理（服务器须落在 VPN 网段才采纳）。
 * 无法解析 → null。
 */
export function parseWinNetSnapshot(json: string, ownTunName: string): WinWorkVpnInputs | null {
  let raw: WinNetSnapshotJson;
  try {
    raw = JSON.parse(json) as WinNetSnapshotJson;
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;
  const own = ownTunName.toLowerCase();
  const str = (v: unknown): string => (typeof v === 'string' ? v : '');

  const ifaceAddrs: Record<string, string[]> = {};
  for (const a of asArray(raw.addrs)) {
    const name = str(a?.n);
    const ip = str(a?.a);
    if (!name || !isIpv4(ip) || ip.startsWith('127.') || ip.startsWith('169.254.')) continue;
    (ifaceAddrs[name] ??= []).push(ip);
  }

  const adapters = asArray(raw.adapters).filter((a) => str(a?.n));
  const adapterNames = new Set(adapters.map((a) => str(a.n)));
  const tunnelIfaces = new Set<string>();
  for (const a of adapters) {
    if (WIN_VPN_ADAPTER_RE.test(str(a.d))) tunnelIfaces.add(str(a.n));
  }
  // 网卡列表为空（CIM 被拦等）时不做「不在列表里」推断，否则所有接口都成了 VPN。
  if (adapterNames.size > 0) {
    for (const name of Object.keys(ifaceAddrs)) {
      if (!adapterNames.has(name)) tunnelIfaces.add(name);
    }
  }
  for (const name of [...tunnelIfaces]) {
    if (name.toLowerCase() === own) tunnelIfaces.delete(name);
  }

  const routes: RouteEntry[] = [];
  for (const r of asArray(raw.routes)) {
    const iface = str(r?.n);
    const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(str(r?.p));
    if (!iface || !m || !isIpv4(m[1]) || Number(m[2]) > 32) continue;
    routes.push({ cidr: `${m[1]}/${m[2]}`, gateway: str(r?.g), flags: '', iface });
  }

  const suffixOf = new Map<string, string>();
  for (const s of asArray(raw.suffix)) {
    if (str(s?.n) && str(s?.d)) suffixOf.set(str(s.n), str(s.d));
  }
  const dnsEntries: DnsResolverEntry[] = [];
  for (const d of asArray(raw.dns)) {
    const name = str(d?.n);
    if (!tunnelIfaces.has(name)) continue;
    const servers = asArray(d.s).map(str).filter(isIpv4);
    if (servers.length === 0) continue;
    const suffix = suffixOf.get(name);
    dnsEntries.push({ servers, domains: suffix ? [suffix] : [], supplemental: true });
  }
  for (const n of asArray(raw.nrpt)) {
    const servers = asArray(n?.s).map(str).filter(isIpv4);
    const domains = asArray(n?.ns).map(str).filter(Boolean);
    if (servers.length > 0 && domains.length > 0) {
      dnsEntries.push({ servers, domains, supplemental: true });
    }
  }

  return { routes, ifaceAddrs, tunnelIfaces: [...tunnelIfaces], dnsEntries };
}

/**
 * DNS 粘性：FlowZ 接管系统 DNS 会覆盖 VPN 写进主服务的 DNS（OpenVPN Connect 即如此），之后就读不到了。
 * 同名同地址的接口仍在 → 沿用上次读到的 VPN DNS/域名，避免指纹来回翻转触发无限重启。
 */
export function mergeStickyWorkVpnDns(
  current: WorkVpnSnapshot,
  previous: WorkVpnSnapshot | null
): WorkVpnSnapshot {
  if (!previous) return current;
  const interfaces = current.interfaces.map((it) => {
    if (it.dnsServers.length > 0) return it;
    const prev = previous.interfaces.find(
      (p) => p.name === it.name && p.addresses.join(',') === it.addresses.join(',')
    );
    return prev ? { ...it, dnsServers: prev.dnsServers, domains: prev.domains } : it;
  });
  return { ...current, interfaces };
}

/** 决定是否需要重起核的指纹（不含 serverIps：它们只在下次起核生效，且起核后自家 TUN 消失其路由也随之消失）。 */
export function workVpnFingerprint(s: WorkVpnSnapshot | null): string {
  if (!s || s.interfaces.length === 0) return '';
  return JSON.stringify(
    s.interfaces.map((it) => [
      it.name,
      [...it.cidrs].sort(),
      [...it.dnsServers].sort(),
      [...it.domains].sort(),
      it.fullTunnel,
    ])
  );
}

/** 一行摘要（日志 / 设置页状态）。 */
export function describeWorkVpn(s: WorkVpnSnapshot | null): string {
  if (!s || s.interfaces.length === 0) return '';
  return s.interfaces
    .map(
      (it) =>
        `${it.name}: ${it.cidrs.join(', ') || '-'}` +
        (it.dnsServers.length ? ` · DNS ${it.dnsServers.join(', ')}` : '') +
        (it.domains.length ? ` · ${it.domains.join(', ')}` : '') +
        (it.fullTunnel ? ' · full-tunnel' : '')
    )
    .join(' | ');
}

// ── VPN 客户端配置文件（.ovpn）────────────────────────────────────────────────────────────

/** 从 OpenVPN 配置文本取 `remote <host> [port] [proto]` 的 host（含 <connection> 块内的）。 */
export function parseOpenVpnRemotes(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split('\n')) {
    const m = /^\s*remote\s+(\S+)/.exec(raw);
    if (!m) continue;
    const host = m[1].trim().toLowerCase();
    if (isIpv4(host) || normalizeWorkDomain(host) === host) out.push(host);
  }
  return dedupe(out);
}

/** 自身走物理网卡、必须直连的 VPN 客户端进程（其传输层若被 TUN 捕获，按进程兜底直连）。macOS 名 + Windows 可执行文件名。 */
export const VPN_CLIENT_PROCESS_NAMES = [
  'OpenVPN Connect',
  'openvpn',
  'ovpnagent',
  'Tunnelblick',
  'Viscosity',
  'vpnagentd',
  'Cisco Secure Client',
  'FortiClient',
  'fctservctl2',
  'PanGPS',
  'GlobalProtect',
  'openconnect',
  'openvpn.exe',
  'openvpnserv.exe',
  'vpnagent.exe',
  'FortiSSLVPNdaemon.exe',
  'PanGPS.exe',
  'wireguard.exe',
  'openconnect.exe',
];

/**
 * Windows：按安装目录认 VPN 客户端进程。OpenVPN Connect 的隧道进程名带版本时间戳（agent_ovpnconnect_<数字>.exe），
 * 按名单匹配不到；sing-box 的 process_path_regex 是 RE2，(?i) 不分大小写。
 */
export const WIN_VPN_CLIENT_PATH_REGEX = [
  String.raw`(?i)\\OpenVPN Connect\\[^\\]+\.exe$`,
  String.raw`(?i)\\OpenVPN\\bin\\[^\\]+\.exe$`,
  String.raw`(?i)\\Cisco\\Cisco (AnyConnect Secure Mobility Client|Secure Client)\\[^\\]+\.exe$`,
  String.raw`(?i)\\Fortinet\\FortiClient\\[^\\]+\.exe$`,
  String.raw`(?i)\\Palo Alto Networks\\GlobalProtect\\[^\\]+\.exe$`,
  String.raw`(?i)\\WireGuard\\[^\\]+\.exe$`,
];

// ── 注入 sing-box 配置 ────────────────────────────────────────────────────────────────────

/** 本模块只读写 sing-box 配置的这几处结构；用宽松形状避免 shared 依赖 main 的类型文件。 */
interface LooseConfig {
  dns?: { servers: Array<Record<string, unknown>>; rules?: Array<Record<string, unknown>> };
  inbounds: Array<Record<string, unknown>>;
  outbounds: Array<Record<string, unknown>>;
  route?: { rules?: Array<Record<string, unknown>> };
}

export interface WorkVpnApplyInput {
  snapshot: WorkVpnSnapshot | null;
  /** VPN 服务器 IP（路由识别的 + 配置文件解析出来的），IPv4。 */
  serverIps: string[];
  /** VPN 服务器域名（配置文件里的 remote）。 */
  serverHosts: string[];
  /** 用户手填的内部域名（规范化前）。 */
  userDomains: string[];
  /** 自动识别内部域名（evaluate 探测）。 */
  autoDetectDomains: boolean;
  tunMode: boolean;
  /** 节点域名同款真实解析器 tag（VPN 服务器域名用它，不能落 fakeip）。 */
  realResolverTag: string;
  /** 本机物理网卡网段：VPN 网段与之相交时不排除出 TUN（macOS NE 反向路由会丢回包，见 tun-route-exclude）。 */
  ownLanCidrs: string[];
  /** fakeip 段：与之相交的不排除。 */
  fakeipRanges: string[];
  /** 'win32' 时另按安装目录认 VPN 客户端进程（WIN_VPN_CLIENT_PATH_REGEX）。 */
  platform?: string;
}

export interface WorkVpnApplyResult {
  /** 是否发射了 evaluate 探测规则（1.14 新语法；起核前需额外 check 一次以便失败时回退）。 */
  usedEvaluate: boolean;
  /** 追加进 TUN route_exclude_address 的段。 */
  tunExcludes: string[];
  logs: Array<{ level: 'info' | 'warn'; message: string }>;
}

export const WORK_VPN_OUTBOUND_PREFIX = 'work-vpn-';
export const WORK_VPN_DNS_PREFIX = 'work-vpn-dns-';
/**
 * VPN DNS 探测超时：VPN 掉线但接口未拆时（OpenVPN keepalive 超时前可达一分钟），**每个**新域名都多等这么久。
 * 真机实证 1.5s 足以让整机上网瘫痪，故压到 500ms（内网 DNS 经 VPN 的 RTT 实测 30–60ms），且该探测默认关闭。
 */
const EVALUATE_TIMEOUT = '500ms';

/**
 * DNS 规则里是否有 1.14 之前的「旧式地址过滤」用法（未配 match_response 的 ip_cidr/ip_is_private/ip_accept_any、
 * 规则级 strategy、rule_set_ip_cidr_accept_empty、引用 geoip 规则集）。有则不能再混用 evaluate/match_response，
 * 否则内核启动即拒（sing-box 1.14.0 changelog #13）。
 */
export function dnsRulesUseLegacyAddressFilter(rules: Array<Record<string, unknown>>): boolean {
  const check = (r: Record<string, unknown>): boolean => {
    if (r.match_response) return false;
    if ('ip_cidr' in r || 'ip_is_private' in r || 'ip_accept_any' in r) return true;
    if ('strategy' in r || 'rule_set_ip_cidr_accept_empty' in r) return true;
    const rs = r.rule_set;
    const tags = Array.isArray(rs) ? rs : typeof rs === 'string' ? [rs] : [];
    if (tags.some((t) => typeof t === 'string' && t.startsWith('geoip'))) return true;
    const sub = r.rules;
    return Array.isArray(sub) && sub.some((x) => check(x as Record<string, unknown>));
  };
  return rules.some(check);
}

function safeTagPart(name: string): string {
  return name.replace(/[^A-Za-z0-9_-]/g, '_');
}

/**
 * 把工作 VPN 的路由 / DNS / 服务器直连注入已生成的 sing-box 配置（原地修改）。
 * 无 VPN 接口且无服务器信息时为 no-op。
 */
export function applyWorkVpnToSingBoxConfig(
  cfg: LooseConfig,
  input: WorkVpnApplyInput
): WorkVpnApplyResult {
  const result: WorkVpnApplyResult = { usedEvaluate: false, tunExcludes: [], logs: [] };
  const ifaces = (input.snapshot?.interfaces ?? []).filter(
    (it) => it.cidrs.length > 0 || it.dnsServers.length > 0
  );
  const serverIps = dedupe(input.serverIps.filter(isIpv4));
  const serverHosts = dedupe(input.serverHosts.filter((h) => !isIpv4(h)));
  if (ifaces.length === 0 && serverIps.length === 0 && serverHosts.length === 0) return result;

  const dnsRules = cfg.dns?.rules;
  const routeRules = cfg.route?.rules;
  const userDomains = dedupe(
    input.userDomains.map(normalizeWorkDomain).filter((d): d is string => !!d)
  );
  // 用户手填的内部域名归第一个带 DNS 的 VPN（多 VPN 并存时无从判断归属，取首个）。
  const primaryIface = ifaces.find((it) => it.dnsServers.length > 0) ?? null;
  const domainsOf = (it: WorkVpnInterface): string[] =>
    dedupe([...it.domains, ...(it === primaryIface ? userDomains : [])]);

  // ── 出站：每个 VPN 接口一个 direct 出站（TUN 下绑接口，防被 auto_detect_interface 绑到物理网卡）──
  const outboundTag = new Map<string, string>();
  const dnsTagsByIface = new Map<string, string[]>();
  let dnsIdx = 0;
  for (const it of ifaces) {
    const tags: string[] = [];
    for (const server of it.dnsServers.slice(0, 2)) {
      const tag = `${WORK_VPN_DNS_PREFIX}${dnsIdx++}`;
      cfg.dns?.servers.push({
        tag,
        type: 'udp',
        server,
        ...(input.tunMode ? { bind_interface: it.name } : {}),
      });
      tags.push(tag);
    }
    dnsTagsByIface.set(it.name, tags);
    if (input.tunMode) {
      const tag = `${WORK_VPN_OUTBOUND_PREFIX}${safeTagPart(it.name)}`;
      cfg.outbounds.push({
        type: 'direct',
        tag,
        bind_interface: it.name,
        ...(tags.length > 0 ? { domain_resolver: tags[0] } : {}),
      });
      outboundTag.set(it.name, tag);
    } else {
      // 非 TUN 无回环风险、未开 auto_detect_interface：普通 direct 即服从 OS 路由进 VPN。
      outboundTag.set(it.name, 'direct');
    }
  }

  // ── DNS 规则：插在 bootstrap 规则之后（节点域名 / DoH 自身解析等内部规则仍优先）──
  if (dnsRules) {
    let at = dnsRules.findIndex((r) => r.server === 'dns-bootstrap' && Array.isArray(r.domain));
    if (at < 0) {
      at = -1;
      dnsRules.forEach((r, i) => {
        if (r.inbound !== undefined) at = i;
      });
    }
    const add: Array<Record<string, unknown>> = [];
    if (serverHosts.length > 0) {
      add.push({ domain: serverHosts, server: input.realResolverTag });
    }
    for (const it of ifaces) {
      const tags = dnsTagsByIface.get(it.name) ?? [];
      if (tags.length === 0) continue;
      const domains = domainsOf(it);
      if (domains.length > 0) {
        add.push({ domain: domains, domain_suffix: domains.map((d) => `.${d}`), server: tags[0] });
      }
    }
    const probeIfaces = ifaces.filter(
      (it) => it.cidrs.length > 0 && (dnsTagsByIface.get(it.name) ?? []).length > 0
    );
    if (input.autoDetectDomains && probeIfaces.length > 0) {
      if (dnsRulesUseLegacyAddressFilter(dnsRules)) {
        result.logs.push({
          level: 'warn',
          message:
            '工作 VPN：DNS 规则含旧式地址过滤，不能与 evaluate 混用，已跳过内部域名自动识别（可手动填写内部域名）',
        });
      } else {
        for (const it of probeIfaces) {
          add.push({
            query_type: ['A'],
            action: 'evaluate',
            server: (dnsTagsByIface.get(it.name) ?? [])[0],
            timeout: EVALUATE_TIMEOUT,
          });
          add.push({ match_response: true, ip_cidr: it.cidrs, action: 'respond' });
        }
        result.usedEvaluate = true;
      }
    }
    dnsRules.splice(at + 1, 0, ...add);
  }

  // ── 路由规则：插在 hijack-dns 之后（无则 sniff / inbound 键控规则之后），先于一切代理 / 私网直连规则 ──
  if (routeRules) {
    let at = routeRules.findIndex((r) => r.action === 'hijack-dns');
    if (at < 0) {
      at = -1;
      routeRules.forEach((r, i) => {
        if (r.action === 'sniff' || r.inbound !== undefined) at = i;
      });
    }
    const add: Array<Record<string, unknown>> = [
      { process_name: VPN_CLIENT_PROCESS_NAMES, action: 'route', outbound: 'direct' },
    ];
    if (input.platform === 'win32') {
      add.push({
        process_path_regex: WIN_VPN_CLIENT_PATH_REGEX,
        action: 'route',
        outbound: 'direct',
      });
    }
    if (serverIps.length > 0 || serverHosts.length > 0) {
      add.push({
        ...(serverIps.length > 0 ? { ip_cidr: serverIps.map((ip) => `${ip}/32`) } : {}),
        ...(serverHosts.length > 0 ? { domain: serverHosts } : {}),
        action: 'route',
        outbound: 'direct',
      });
    }
    for (const it of ifaces) {
      const outbound = outboundTag.get(it.name) ?? 'direct';
      if (it.cidrs.length > 0) add.push({ ip_cidr: it.cidrs, action: 'route', outbound });
      const domains = domainsOf(it);
      if (domains.length > 0) {
        add.push({
          domain: domains,
          domain_suffix: domains.map((d) => `.${d}`),
          action: 'route',
          outbound,
        });
      }
    }
    routeRules.splice(at + 1, 0, ...add);
  }

  // ── TUN 排除：VPN 网段 + VPN 服务器 IP 交给 OS 直接走 VPN / 物理网卡 ──
  const tun = cfg.inbounds.find((ib) => ib.type === 'tun');
  if (tun) {
    const candidates = [
      ...ifaces.flatMap((it) => it.cidrs),
      ...serverIps.map((ip) => `${ip}/32`),
    ].filter(
      (c) =>
        prefixOf(c) >= MIN_VPN_PREFIX &&
        !cidrOverlapsAny(c, input.fakeipRanges) &&
        !cidrOverlapsAny(c, input.ownLanCidrs)
    );
    const existing = Array.isArray(tun.route_exclude_address)
      ? (tun.route_exclude_address as string[])
      : [];
    const added = candidates.filter((c) => !existing.includes(c));
    if (added.length > 0) {
      tun.route_exclude_address = dedupe([...existing, ...added]);
      result.tunExcludes = added;
    }
  }

  const fullTunnel = ifaces.filter((it) => it.fullTunnel).map((it) => it.name);
  if (fullTunnel.length > 0) {
    result.logs.push({
      level: 'warn',
      message: `工作 VPN ${fullTunnel.join(', ')} 为全隧道（接管默认路由），FlowZ 的出站会经它转发；建议在 VPN 客户端里关闭 redirect-gateway`,
    });
  }
  return result;
}
