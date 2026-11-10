/**
 * Xray / v2ray JSON 配置 → ServerConfig 解析（纯模块，刻意不 import electron，可直接 jest 单测）。
 *
 * 与 sing-box JSON 的差异：xray outbound 用 `protocol` + `settings`（vnext/servers）+ `streamSettings`，
 * 而 sing-box 用扁平 `type` + 同级字段。本模块只覆盖 FlowZ 已建模的主流协议；其余协议跳过并报告
 * （不透传 custom：custom 落点是 sing-box outbound schema，xray schema 不兼容）。
 *
 * 逐 outbound try/catch，单条失败不影响其它（对齐 ClashSubscriptionParser.parseClashProxies）。
 */
import { randomUUID } from 'crypto';
import type { ServerConfig, Network, Security } from '../../shared/types';
import { unsupportedVlessEncryption } from './ProtocolParser';
import { canUseXray, isXhttpNetwork, readXrayTcpFragment, requiresXray } from '../../shared/xray-node';

/** 本模块可映射的 xray outbound.protocol。 */
const XRAY_SUPPORTED = new Set(['vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria']);
/** xray 内部/非节点 outbound（忽略，不计入 skipped）。 */
const XRAY_INTERNAL = new Set(['freedom', 'blackhole', 'dns', 'loopback']);
/**
 * 可映射到 sing-box 的 streamSettings.network（raw = xray 新版对 tcp 的改名）。VLESS XHTTP 由 Xray 处理。
 * 整节点跳过——落回裸 TCP 会产出连不上的假节点（与 sing-box 订阅路径 SINGBOX_SUPPORTED_TRANSPORTS 同口径）。
 */
const XRAY_SUPPORTED_NETWORKS = new Set(['tcp', 'raw', 'ws', 'grpc', 'h2', 'http', 'httpupgrade']);

export interface XrayParseResult {
  servers: ServerConfig[];
  skipped: number; // 协议不支持
  failed: number; // 字段缺失 / 异常
  warnings: string[];
}

/** 标量规整：数字/字符串统一 String()，缺省 undefined。 */
function str(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return undefined;
}

function num(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && v.trim() && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

function xrayNetwork(stream: Record<string, unknown> | undefined): string {
  return (str(stream?.method) || str(stream?.network) || 'tcp').toLowerCase();
}

/** xray streamSettings → ServerConfig 传输/安全层字段。 */
function applyStreamSettings(server: ServerConfig, ss: Record<string, unknown> | undefined): void {
  if (!ss || typeof ss !== 'object') return;
  if (server.protocol === 'vless') {
    const fragment = readXrayTcpFragment(ss.finalmask);
    if (fragment) server.xrayTcpFragment = fragment;
  }

  // 传输层
  const network = xrayNetwork(ss);
  if (isXhttpNetwork(network)) {
    server.network = 'xhttp';
    const xhttp = (ss.xhttpSettings ?? ss.splithttpSettings ?? {}) as Record<string, unknown>;
    server.xhttpSettings = { path: str(xhttp.path), host: str(xhttp.host), mode: str(xhttp.mode) };
  } else if (network === 'ws') {
    server.network = 'ws';
    const ws = (ss.wsSettings as Record<string, unknown>) || {};
    const headers = (ws.headers as Record<string, unknown>) || {};
    const host = str(headers.Host) || str(headers.host);
    server.wsSettings = { path: str(ws.path) || '/', headers: host ? { Host: host } : undefined };
  } else if (network === 'grpc') {
    server.network = 'grpc';
    const grpc = (ss.grpcSettings as Record<string, unknown>) || {};
    server.grpcSettings = {
      serviceName: str(grpc.serviceName) || '',
      ...(grpc.multiMode === true ? { multiMode: true } : {}),
      ...(str(grpc.authority) ? { authority: str(grpc.authority) } : {}),
    };
  } else if (network === 'h2' || network === 'http') {
    server.network = 'http';
    const h2 = (ss.httpSettings as Record<string, unknown>) || {};
    const hostVal = h2.host;
    server.httpSettings = {
      path: str(h2.path) || '/',
      host: Array.isArray(hostVal)
        ? (hostVal as string[])
        : str(hostVal)
          ? [str(hostVal)!]
          : undefined,
    };
  } else if (network === 'httpupgrade') {
    server.network = 'httpupgrade';
    const hu = (ss.httpupgradeSettings as Record<string, unknown>) || {};
    const host = str(hu.host);
    server.wsSettings = { path: str(hu.path) || '/', headers: host ? { Host: host } : undefined };
  } else if (network !== 'hysteria') {
    server.network = 'tcp' as Network;
  }

  // 安全层
  const security = (str(ss.security) || 'none').toLowerCase();
  if (security === 'tls' || security === 'xtls') {
    server.security = 'tls' as Security;
    const tls = (ss.tlsSettings as Record<string, unknown>) || {};
    const alpn = tls.alpn;
    server.tlsSettings = {
      serverName: str(tls.serverName),
      allowInsecure: tls.allowInsecure === true,
      alpn: Array.isArray(alpn) ? (alpn as string[]) : undefined,
      fingerprint: str(tls.fingerprint) || 'chrome',
    };
  } else if (security === 'reality') {
    server.security = 'reality' as Security;
    const reality = (ss.realitySettings as Record<string, unknown>) || {};
    server.tlsSettings = {
      serverName: str(reality.serverName),
      fingerprint: str(reality.fingerprint) || 'chrome',
    };
    server.realitySettings = {
      publicKey: str(reality.password) || str(reality.publicKey) || '',
      shortId: str(reality.shortId),
      ...(str(reality.spiderX) ? { spiderX: str(reality.spiderX) } : {}),
      ...(str(reality.mldsa65Verify) ? { mldsa65Verify: str(reality.mldsa65Verify) } : {}),
    };
  } else {
    server.security = 'none' as Security;
  }
}

/** 单条 xray outbound → ServerConfig（失败 throw / 返回 null）。 */
function mapXrayOutbound(
  o: Record<string, unknown>,
  proto: string,
  now: string
): ServerConfig | null {
  const settings = (o.settings as Record<string, unknown>) || {};
  const tag = str(o.tag);

  const base = (address: string, port: number): ServerConfig => ({
    id: randomUUID(),
    name: tag || `${address}:${port}`,
    protocol: proto as ServerConfig['protocol'],
    address,
    port,
    createdAt: now,
    updatedAt: now,
  });

  if (proto === 'vmess' || proto === 'vless') {
    const vnext = (settings.vnext as Array<Record<string, unknown>>)?.[0] ??
      (proto === 'vless' ? settings : undefined);
    if (!vnext) return null;
    const address = str(vnext.address);
    const port = num(vnext.port);
    const user = (vnext.users as Array<Record<string, unknown>>)?.[0] ?? vnext;
    const uuid = str(user?.id);
    if (!address || !port || !uuid) return null;
    const server = base(address, port);
    server.uuid = uuid;
    if (proto === 'vmess') {
      server.alterId = num(user?.alterId) ?? 0;
      server.vmessSecurity = str(user?.security) || 'auto';
    } else {
      server.flow = str(user?.flow);
      const encryption = str(user?.encryption)?.trim();
      if (encryption) server.encryption = encryption;
    }
    applyStreamSettings(server, o.streamSettings as Record<string, unknown>);
    return server;
  }

  if (proto === 'trojan') {
    const srv = (settings.servers as Array<Record<string, unknown>>)?.[0];
    if (!srv) return null;
    const address = str(srv.address);
    const port = num(srv.port);
    const password = str(srv.password);
    if (!address || !port || !password) return null;
    const server = base(address, port);
    server.password = password;
    applyStreamSettings(server, o.streamSettings as Record<string, unknown>);
    return server;
  }

  if (proto === 'shadowsocks') {
    const srv = (settings.servers as Array<Record<string, unknown>>)?.[0];
    if (!srv) return null;
    const address = str(srv.address);
    const port = num(srv.port);
    const method = str(srv.method);
    const password = str(srv.password);
    if (!address || !port || !method || !password) return null;
    const server = base(address, port);
    server.shadowsocksSettings = { method, password };
    applyStreamSettings(server, o.streamSettings as Record<string, unknown>);
    return server;
  }

  if (proto === 'hysteria') {
    const stream = o.streamSettings as Record<string, unknown> | undefined;
    const hysteria = stream?.hysteriaSettings as Record<string, unknown> | undefined;
    const tls = stream?.tlsSettings as Record<string, unknown> | undefined;
    const address = str(settings.address);
    const port = num(settings.port);
    const password = str(hysteria?.auth);
    if (
      !address ||
      !port ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535 ||
      !password ||
      num(settings.version) !== 2 ||
      num(hysteria?.version) !== 2 ||
      str(stream?.security)?.toLowerCase() !== 'tls'
    )
      return null;
    // Do not turn a pinned connection into ordinary CA validation.
    if (tls && Object.keys(tls).some((key) => /^(?:pin|verifyPeerCert|certificate)/i.test(key))) {
      return null;
    }
    const mask = stream?.finalmask as { udp?: unknown } | undefined;
    const udpMasks = mask?.udp ?? [];
    if (!Array.isArray(udpMasks) || udpMasks.length > 1) return null;
    const server: ServerConfig = { ...base(address, port), protocol: 'hysteria2', password };
    applyStreamSettings(server, stream);
    if (udpMasks.length === 1) {
      const obfs = udpMasks[0];
      const obfsPassword = str(obfs?.settings?.password);
      if (obfs?.type !== 'salamander' || !obfsPassword) return null;
      server.hysteria2Settings = { obfs: { type: 'salamander', password: obfsPassword } };
    }
    return server;
  }

  return null;
}

/** 逐条映射 outbounds，不支持的协议/传输计入共享的 skipBy（供单配置与配置数组两条入口汇总成一条 warning）。 */
function collectXrayOutbounds(
  outbounds: unknown,
  now: string,
  skipBy: Map<string, number>
): { servers: ServerConfig[]; skipped: number; failed: number } {
  const servers: ServerConfig[] = [];
  let skipped = 0;
  let failed = 0;
  if (!Array.isArray(outbounds)) return { servers, skipped, failed };

  const skip = (key: string): void => {
    skipped++;
    skipBy.set(key, (skipBy.get(key) ?? 0) + 1);
  };

  for (const ob of outbounds) {
    if (!ob || typeof ob !== 'object') {
      failed++;
      continue;
    }
    const o = ob as Record<string, unknown>;
    const proto = (str(o.protocol) || '').toLowerCase();
    if (!XRAY_SUPPORTED.has(proto)) {
      if (!XRAY_INTERNAL.has(proto)) skip(proto || '(empty)');
      continue;
    }
    if (proto === 'vless') {
      const settings = o.settings as Record<string, unknown> | undefined;
      const users = (settings?.vnext as
          | Array<Record<string, unknown>>
          | undefined
      )?.[0]?.users as Array<Record<string, unknown>> | undefined;
      const encMethod = unsupportedVlessEncryption(users?.[0]?.encryption ?? settings?.encryption);
      if (encMethod) {
        skip(`vless+encryption:${encMethod}`);
        continue;
      }
    }
    const ss = o.streamSettings as Record<string, unknown> | undefined;
    const network = xrayNetwork(ss);
    const supported = proto === 'hysteria'
      ? network === 'hysteria'
      : XRAY_SUPPORTED_NETWORKS.has(network) || (proto === 'vless' && isXhttpNetwork(network));
    if (!supported) {
      skip(`${proto}+${network}`);
      continue;
    }
    if (isXhttpNetwork(network)) {
      const settings = (ss?.xhttpSettings ?? ss?.splithttpSettings ?? {}) as Record<string, unknown>;
      if (settings.downloadSettings || settings.extra) {
        skip('vless+XHTTP extra settings');
        continue;
      }
    }
    try {
      const server = mapXrayOutbound(o, proto, now);
      if (server && requiresXray(server) && !canUseXray(server)) skip('vless+Xray combination');
      else if (server) servers.push(server);
      else failed++;
    } catch {
      failed++;
    }
  }
  return { servers, skipped, failed };
}

function skipWarnings(skipped: number, skipBy: Map<string, number>): string[] {
  if (skipBy.size === 0) return [];
  const detail = [...skipBy.entries()].map(([p, c]) => `${p}(${c})`).join(', ');
  return [`Skipped ${skipped} unsupported Xray protocol(s): ${detail}`];
}

/** xray outbounds[] → ServerConfig[]，逐条 try/catch，聚合 skipped/failed/warnings。 */
export function parseXrayOutbounds(outbounds: unknown, now: string): XrayParseResult {
  const skipBy = new Map<string, number>();
  const { servers, skipped, failed } = collectXrayOutbounds(outbounds, now, skipBy);
  return { servers, skipped, failed, warnings: skipWarnings(skipped, skipBy) };
}

/**
 * 「Xray JSON 配置数组」：顶层是完整 xray 配置的数组，每项一个节点，名字在 `remarks`
 * （Remnawave / Marzban 等面板对 v2rayN、Happ、Streisand 类客户端返回此格式）。
 */
export function isXrayConfigArray(v: unknown): v is Array<Record<string, unknown>> {
  return (
    Array.isArray(v) &&
    v.length > 0 &&
    v.every(
      (c) => !!c && typeof c === 'object' && Array.isArray((c as { outbounds?: unknown }).outbounds)
    )
  );
}

/**
 * Xray JSON 配置数组 → ServerConfig[]。节点名取该配置的 remarks；一个配置含多个代理 outbound（如分流用的
 * 专用出口）时名字补上 tag 区分。面板常在每个配置里重复同一个共享出口 → 按连接参数去重，避免一份节点出现 N 次。
 */
export function parseXrayConfigArray(configs: unknown, now: string): XrayParseResult {
  const servers: ServerConfig[] = [];
  let skipped = 0;
  let failed = 0;
  const skipBy = new Map<string, number>();
  if (!isXrayConfigArray(configs)) return { servers, skipped, failed, warnings: [] };

  const seen = new Set<string>();
  for (const config of configs) {
    const r = collectXrayOutbounds(config.outbounds, now, skipBy);
    skipped += r.skipped;
    failed += r.failed;
    const remarks = str(config.remarks)?.trim();
    r.servers.forEach((server, i) => {
      if (remarks) {
        server.name =
          r.servers.length === 1 ? remarks : `${remarks} · ${str(server.name) || i + 1}`;
      }
      const { id: _id, name: _name, createdAt: _c, updatedAt: _u, ...params } = server;
      const key = JSON.stringify(params);
      if (seen.has(key)) return;
      seen.add(key);
      servers.push(server);
    });
  }
  return { servers, skipped, failed, warnings: skipWarnings(skipped, skipBy) };
}
