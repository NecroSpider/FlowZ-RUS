import type { ServerConfig } from './types';
import type { XrayTcpFragment } from './types/protocol-settings';

function range(value: unknown): string | undefined {
  if (typeof value !== 'string' && typeof value !== 'number') return undefined;
  const parts = /^(\d{1,10})(?:-(\d{1,10}))?$/.exec(String(value));
  if (!parts) return undefined;
  const low = Number(parts[1]);
  const high = Number(parts[2] ?? parts[1]);
  if (low > high || high > 0x7fffffff) return undefined;
  return low === high ? String(low) : `${low}-${high}`;
}

function ranges(values: unknown): string[] | undefined {
  if (!Array.isArray(values) || !values.length || values.length > 32) return undefined;
  const parsed = values.map(range);
  return parsed.every((value): value is string => value !== undefined) ? parsed : undefined;
}

export function normalizeXrayTcpFragment(value: unknown): XrayTcpFragment | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const input = value as Record<string, unknown>;
  const packets = input.packets === 'tlshello' ? input.packets : range(input.packets);
  const lengths = ranges(input.lengths ?? [input.length]);
  const delays = ranges(input.delays ?? [input.delay ?? 0]);
  const maxSplit = range(input.maxSplit);
  if (
    !packets ||
    packets.split('-')[0] === '0' ||
    !lengths ||
    lengths[lengths.length - 1].split('-')[0] === '0' ||
    !delays
  ) {
    return undefined;
  }
  if (input.maxSplit !== undefined && maxSplit === undefined) return undefined;
  return { packets, lengths, delays, ...(maxSplit !== undefined && { maxSplit }) };
}

/** Project only the supported TCP fragment mask from a subscription. */
export function readXrayTcpFragment(value: unknown): XrayTcpFragment | undefined {
  if (value === undefined) return undefined;
  const mask = value as { tcp?: unknown } | null;
  if (mask && typeof mask === 'object' && !Array.isArray(mask)) {
    if (mask.tcp === undefined || (Array.isArray(mask.tcp) && mask.tcp.length === 0)) {
      return undefined;
    }
    if (Array.isArray(mask.tcp) && mask.tcp.length === 1 && mask.tcp[0]?.type === 'fragment') {
      const fragment = normalizeXrayTcpFragment(mask.tcp[0].settings);
      if (fragment) return fragment;
    }
  }
  throw new Error('Unsupported transport type: Xray TCP FinalMask');
}

export function isXrayVlessEncryption(value: unknown): value is `mlkem768x25519plus.${string}` {
  return typeof value === 'string' && value.startsWith('mlkem768x25519plus.');
}

export function isXhttpNetwork(value: string | undefined): boolean {
  return value === 'xhttp' || value === 'splithttp';
}

export function requiresXray(server: ServerConfig): boolean {
  return (
    server.protocol === 'vless' &&
    (isXrayVlessEncryption(server.encryption) ||
      server.network === 'xhttp' ||
      Boolean(server.xrayTcpFragment) ||
      Boolean(server.realitySettings?.mldsa65Verify))
  );
}

export function canUseXray(server: ServerConfig): boolean {
  const tls = server.tlsSettings;
  const network = server.network ?? 'tcp';
  return (
    server.protocol === 'vless' &&
    Boolean(server.uuid) &&
    (!server.xrayTcpFragment || Boolean(normalizeXrayTcpFragment(server.xrayTcpFragment))) &&
    ['tcp', 'grpc', 'xhttp', 'ws', 'httpupgrade'].includes(network) &&
    (!server.security || ['none', 'tls', 'reality'].includes(server.security)) &&
    (server.security !== 'reality' || Boolean(server.realitySettings?.publicKey)) &&
    !server.detour &&
    !server.multiplexSettings?.enabled &&
    !server.shadowTlsSettings &&
    (!server.packetEncoding || server.packetEncoding === 'xudp') &&
    !tls?.ech &&
    !tls?.echConfig &&
    !tls?.fragment &&
    !tls?.spoofMethod &&
    (server.security !== 'tls' || !tls?.allowInsecure) &&
    (!tls?.engine || tls.engine === 'go') &&
    // The bridge only carries TCP transports to the VLESS server.
    !tls?.alpn?.some((value) => value.startsWith('h3')) &&
    !server.wsSettings?.maxEarlyData &&
    !server.wsSettings?.earlyDataHeaderName
  );
}

export function wantsXray(server: ServerConfig, preferReality?: boolean): boolean {
  return (
    requiresXray(server) ||
    (preferReality === true && server.security === 'reality' && canUseXray(server))
  );
}
