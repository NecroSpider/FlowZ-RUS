/**
 * Choosing the Yandex DoH addresses that are actually reachable on this network.
 *
 * FlowZ's default DNS stack (dns-bootstrap, the domestic DNS and the node-domain race pool) is built on two addresses,
 * 77.88.8.8 and 77.88.8.1. If neither answers DNS queries, try the same operator's "Safe" mode
 * on 77.88.8.88 / 77.88.8.2, followed by the built-in AliDNS and DNSPod DoH servers.
 * Probes live in main/services/dns-reachability.ts.
 */
import {
  DOH_ALIDNS_IP,
  DOH_DNSPOD_IP,
  DOH_YANDEX_ALT_IP,
  DOH_YANDEX_IP,
  DOH_YANDEX_SAFE_ALT_IP,
  DOH_YANDEX_SAFE_IP,
} from './dns';

/** Primary pair first, then the Safe-mode reserve pair. */
export const YANDEX_PRIMARY_IPS: readonly string[] = [DOH_YANDEX_IP, DOH_YANDEX_ALT_IP];
export const YANDEX_SAFE_IPS: readonly string[] = [DOH_YANDEX_SAFE_IP, DOH_YANDEX_SAFE_ALT_IP];
export const YANDEX_PROBE_IPS: readonly string[] = [...YANDEX_PRIMARY_IPS, ...YANDEX_SAFE_IPS];
const FALLBACK_DOH = [
  { id: 'ali', ip: DOH_ALIDNS_IP },
  { id: 'dnspod', ip: DOH_DNSPOD_IP },
] as const;
export const FALLBACK_DOH_IPS = FALLBACK_DOH.map(({ ip }) => ip);

export interface YandexDnsPlan {
  /**
   * IP used for dns-bootstrap and for the default domestic DNS. null = keep the built-in default (77.88.8.8):
   * either it is reachable, or nothing was reachable at all (probe failed / offline) and changing it would not help.
   */
  primaryIp: string | null;
  /** true = the primary pair is down and the Safe pair is up: race pool entries yandex/yandex2 become yandexSafe/yandexSafe2. */
  useSafePool: boolean;
  /** Reachable built-in alternatives when neither Yandex pair answered. */
  fallbackPool?: readonly (typeof FALLBACK_DOH)[number]['id'][];
  /** A probe ran but none of the built-in endpoints answered. */
  unavailable?: true;
}

export const DEFAULT_YANDEX_DNS_PLAN: YandexDnsPlan = { primaryIp: null, useSafePool: false };

/**
 * @param reachable ip -> returned a usable DoH answer. Missing keys are treated as unreachable.
 */
export function planYandexDns(reachable: Readonly<Record<string, boolean>>): YandexDnsPlan {
  const ok = (ip: string): boolean => reachable[ip] === true;
  const primary = YANDEX_PRIMARY_IPS.find(ok);
  if (primary) {
    // 77.88.8.8 is the default; only when it alone is blocked do we move bootstrap/domestic to the other primary address.
    return { primaryIp: primary === DOH_YANDEX_IP ? null : primary, useSafePool: false };
  }
  const safe = YANDEX_SAFE_IPS.find(ok);
  if (safe) return { primaryIp: safe, useSafePool: true };
  const fallbacks = FALLBACK_DOH.filter(({ ip }) => ok(ip));
  if (fallbacks.length > 0) {
    return {
      primaryIp: fallbacks[0].ip,
      useSafePool: false,
      fallbackPool: fallbacks.map(({ id }) => id),
    };
  }
  return { ...DEFAULT_YANDEX_DNS_PLAN, unavailable: true };
}

/** Whether the plan changes anything compared to the built-in defaults. */
export function isDefaultYandexDnsPlan(plan: YandexDnsPlan): boolean {
  return plan.primaryIp === null && !plan.useSafePool;
}

/**
 * Apply the plan to the user's node-resolver pool (ids of built-in upstreams). Only the Yandex ids are swapped, and only
 * when the primary pair is down; anything the user picked on purpose (Ali, DNSPod, custom IPs, system) is left alone.
 */
export function applyYandexDnsPlanToPool(
  poolIds: readonly string[],
  plan: YandexDnsPlan
): string[] {
  const fallback = plan.fallbackPool?.[0];
  if (!plan.useSafePool && !fallback) return [...poolIds];
  const swap: Record<string, string> = fallback
    ? { yandex: fallback, yandex2: plan.fallbackPool?.[1] ?? fallback }
    : { yandex: 'yandexSafe', yandex2: 'yandexSafe2' };
  const out: string[] = [];
  for (const id of poolIds) {
    const next = swap[id] ?? id;
    if (!out.includes(next)) out.push(next);
  }
  return out;
}

/** https://<ip>/dns-query, the form used for dnsConfig.domesticDns. */
export function ipDohUrl(ip: string): string {
  return `https://${ip}/dns-query`;
}
