/**
 * Choosing the Yandex DoH addresses that are actually reachable on this network.
 *
 * FlowZ's default DNS stack (dns-bootstrap, the domestic DNS and the node-domain race pool) is built on two addresses,
 * 77.88.8.8 and 77.88.8.1. Some networks block exactly those (seen: TCP 443 to 77.88.8.8, 77.88.8.1 and 8.8.8.8 closed
 * while 77.88.8.88 was open); every domain that goes direct then fails to resolve ("SERVFAIL"), including Russian sites
 * such as VK. The same operator also serves "Safe" mode on 77.88.8.88 / 77.88.8.2, so the app probes the addresses at
 * start and falls back to those. Pure logic only: the probing itself lives in main/services/dns-reachability.ts.
 */
import {
  DOH_YANDEX_ALT_IP,
  DOH_YANDEX_IP,
  DOH_YANDEX_SAFE_ALT_IP,
  DOH_YANDEX_SAFE_IP,
} from './dns';

/** Primary pair first, then the Safe-mode reserve pair. */
export const YANDEX_PRIMARY_IPS: readonly string[] = [DOH_YANDEX_IP, DOH_YANDEX_ALT_IP];
export const YANDEX_SAFE_IPS: readonly string[] = [DOH_YANDEX_SAFE_IP, DOH_YANDEX_SAFE_ALT_IP];
export const YANDEX_PROBE_IPS: readonly string[] = [...YANDEX_PRIMARY_IPS, ...YANDEX_SAFE_IPS];

export interface YandexDnsPlan {
  /**
   * IP used for dns-bootstrap and for the default domestic DNS. null = keep the built-in default (77.88.8.8):
   * either it is reachable, or nothing was reachable at all (probe failed / offline) and changing it would not help.
   */
  primaryIp: string | null;
  /** true = the primary pair is down and the Safe pair is up: race pool entries yandex/yandex2 become yandexSafe/yandexSafe2. */
  useSafePool: boolean;
}

export const DEFAULT_YANDEX_DNS_PLAN: YandexDnsPlan = { primaryIp: null, useSafePool: false };

/**
 * @param reachable ip -> TCP 443 reachable. Missing key = not probed = treated as unreachable.
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
  return DEFAULT_YANDEX_DNS_PLAN;
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
  if (!plan.useSafePool) return [...poolIds];
  const swap: Record<string, string> = { yandex: 'yandexSafe', yandex2: 'yandexSafe2' };
  const out: string[] = [];
  for (const id of poolIds) {
    const next = swap[id] ?? id;
    if (!out.includes(next)) out.push(next);
  }
  return out;
}

/** https://<ip>/dns-query, the form used for dnsConfig.domesticDns. */
export function yandexDohUrl(ip: string): string {
  return `https://${ip}/dns-query`;
}
