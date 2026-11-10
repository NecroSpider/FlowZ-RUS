/**
 * Probes which Yandex DoH addresses answer on this network and keeps the resulting plan for the session
 * (see shared/dns-failover.ts for why). Everything that builds a DNS config reads the plan through
 * getYandexDnsPlan(): ProxyManager (dns-bootstrap, domestic DNS, race pool) and SpeedTestService (dns-direct).
 */
import * as net from 'net';
import {
  DEFAULT_YANDEX_DNS_PLAN,
  YANDEX_PROBE_IPS,
  planYandexDns,
  type YandexDnsPlan,
} from '../../shared/dns-failover';

/** One TCP connect. true = the connection was established within the timeout. Never rejects. */
export function probeTcpReachable(ip: string, port = 443, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const sock = net.connect({ host: ip, port });
    const done = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(ok);
    };
    const timer = setTimeout(() => done(false), timeoutMs);
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
  });
}

export type ReachabilityProbe = (ips: readonly string[]) => Promise<Record<string, boolean>>;

/** Probes all addresses in parallel. */
export const probeAllTcp: ReachabilityProbe = async (ips) => {
  const results = await Promise.all(ips.map((ip) => probeTcpReachable(ip)));
  const out: Record<string, boolean> = {};
  ips.forEach((ip, i) => (out[ip] = results[i]));
  return out;
};

let currentPlan: YandexDnsPlan = DEFAULT_YANDEX_DNS_PLAN;
let planAt = 0;
let inflight: Promise<YandexDnsPlan> | null = null;

/** The plan chosen by the most recent probe (the built-in defaults until one has run). */
export function getYandexDnsPlan(): YandexDnsPlan {
  return currentPlan;
}

/**
 * Runs a probe unless a recent result exists. `maxAgeMs` 0 forces a fresh probe. Concurrent callers share one probe.
 * Never rejects: a failed probe leaves the defaults in place.
 */
export async function ensureYandexDnsPlan(
  maxAgeMs: number,
  deps: { probe?: ReachabilityProbe; now?: () => number } = {}
): Promise<YandexDnsPlan> {
  const now = deps.now ?? Date.now;
  if (maxAgeMs > 0 && planAt > 0 && now() - planAt < maxAgeMs) return currentPlan;
  if (inflight) return inflight;
  const probe = deps.probe ?? probeAllTcp;
  inflight = (async () => {
    try {
      currentPlan = planYandexDns(await probe(YANDEX_PROBE_IPS));
      planAt = now();
    } catch {
      currentPlan = DEFAULT_YANDEX_DNS_PLAN;
    }
    return currentPlan;
  })().finally(() => {
    inflight = null;
  });
  return inflight;
}

/** Test hook: back to the built-in defaults, no probe result. */
export function resetYandexDnsPlanForTest(): void {
  currentPlan = DEFAULT_YANDEX_DNS_PLAN;
  planAt = 0;
  inflight = null;
}
