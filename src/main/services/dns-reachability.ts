/**
 * Probes which Yandex DoH addresses answer on this network and keeps the resulting plan for the session
 * (see shared/dns-failover.ts for why). Everything that builds a DNS config reads the plan through
 * getYandexDnsPlan(): ProxyManager (dns-bootstrap, domestic DNS, race pool) and SpeedTestService (dns-direct).
 */
import * as http2 from 'http2';
import {
  classifyDnsResponse,
  decodeDnsAnswers,
  decodeDnsQuestion,
  encodeDnsQuery,
} from '../../shared/dns-wire';
import {
  DEFAULT_YANDEX_DNS_PLAN,
  FALLBACK_DOH_IPS,
  YANDEX_PROBE_IPS,
  planYandexDns,
  type YandexDnsPlan,
} from '../../shared/dns-failover';
import { h2DohQuery } from './node-dns-race-server';

const PROBE_DOMAIN = 'example.com';
const PROBE_QUERY = encodeDnsQuery(PROBE_DOMAIN);

export type ReachabilityProbe = (ips: readonly string[]) => Promise<Record<string, boolean>>;

/** Use fresh sessions so a reconnect tests the current network and cannot reuse an old route. */
const probeAllDoh: ReachabilityProbe = async (ips) =>
  Object.fromEntries(
    await Promise.all(
      ips.map(async (ip) => {
        try {
          const session = http2.connect(`https://${ip}`);
          session.on('error', () => {}); // Stream errors are handled by h2DohQuery.
          try {
            const response = await h2DohQuery(
              session,
              '/dns-query',
              PROBE_QUERY,
              AbortSignal.timeout(2500)
            );
            const question = decodeDnsQuestion(response);
            const answered =
              question?.qname.toLowerCase() === PROBE_DOMAIN &&
              question.id === 0 &&
              question.qtype === 1 &&
              question.qclass === 1 &&
              classifyDnsResponse(response, 1) === 'HIT' &&
              decodeDnsAnswers(response).length > 0;
            return [ip, answered];
          } finally {
            session.destroy();
          }
        } catch {
          return [ip, false];
        }
      })
    )
  );

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
  const probe = deps.probe ?? probeAllDoh;
  inflight = (async () => {
    try {
      const yandex = await probe(YANDEX_PROBE_IPS);
      const plan = planYandexDns(yandex);
      currentPlan = plan.unavailable
        ? planYandexDns({ ...yandex, ...(await probe(FALLBACK_DOH_IPS)) })
        : plan;
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
