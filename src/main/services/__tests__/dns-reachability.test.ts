import * as net from 'net';
import {
  ensureYandexDnsPlan,
  getYandexDnsPlan,
  probeTcpReachable,
  resetYandexDnsPlanForTest,
} from '../dns-reachability';
import { DEFAULT_YANDEX_DNS_PLAN } from '../../../shared/dns-failover';

afterEach(() => resetYandexDnsPlanForTest());

const blocked = async (): Promise<Record<string, boolean>> => ({
  '77.88.8.8': false,
  '77.88.8.1': false,
  '77.88.8.88': true,
  '77.88.8.2': true,
});

describe('ensureYandexDnsPlan', () => {
  it('starts as the built-in defaults', () => {
    expect(getYandexDnsPlan()).toEqual(DEFAULT_YANDEX_DNS_PLAN);
  });

  it('stores the plan derived from the probe', async () => {
    const probe = jest.fn(blocked);
    const plan = await ensureYandexDnsPlan(0, { probe });
    expect(plan).toEqual({ primaryIp: '77.88.8.88', useSafePool: true });
    expect(getYandexDnsPlan()).toEqual(plan);
    expect(probe).toHaveBeenCalledWith(['77.88.8.8', '77.88.8.1', '77.88.8.88', '77.88.8.2']);
  });

  it('reuses a fresh result, but maxAge 0 forces a new probe', async () => {
    let t = 1000;
    const probe = jest.fn(blocked);
    const deps = { probe, now: () => t };
    await ensureYandexDnsPlan(0, deps);
    t += 1000;
    await ensureYandexDnsPlan(60_000, deps);
    expect(probe).toHaveBeenCalledTimes(1);
    t += 120_000;
    await ensureYandexDnsPlan(60_000, deps);
    expect(probe).toHaveBeenCalledTimes(2);
    await ensureYandexDnsPlan(0, deps);
    expect(probe).toHaveBeenCalledTimes(3);
  });

  it('lets concurrent callers share one probe', async () => {
    const probe = jest.fn(blocked);
    const [a, b] = await Promise.all([
      ensureYandexDnsPlan(0, { probe }),
      ensureYandexDnsPlan(0, { probe }),
    ]);
    expect(probe).toHaveBeenCalledTimes(1);
    expect(a).toEqual(b);
  });

  it('falls back to the defaults when the probe throws, and never rejects', async () => {
    await ensureYandexDnsPlan(0, { probe: blocked });
    const plan = await ensureYandexDnsPlan(0, {
      probe: async () => {
        throw new Error('boom');
      },
    });
    expect(plan).toEqual(DEFAULT_YANDEX_DNS_PLAN);
  });
});

describe('probeTcpReachable', () => {
  it('is true for a listening port and false for a closed one', async () => {
    const server = net.createServer((s) => s.destroy());
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const open = (server.address() as net.AddressInfo).port;
    try {
      await expect(probeTcpReachable('127.0.0.1', open, 1000)).resolves.toBe(true);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
    await expect(probeTcpReachable('127.0.0.1', open, 1000)).resolves.toBe(false);
  });
});
