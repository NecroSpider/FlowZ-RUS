import * as http2 from 'http2';
import {
  ensureYandexDnsPlan,
  getYandexDnsPlan,
  resetYandexDnsPlanForTest,
} from '../dns-reachability';
import { DEFAULT_YANDEX_DNS_PLAN } from '../../../shared/dns-failover';
import { buildAnswerResponse, buildServfail } from '../../../shared/dns-wire';
import { h2DohQuery } from '../node-dns-race-server';

jest.mock('http2', () => ({ connect: jest.fn() }));
jest.mock('../node-dns-race-server', () => ({ h2DohQuery: jest.fn() }));

afterEach(() => {
  jest.resetAllMocks();
  resetYandexDnsPlanForTest();
});

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

  it('tries the built-in alternatives only when both Yandex pairs fail', async () => {
    const probe = jest
      .fn(async () => ({}) as Record<string, boolean>)
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ '1.12.12.12': true });
    const plan = await ensureYandexDnsPlan(0, { probe });
    expect(probe).toHaveBeenNthCalledWith(2, ['223.5.5.5', '1.12.12.12']);
    expect(plan).toEqual({ primaryIp: '1.12.12.12', useSafePool: false, fallbackPool: ['dnspod'] });
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

describe('DoH reachability', () => {
  it('uses Safe when the primary addresses connect but return SERVFAIL', async () => {
    const destroy = jest.fn();
    jest
      .mocked(http2.connect)
      .mockImplementation(
        (authority) =>
          ({ authority, on: jest.fn(), destroy }) as unknown as http2.ClientHttp2Session
      );
    jest.mocked(h2DohQuery).mockImplementation(async (session, _path, query) => {
      const origin = (session as unknown as { authority: string }).authority;
      if (origin === 'https://77.88.8.88') {
        return buildAnswerResponse(query, [{ type: 1, rdata: Uint8Array.of(192, 0, 2, 1) }]);
      }
      return buildServfail(query);
    });

    await expect(ensureYandexDnsPlan(0)).resolves.toEqual({
      primaryIp: '77.88.8.88',
      useSafePool: true,
    });
    expect(destroy).toHaveBeenCalledTimes(4);
  });
});
