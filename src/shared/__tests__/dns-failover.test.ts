import {
  DEFAULT_YANDEX_DNS_PLAN,
  applyYandexDnsPlanToPool,
  isDefaultYandexDnsPlan,
  planYandexDns,
  yandexDohUrl,
} from '../dns-failover';

const reach = (ok: string[]): Record<string, boolean> =>
  Object.fromEntries(
    ['77.88.8.8', '77.88.8.1', '77.88.8.88', '77.88.8.2'].map((ip) => [ip, ok.includes(ip)])
  );

describe('planYandexDns', () => {
  it('keeps the built-in defaults when the primary addresses answer', () => {
    expect(planYandexDns(reach(['77.88.8.8', '77.88.8.1', '77.88.8.88', '77.88.8.2']))).toEqual(
      DEFAULT_YANDEX_DNS_PLAN
    );
    expect(planYandexDns(reach(['77.88.8.8']))).toEqual(DEFAULT_YANDEX_DNS_PLAN);
  });

  it('moves bootstrap/domestic to 77.88.8.1 when only 77.88.8.8 is blocked, race pool untouched', () => {
    const plan = planYandexDns(reach(['77.88.8.1', '77.88.8.88']));
    expect(plan).toEqual({ primaryIp: '77.88.8.1', useSafePool: false });
  });

  it('falls back to the Safe pair when both primary addresses are blocked (the VK report)', () => {
    // 2026-11-09: TCP 443 to 77.88.8.8, 77.88.8.1 and 8.8.8.8 closed; 77.88.8.88 open.
    expect(planYandexDns(reach(['77.88.8.88']))).toEqual({
      primaryIp: '77.88.8.88',
      useSafePool: true,
    });
    expect(planYandexDns(reach(['77.88.8.2']))).toEqual({
      primaryIp: '77.88.8.2',
      useSafePool: true,
    });
  });

  it('changes nothing when nothing answers (offline / probe failed)', () => {
    expect(planYandexDns(reach([]))).toEqual(DEFAULT_YANDEX_DNS_PLAN);
    expect(planYandexDns({})).toEqual(DEFAULT_YANDEX_DNS_PLAN);
  });

  it('isDefaultYandexDnsPlan tells a changed plan from the default', () => {
    expect(isDefaultYandexDnsPlan(DEFAULT_YANDEX_DNS_PLAN)).toBe(true);
    expect(isDefaultYandexDnsPlan({ primaryIp: '77.88.8.1', useSafePool: false })).toBe(false);
    expect(isDefaultYandexDnsPlan({ primaryIp: '77.88.8.88', useSafePool: true })).toBe(false);
  });
});

describe('applyYandexDnsPlanToPool', () => {
  const safe = { primaryIp: '77.88.8.88', useSafePool: true };

  it("swaps only the Yandex ids when the Safe pool is in use, keeping order and the user's other picks", () => {
    expect(applyYandexDnsPlanToPool(['yandex', 'yandex2'], safe)).toEqual([
      'yandexSafe',
      'yandexSafe2',
    ]);
    expect(applyYandexDnsPlanToPool(['ali', 'yandex', 'custom-1', 'system'], safe)).toEqual([
      'ali',
      'yandexSafe',
      'custom-1',
      'system',
    ]);
  });

  it('does not add a duplicate when the user already picked a Safe id', () => {
    expect(applyYandexDnsPlanToPool(['yandex', 'yandexSafe'], safe)).toEqual(['yandexSafe']);
  });

  it('returns the pool unchanged for the default plan and for a primary-only change', () => {
    expect(applyYandexDnsPlanToPool(['yandex', 'yandex2'], DEFAULT_YANDEX_DNS_PLAN)).toEqual([
      'yandex',
      'yandex2',
    ]);
    expect(
      applyYandexDnsPlanToPool(['yandex'], { primaryIp: '77.88.8.1', useSafePool: false })
    ).toEqual(['yandex']);
  });

  it('does not mutate its input', () => {
    const pool = ['yandex', 'yandex2'];
    applyYandexDnsPlanToPool(pool, safe);
    expect(pool).toEqual(['yandex', 'yandex2']);
  });
});

describe('yandexDohUrl', () => {
  it('builds the domesticDns form', () => {
    expect(yandexDohUrl('77.88.8.88')).toBe('https://77.88.8.88/dns-query');
  });
});
