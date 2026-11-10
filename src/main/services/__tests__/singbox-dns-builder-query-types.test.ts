/**
 * DNS 泄漏（2026-11 审计 #4）：所有 catch-all 都限定 A/AAAA 时，HTTPS/SVCB/TXT 等查询落 final=dns-domestic
 * （境内 DoH、隧道外）——浏览器每次打开页面都发 HTTPS-RR 查询，等于把每个境外域名交给境内解析器。
 * 钉住：① 其余类型按与 A/AAAA 真实解析同一套二分路由（region-local → 境内，其余 → 经隧道）；
 * ② 新规则在链尾，不遮蔽任何更早的规则（工作 VPN 内网域名、内网/PTR、captive、银行、节点域名、bootstrap）。
 */
jest.mock('../../utils/paths', () => ({
  getUserDataPath: () => '/tmp/flowz-dns-qtype-test',
  getCustomRulesDir: () => '/tmp/flowz-dns-qtype-test/rules',
}));
jest.mock('../builtin-geo-rulesets', () => ({
  ...jest.requireActual('../builtin-geo-rulesets'),
  isValidSrsFile: () => true,
}));

import { buildDnsConfig } from '../singbox-dns-builder';
import { buildIdToTagMap } from '../singbox-config-helpers';
import { applyWorkVpnToSingBoxConfig } from '../../../shared/work-vpn';
import type { UserConfig } from '../../../shared/types';

type Rule = Record<string, unknown>;

const config = (over: Partial<UserConfig> = {}): UserConfig =>
  ({
    servers: [{ id: 's1', name: 'HK', protocol: 'vless', address: 'node.example.com', port: 443 }],
    selectedServerId: 's1',
    proxyMode: 'smart',
    proxyModeType: 'tun',
    enableIPv6: false,
    ...over,
  }) as unknown as UserConfig;

const build = (c: UserConfig) =>
  buildDnsConfig(c, 'proxy-selector', null, buildIdToTagMap(c.servers), () => {});

/** 不带任何匹配条件（除 rule_set 外）的规则 = 对任意域名生效。 */
const MATCH_KEYS = [
  'domain',
  'domain_suffix',
  'domain_keyword',
  'inbound',
  'preferred_by',
  'process_name',
  'match_response',
];

/** 对「类型 qtype、不在任何具体清单里的普通域名」首个命中的规则（rule_set 视为不命中，返回第一条无条件规则）。 */
function firstCatchAllFor(rules: Rule[], qtype: string): Rule | undefined {
  return rules.find((r) => {
    const qt = r.query_type as string[] | undefined;
    if (qt && !qt.includes(qtype)) return false;
    if (MATCH_KEYS.some((k) => k in r)) return false;
    if ('rule_set' in r) return false;
    return !r.action || r.action === 'route';
  });
}

describe('#4 非 A/AAAA 查询不再落到隧道外的境内解析器', () => {
  it('TUN + FakeIP（默认）+ smart：HTTPS 查询的兜底 = dns-remote（经隧道），region-local 规则集 → 境内', () => {
    const dns = build(config());
    const rules = dns.rules as Rule[];
    expect(dns.final).toBe('dns-domestic');

    const httpsCatchAll = firstCatchAllFor(rules, 'HTTPS');
    expect(httpsCatchAll?.server).toBe('dns-remote');
    // A 仍先命中 fakeip（行为不变）
    expect(firstCatchAllFor(rules, 'A')?.server).toBe('fakeip');

    // 链尾两条：不限类型的 region-local → 境内、其余 → 隧道
    const tail = rules.slice(-2);
    expect(tail[0].query_type).toBeUndefined();
    expect(tail[0].rule_set).toBeDefined();
    expect(tail[0].server).not.toBe('dns-remote');
    expect(tail[1]).toEqual({ server: 'dns-remote' });
  });

  it('global + FakeIP：二分不生效 → 只有一条不限类型的 dns-remote 兜底（不发 region-local）', () => {
    const rules = build(config({ proxyMode: 'global' } as Partial<UserConfig>)).rules as Rule[];
    expect(rules[rules.length - 1]).toEqual({ server: 'dns-remote' });
    expect(rules.filter((r) => r.rule_set && !r.query_type)).toHaveLength(0);
  });

  it('global + FakeIP 关：兜底不再限定 A/AAAA', () => {
    const rules = build(
      config({ proxyMode: 'global', dnsConfig: { enableFakeIp: false } } as Partial<UserConfig>)
    ).rules as Rule[];
    expect(firstCatchAllFor(rules, 'TXT')?.server).toBe('dns-remote');
    expect(firstCatchAllFor(rules, 'HTTPS')?.server).toBe('dns-remote');
  });

  it('direct 模式：不加任何新规则（出口恒直连，final=境内正确）', () => {
    const rules = build(config({ proxyMode: 'direct' } as Partial<UserConfig>)).rules as Rule[];
    expect(firstCatchAllFor(rules, 'HTTPS')).toBeUndefined();
  });

  it('不遮蔽更早的规则：内网/PTR、银行、captive、节点域名、bootstrap、工作 VPN 内网域名都排在新兜底之前', () => {
    const dns = build(config());
    const cfg: any = { dns, route: { rules: [] }, inbounds: [], outbounds: [] };
    applyWorkVpnToSingBoxConfig(cfg, {
      snapshot: {
        interfaces: [
          {
            name: 'utun9',
            cidrs: ['10.8.0.0/16'],
            dnsServers: ['10.8.0.1'],
            domains: ['corp.example'],
          },
        ],
      } as any,
      serverIps: [],
      serverHosts: [],
      userDomains: [],
      autoDetectDomains: false,
      tunMode: true,
      realResolverTag: 'dns-domestic',
      ownLanCidrs: [],
      fakeipRanges: ['198.18.0.0/15'],
      platform: 'darwin',
    } as any);
    const rules = dns.rules as Rule[];
    const catchAllIdx = rules.indexOf(firstCatchAllFor(rules, 'HTTPS')!);
    const idx = (pred: (r: Rule) => boolean) => rules.findIndex(pred);
    const has = (r: Rule, key: string, v: string) =>
      Array.isArray(r[key]) && (r[key] as string[]).includes(v);

    const before = [
      idx((r) => has(r, 'domain_suffix', '.arpa')), // 反查 PTR / 内网后缀
      idx((r) => has(r, 'domain_suffix', '.local')),
      idx((r) => has(r, 'domain', 'node.example.com')), // 节点域名
      idx((r) => has(r, 'domain', 'dns.google')), // DoH bootstrap
      idx((r) => has(r, 'domain', 'corp.example')), // 工作 VPN 内网域名
      idx((r) => r.server === 'fakeip'),
    ];
    for (const i of before) {
      expect(i).toBeGreaterThanOrEqual(0);
      expect(i).toBeLessThan(catchAllIdx);
    }
  });
});
