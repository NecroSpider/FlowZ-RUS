/**
 * 节点「自身」主机名（nodeOwnHosts）：REALITY 的伪装 SNI 不进节点域名直连路由 / DNS rule1。
 *
 * 回归：上游把所有节点的 tlsSettings.serverName 都收进「节点域名 → direct」与 rule1（真实解析）。REALITY 节点的
 * SNI 是借来握手的第三方站点（claude.ai、api.openai.com、www.apple.com…），于是这些站点在浏览器里恒被直连——
 * 真机实证：7 个 REALITY 节点 SNI=claude.ai → claude.ai 绕过代理、被墙超时。
 */
jest.mock('electron', () => ({
  app: {
    getPath: () => '/fake/userData',
    getVersion: () => '9.9.9',
    isPackaged: false,
    getAppPath: () => '/fake/app',
  },
  BrowserWindow: class {},
  Notification: class {},
  net: {},
  session: {},
}));

import { ProxyManager } from '../ProxyManager';
import { nodeOwnHosts } from '../singbox-config-helpers';
import type { ServerConfig, UserConfig } from '../../../shared/types';

const realityByIp = {
  id: 'r1',
  name: 'Reality IP',
  protocol: 'vless',
  address: '203.0.113.7',
  port: 443,
  uuid: 'u1',
  security: 'reality',
  tlsSettings: { serverName: 'claude.ai' },
  realitySettings: { publicKey: 'pk' },
} as ServerConfig;

const realityByDomain = {
  id: 'r2',
  name: 'Reality domain',
  protocol: 'vless',
  address: 'node.example.net',
  port: 443,
  uuid: 'u2',
  security: 'reality',
  tlsSettings: { serverName: 'www.apple.com' },
  realitySettings: { publicKey: 'pk' },
} as ServerConfig;

const tlsByIp = {
  id: 't1',
  name: 'TLS via CDN IP',
  protocol: 'vless',
  address: '198.51.100.9',
  port: 443,
  uuid: 'u3',
  security: 'tls',
  tlsSettings: { serverName: 'my-own.example.org' },
} as ServerConfig;

describe('nodeOwnHosts', () => {
  it('REALITY → 只有 address（伪装 SNI 不算节点自身）', () => {
    expect(nodeOwnHosts(realityByIp)).toEqual(['203.0.113.7']);
    expect(nodeOwnHosts(realityByDomain)).toEqual(['node.example.net']);
  });

  it('普通 TLS → address + SNI（SNI 是节点自己的域名）', () => {
    expect(nodeOwnHosts(tlsByIp)).toEqual(['198.51.100.9', 'my-own.example.org']);
  });

  it('空 / 缺失字段被滤掉', () => {
    expect(nodeOwnHosts({ ...tlsByIp, tlsSettings: undefined } as ServerConfig)).toEqual([
      '198.51.100.9',
    ]);
  });
});

describe('生成的 sing-box config：REALITY 伪装 SNI 不被直连 / 不进 rule1', () => {
  const config = {
    subscriptions: [],
    servers: [realityByIp, realityByDomain, tlsByIp],
    selectedServerId: 'r1',
    proxyMode: 'smart',
    proxyModeType: 'tun',
    tunConfig: { mtu: 'auto', stack: 'auto', autoRoute: true, strictRoute: true },
    customRules: [],
    appRules: [],
    customAppPresets: [],
    mixedPort: 7890,
    logLevel: 'info',
    clashApiSecret: 'testsecret',
  } as unknown as UserConfig;

  const svc: any = new ProxyManager(undefined, undefined, '/fake/cfg.json', '/fake/sing-box');
  svc.coreVersion = '1.14.4';
  const out = svc.generateSingBoxConfig(config);
  const routeRules: any[] = out.route.rules;
  const dnsRules: any[] = out.dns.rules;
  const directDomainRule = routeRules.find(
    (r) =>
      r.outbound === 'direct' && Array.isArray(r.domain) && r.domain.includes('node.example.net')
  );

  it('节点域名直连规则：含节点 address 与普通 TLS 的 SNI，不含 REALITY 的 claude.ai / www.apple.com', () => {
    expect(directDomainRule).toBeDefined();
    expect(directDomainRule.domain).toEqual(
      expect.arrayContaining(['node.example.net', 'my-own.example.org'])
    );
    expect(directDomainRule.domain).not.toContain('claude.ai');
    expect(directDomainRule.domain).not.toContain('www.apple.com');
  });

  it('REALITY 的 IP 节点仍由 ip_cidr 直连兜住（防回流）', () => {
    const ipRule = routeRules.find(
      (r) =>
        r.outbound === 'direct' && Array.isArray(r.ip_cidr) && r.ip_cidr.includes('203.0.113.7/32')
    );
    expect(ipRule).toBeDefined();
  });

  it('全部 direct 规则与 DNS 规则里都不再出现伪装 SNI', () => {
    const mentions = (rules: any[], host: string) =>
      rules.some(
        (r) =>
          (Array.isArray(r.domain) && r.domain.includes(host)) ||
          (Array.isArray(r.domain_suffix) && r.domain_suffix.includes(`.${host}`))
      );
    expect(
      mentions(
        routeRules.filter((r) => r.outbound === 'direct'),
        'claude.ai'
      )
    ).toBe(false);
    expect(mentions(dnsRules, 'claude.ai')).toBe(false);
    expect(mentions(dnsRules, 'www.apple.com')).toBe(false);
    expect(mentions(dnsRules, 'node.example.net')).toBe(true); // 节点域名仍走真实解析
  });
});
