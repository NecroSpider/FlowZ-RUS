/**
 * Yandex DoH reachability plan -> generated sing-box config and race pool.
 * Private methods are called through `(svc as any)`; nothing is started.
 */
const os = require('os');
const path = require('path');
const fsSync = require('fs');

const TMP = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-dnsplan-'));

jest.mock('electron', () => ({
  app: { getPath: () => TMP, getVersion: () => '9.9.9', isPackaged: false, getAppPath: () => TMP },
  BrowserWindow: class {},
  Notification: class {},
  net: {},
  session: {},
}));
jest.mock('../builtin-geo-rulesets', () => ({
  ...jest.requireActual('../builtin-geo-rulesets'),
  isValidSrsFile: () => true,
}));

import { ProxyManager } from '../ProxyManager';
import { ensureYandexDnsPlan, resetYandexDnsPlanForTest } from '../dns-reachability';

afterAll(() => {
  try {
    fsSync.rmSync(TMP, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});
afterEach(() => resetYandexDnsPlanForTest());

const userConfig = (dnsOver: Record<string, unknown> = {}): any => ({
  subscriptions: [],
  servers: [
    { id: 's1', name: 'HK', protocol: 'vless', address: 'a.example.com', port: 443, uuid: 'u' },
  ],
  selectedServerId: 's1',
  proxyMode: 'smart',
  proxyModeType: 'systemProxy',
  tunConfig: {},
  customRules: [],
  appRules: [],
  customAppPresets: [],
  socksPort: 1080,
  httpPort: 1087,
  mixedPort: 7890,
  logLevel: 'info',
  clashApiSecret: 's',
  dnsConfig: {
    domesticDns: 'https://77.88.8.8/dns-query',
    foreignDns: 'https://dns.google/dns-query',
    enableFakeIp: false,
    ...dnsOver,
  },
});

function makeSvc(): any {
  const svc: any = new ProxyManager(
    undefined,
    undefined,
    path.join(TMP, 'sb.json'),
    '/fake/sing-box'
  );
  svc.coreVersion = '1.14.4';
  return svc;
}

const dnsServer = (cfg: any, tag: string): any => cfg.dns.servers.find((s: any) => s.tag === tag);

const blockPrimary = (): Promise<unknown> =>
  ensureYandexDnsPlan(0, {
    probe: async () => ({
      '77.88.8.8': false,
      '77.88.8.1': false,
      '77.88.8.88': true,
      '77.88.8.2': true,
    }),
  });

describe('generated config follows the reachability plan', () => {
  it('is unchanged while no probe has run', () => {
    const cfg = makeSvc().generateSingBoxConfig(userConfig());
    expect(dnsServer(cfg, 'dns-bootstrap').server).toBe('77.88.8.8');
    expect(dnsServer(cfg, 'dns-domestic').server).toBe('77.88.8.8');
  });

  it('uses the reachable address for dns-bootstrap and the default domestic DNS when 77.88.8.8 / .1 are blocked', async () => {
    await blockPrimary();
    const cfg = makeSvc().generateSingBoxConfig(userConfig());
    expect(dnsServer(cfg, 'dns-bootstrap').server).toBe('77.88.8.88');
    expect(dnsServer(cfg, 'dns-domestic').server).toBe('77.88.8.88');
  });

  it('leaves a domestic DNS the user chose alone, but still moves dns-bootstrap', async () => {
    await blockPrimary();
    const cfg = makeSvc().generateSingBoxConfig(
      userConfig({ domesticDns: 'https://1.1.1.1/dns-query' })
    );
    expect(dnsServer(cfg, 'dns-domestic').server).toBe('1.1.1.1');
    expect(dnsServer(cfg, 'dns-bootstrap').server).toBe('77.88.8.88');
  });

  it('moves only to 77.88.8.1 when just 77.88.8.8 is blocked', async () => {
    await ensureYandexDnsPlan(0, {
      probe: async () => ({
        '77.88.8.8': false,
        '77.88.8.1': true,
        '77.88.8.88': true,
        '77.88.8.2': true,
      }),
    });
    const cfg = makeSvc().generateSingBoxConfig(userConfig());
    expect(dnsServer(cfg, 'dns-bootstrap').server).toBe('77.88.8.1');
    expect(dnsServer(cfg, 'dns-domestic').server).toBe('77.88.8.1');
  });
});

describe('node-domain race pool follows the plan', () => {
  const poolUsed = async (svc: any, config: any): Promise<string[]> => {
    let ups: any = null;
    svc.nodeDnsRaceServer = {
      start: jest.fn(async (u: any) => ((ups = u), 12345)),
      stop: jest.fn(),
    };
    await svc.startNodeDnsRaceServer(config);
    return ups.tier1.map((u: any) => u.id);
  };

  it('keeps Yandex while it is reachable', async () => {
    expect(await poolUsed(makeSvc(), userConfig())).toEqual(['yandex', 'yandex2']);
  });

  it('switches to Yandex Safe when both primary addresses are blocked', async () => {
    await blockPrimary();
    expect(await poolUsed(makeSvc(), userConfig())).toEqual(['yandexSafe', 'yandexSafe2']);
  });

  it('keeps a pool the user set to something else', async () => {
    await blockPrimary();
    const config = userConfig({ nodeResolverPool: ['ali'] });
    expect(await poolUsed(makeSvc(), config)).toEqual(['ali']);
  });
});
