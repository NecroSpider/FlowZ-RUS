/**
 * issue #147 节点域名解析器迁移 + 消费点等价单测。
 * 本项目铁律：DNS runtime 改动 code review 判不准，须以生成物/纯函数断言验证。
 *
 * 覆盖：
 *  A. migrateNodeResolver（经 loadConfig 真实路径）：旧单选档位 auto/dnspod/system → 新 pool/single 映射 +
 *     migrated 标记；旧无字段→auto 等价；幂等（已 migrated 不覆盖用户值）；新装默认。
 *  B. getNodeResolverTag 读 nodeResolverSingle 产出与旧档位【完全等价】的 tag；single 缺失回退 legacy。
 *  C. migrateDnsDefaults（本 fork）：仍等于上游中国默认的 domesticDns / pool / single → Yandex；用户改过的保留；
 *     显式地区 cn 跳过且不置位；幂等。旧 auto 档位经 A 落 [ali,dnspod]/ali 后，同一次 loadConfig 再经 C 落 Yandex。
 */

import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-node-resolver-test-'));
jest.mock('electron', () => ({
  app: {
    getPath: () => TMP,
    getVersion: () => '9.9.9',
    isPackaged: false,
    getAppPath: () => TMP,
  },
  BrowserWindow: class {},
  Notification: class {},
  net: {},
  session: {},
}));

import { ConfigManager } from '../ConfigManager';
import { getNodeResolverTag } from '../singbox-config-helpers';
import type { UserConfig } from '../../../shared/types';

/** 最小可校验 UserConfig（够过 validateConfig），按需覆盖。 */
function makeConfig(over: Partial<UserConfig> = {}): UserConfig {
  return {
    subscriptions: [],
    servers: [],
    selectedServerId: null,
    proxyMode: 'smart',
    proxyModeType: 'systemProxy',
    tunConfig: { mtu: 1350, stack: 'system', autoRoute: true, strictRoute: true },
    customRules: [],
    autoStart: false,
    silentStart: false,
    autoConnect: false,
    minimizeToTray: true,
    autoCheckUpdate: true,
    autoLightweightMode: false,
    autoUpdateSubscriptionOnStart: false,
    subscriptionUpdateIntervalHours: 12,
    subscriptionProxyPolicy: 'follow',
    mainSessionViaProxy: true,
    rememberWindowSize: false,
    enableIPv6: false,
    autoPrivacyMode: false,
    privacyPassword: '',
    customRuleSets: [],
    appRules: [],
    appRoutingEnabled: true,
    logLevel: 'info',
    disableLogFile: false,
    clashApiSecret: 'fixedsecret0000000000000000000000',
    uiTheme: 'system',
    ...over,
  } as unknown as UserConfig;
}

const baseDns = (over: Record<string, unknown> = {}) =>
  ({
    domesticDns: 'x',
    foreignDns: 'y',
    enableFakeIp: true,
    fakeIpToggleMigrated: true,
    ...over,
  }) as any;

describe('A. migrateNodeResolver（经 loadConfig）', () => {
  let dir: string;
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-node-resolver-migrate-'));
  });
  const write = (config: UserConfig): string => {
    const p = path.join(dir, `cfg-${Math.random().toString(36).slice(2)}.json`);
    fs.writeFileSync(p, JSON.stringify(config, null, 2));
    return p;
  };

  it('旧 auto → pool[ali,dnspod] + single ali（A）→ 再经 C 落 Yandex', async () => {
    const p = write(makeConfig({ dnsConfig: baseDns({ nodeDomainResolver: 'auto' }) }));
    const c = (await new ConfigManager(p).loadConfig()).dnsConfig as any;
    expect(c.nodeResolverPool).toEqual(['yandex', 'yandex2']);
    expect(c.nodeResolverSingle).toBe('yandex');
    expect(c.nodeResolverMigrated).toBe(true);
    expect(c.dnsDefaultsMigrated).toBe(true);
  });

  it('旧 auto + 显式地区 cn → 停在 A 的 [ali,dnspod]/ali（C 跳过）', async () => {
    const p = write(
      makeConfig({
        regionRouting: { enabled: true, region: 'cn', reverse: false },
        dnsConfig: baseDns({ nodeDomainResolver: 'auto' }),
      })
    );
    const c = (await new ConfigManager(p).loadConfig()).dnsConfig as any;
    expect(c.nodeResolverPool).toEqual(['ali', 'dnspod']);
    expect(c.nodeResolverSingle).toBe('ali');
  });

  it('旧 dnspod → [dnspod]/dnspod（保留用户意图）', async () => {
    const p = write(makeConfig({ dnsConfig: baseDns({ nodeDomainResolver: 'dnspod' }) }));
    const c = (await new ConfigManager(p).loadConfig()).dnsConfig as any;
    expect(c.nodeResolverPool).toEqual(['dnspod']);
    expect(c.nodeResolverSingle).toBe('dnspod');
  });

  it('旧 system → [system]/system', async () => {
    const p = write(makeConfig({ dnsConfig: baseDns({ nodeDomainResolver: 'system' }) }));
    const c = (await new ConfigManager(p).loadConfig()).dnsConfig as any;
    expect(c.nodeResolverPool).toEqual(['system']);
    expect(c.nodeResolverSingle).toBe('system');
  });

  it('旧无 nodeDomainResolver 字段 → 视为 auto 等价（经 C 落 Yandex）', async () => {
    const p = write(makeConfig({ dnsConfig: baseDns() }));
    const c = (await new ConfigManager(p).loadConfig()).dnsConfig as any;
    expect(c.nodeResolverPool).toEqual(['yandex', 'yandex2']);
    expect(c.nodeResolverSingle).toBe('yandex');
  });

  it('幂等：已 migrated 的用户自定义 pool/single 不被覆盖', async () => {
    const p = write(
      makeConfig({
        dnsConfig: baseDns({
          nodeDomainResolver: 'auto',
          nodeResolverPool: ['dnspod'],
          nodeResolverSingle: 'system',
          nodeResolverMigrated: true,
        }),
      })
    );
    const c = (await new ConfigManager(p).loadConfig()).dnsConfig as any;
    expect(c.nodeResolverPool).toEqual(['dnspod']);
    expect(c.nodeResolverSingle).toBe('system');
  });

  it('新装（配置文件不存在）→ 默认 Yandex：pool[yandex,yandex2]/single yandex/国内 DNS/migrated', async () => {
    const p = path.join(dir, 'nonexistent-default.json');
    const c = (await new ConfigManager(p).loadConfig()).dnsConfig as any;
    expect(c.nodeResolverPool).toEqual(['yandex', 'yandex2']);
    expect(c.nodeResolverSingle).toBe('yandex');
    expect(c.domesticDns).toBe('https://77.88.8.8/dns-query');
    expect(c.nodeResolverMigrated).toBe(true);
    expect(c.dnsDefaultsMigrated).toBe(true);
  });
});

describe('C. migrateDnsDefaults（中国 DNS 默认值 → Yandex）', () => {
  let dir: string;
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-dns-defaults-migrate-'));
  });
  const load = async (config: UserConfig) => {
    const p = path.join(dir, `cfg-${Math.random().toString(36).slice(2)}.json`);
    fs.writeFileSync(p, JSON.stringify(config, null, 2));
    const loaded = (await new ConfigManager(p).loadConfig()).dnsConfig as any;
    const onDisk = JSON.parse(fs.readFileSync(p, 'utf-8')).dnsConfig;
    return { loaded, onDisk };
  };
  const legacy = (over: Record<string, unknown> = {}) =>
    baseDns({
      domesticDns: 'https://doh.pub/dns-query',
      nodeResolverPool: ['ali', 'dnspod'],
      nodeResolverSingle: 'ali',
      nodeResolverMigrated: true,
      ...over,
    });

  it('三项仍是上游默认（含存量 region=ru）→ 全部换 Yandex，置位并落盘', async () => {
    const { loaded, onDisk } = await load(
      makeConfig({
        regionRouting: { enabled: true, region: 'ru', reverse: false },
        dnsConfig: legacy(),
      })
    );
    expect(loaded.domesticDns).toBe('https://77.88.8.8/dns-query');
    expect(loaded.nodeResolverPool).toEqual(['yandex', 'yandex2']);
    expect(loaded.nodeResolverSingle).toBe('yandex');
    expect(loaded.dnsDefaultsMigrated).toBe(true);
    expect(onDisk.domesticDns).toBe('https://77.88.8.8/dns-query');
    expect(onDisk.dnsDefaultsMigrated).toBe(true);
  });

  it('pool 顺序不同（[dnspod,ali]）仍视为旧默认', async () => {
    const { loaded } = await load(
      makeConfig({ dnsConfig: legacy({ nodeResolverPool: ['dnspod', 'ali'] }) })
    );
    expect(loaded.nodeResolverPool).toEqual(['yandex', 'yandex2']);
  });

  it('用户改过的值保留：自定义国内 DNS / 改过的 pool / single dnspod', async () => {
    const { loaded } = await load(
      makeConfig({
        dnsConfig: legacy({
          domesticDns: 'https://dns.comss.one/dns-query',
          nodeResolverPool: ['ali', 'dnspod', 'custom-1'],
          nodeResolverSingle: 'dnspod',
        }),
      })
    );
    expect(loaded.domesticDns).toBe('https://dns.comss.one/dns-query');
    expect(loaded.nodeResolverPool).toEqual(['ali', 'dnspod', 'custom-1']);
    expect(loaded.nodeResolverSingle).toBe('dnspod');
    expect(loaded.dnsDefaultsMigrated).toBe(true);
  });

  it('显式地区 cn → 不迁且不置位（之后切到别的地区，下次启动再迁）', async () => {
    const { loaded } = await load(
      makeConfig({
        regionRouting: { enabled: true, region: 'cn', reverse: false },
        dnsConfig: legacy(),
      })
    );
    expect(loaded.domesticDns).toBe('https://doh.pub/dns-query');
    expect(loaded.nodeResolverPool).toEqual(['ali', 'dnspod']);
    expect(loaded.nodeResolverSingle).toBe('ali');
    expect(loaded.dnsDefaultsMigrated).toBeUndefined();
  });

  it('幂等：已置位后用户再改回 doh.pub / ali 不被覆盖', async () => {
    const { loaded } = await load(makeConfig({ dnsConfig: legacy({ dnsDefaultsMigrated: true }) }));
    expect(loaded.domesticDns).toBe('https://doh.pub/dns-query');
    expect(loaded.nodeResolverPool).toEqual(['ali', 'dnspod']);
    expect(loaded.nodeResolverSingle).toBe('ali');
  });
});

describe('B. getNodeResolverTag：race on → dns-node-race；off → 单上游（等价旧档位）', () => {
  // race off（逃生/降级 / snapshot·preflight 路径）才走单上游；race server 就绪时 ProxyManager 才把 config 置 on。
  const off = (over: Record<string, unknown> = {}) =>
    baseDns({ resolveNodeDomainsAhead: false, ...over });

  it('race on（默认）→ dns-node-race（dial 与 rule 同 tag）', () => {
    const c = makeConfig({ dnsConfig: baseDns({ nodeResolverPool: ['ali', 'dnspod'] }) });
    expect(getNodeResolverTag(c, 'dial')).toBe('dns-node-race');
    expect(getNodeResolverTag(c, 'rule')).toBe('dns-node-race');
  });

  it('off + single yandex（默认）→ dial=dns-bootstrap / rule=dns-domestic', () => {
    const c = makeConfig({ dnsConfig: off({ nodeResolverSingle: 'yandex' }) });
    expect(getNodeResolverTag(c, 'dial')).toBe('dns-bootstrap');
    expect(getNodeResolverTag(c, 'rule')).toBe('dns-domestic');
  });

  it('off + single ali → dns-ali（dial 与 rule 同；dns-bootstrap 已是 Yandex，ali 单列）', () => {
    const c = makeConfig({ dnsConfig: off({ nodeResolverSingle: 'ali' }) });
    expect(getNodeResolverTag(c, 'dial')).toBe('dns-ali');
    expect(getNodeResolverTag(c, 'rule')).toBe('dns-ali');
  });

  it('off + single dnspod → dns-node（dial 与 rule 同）', () => {
    const c = makeConfig({ dnsConfig: off({ nodeResolverSingle: 'dnspod' }) });
    expect(getNodeResolverTag(c, 'dial')).toBe('dns-node');
    expect(getNodeResolverTag(c, 'rule')).toBe('dns-node');
  });

  it('off + single system → dial=dns-local；TUN rule 强制 dns-node（INV-1 防递归）', () => {
    const sys = makeConfig({
      proxyModeType: 'systemProxy',
      dnsConfig: off({ nodeResolverSingle: 'system' }),
    });
    expect(getNodeResolverTag(sys, 'dial')).toBe('dns-local');
    expect(getNodeResolverTag(sys, 'rule')).toBe('dns-local');
    const tun = makeConfig({
      proxyModeType: 'tun',
      dnsConfig: off({ nodeResolverSingle: 'system' }),
    });
    expect(getNodeResolverTag(tun, 'rule')).toBe('dns-node'); // INV-1
  });

  it('off + 回退 legacy（仅 deprecated nodeDomainResolver，无 single）→ 等价旧', () => {
    expect(
      getNodeResolverTag(makeConfig({ dnsConfig: off({ nodeDomainResolver: 'dnspod' }) }), 'dial')
    ).toBe('dns-node');
    const auto = makeConfig({ dnsConfig: off({ nodeDomainResolver: 'auto' }) });
    expect(getNodeResolverTag(auto, 'dial')).toBe('dns-bootstrap');
    expect(getNodeResolverTag(auto, 'rule')).toBe('dns-domestic');
  });

  it('off + 自定义 single → 当前回退基线 tag（off+自定义单上游 server 生成为 §E 二期）', () => {
    const c = makeConfig({ dnsConfig: off({ nodeResolverSingle: 'custom-xxx' }) });
    expect(getNodeResolverTag(c, 'dial')).toBe('dns-bootstrap');
  });
});
