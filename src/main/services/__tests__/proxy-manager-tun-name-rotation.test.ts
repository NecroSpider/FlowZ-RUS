/**
 * Windows TUN 接口名轮换：每次起核换一个 `flowz-tun<N>`，避开上一次硬杀（helper 服务模式）留下的同名半删除适配器。
 * 私有方法经 `(svc as any)` 直调，不启动 sing-box。
 */
const os = require('os');
const path = require('path');
const fsSync = require('fs');

const TMP = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-tunrot-'));

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
import { withPlatform } from './platform-test-utils';

afterAll(() => {
  try {
    fsSync.rmSync(TMP, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

const cfg = (tunConfig: Record<string, unknown> = {}): any => ({
  proxyModeType: 'tun',
  servers: [],
  selectedServerId: 'x',
  tunConfig,
});

function makeSvc(): any {
  return new ProxyManager(undefined, undefined, path.join(TMP, 'sb.json'), '/fake/sing-box');
}

describe('Windows TUN name rotation', () => {
  it('gives every start a different flowz-tun<N> name, and winTunNameFor follows it', () => {
    withPlatform('win32', () => {
      const svc = makeSvc();
      const names: string[] = [];
      for (let i = 0; i < 5; i++) {
        const n = svc.rotateWinTunName(cfg());
        expect(n).toMatch(/^flowz-tun\d{1,2}$/);
        expect(svc.winTunNameFor(cfg())).toBe(n);
        names.push(n);
      }
      expect(new Set(names).size).toBe(5);
    });
  });

  it('before any start (and in unit tests) the name is the historical flowz-tun0', () => {
    withPlatform('win32', () => {
      expect(makeSvc().winTunNameFor(cfg())).toBe('flowz-tun0');
    });
  });

  it('keeps a name the user set in tunConfig.interfaceName', () => {
    withPlatform('win32', () => {
      const svc = makeSvc();
      expect(svc.rotateWinTunName(cfg({ interfaceName: 'my-tun' }))).toBe('my-tun');
      expect(svc.rotateWinTunName(cfg({ interfaceName: 'my-tun' }))).toBe('my-tun');
    });
  });

  it('does nothing on macOS and Linux', () => {
    for (const plat of ['darwin', 'linux'] as const) {
      withPlatform(plat, () => {
        const svc = makeSvc();
        expect(svc.rotateWinTunName(cfg())).toBeNull();
        expect(svc.winTunName).toBeNull();
      });
    }
  });

  it('the generated sing-box config carries the rotated name (wiring ProxyManager -> inbound builder)', () => {
    const full: any = {
      ...cfg({ mtu: 'auto', stack: 'auto', autoRoute: true, strictRoute: true }),
      subscriptions: [],
      servers: [
        { id: 's1', name: 'HK', protocol: 'vless', address: 'a.example.com', port: 443, uuid: 'u' },
      ],
      selectedServerId: 's1',
      proxyMode: 'smart',
      customRules: [],
      appRules: [],
      customAppPresets: [],
      socksPort: 1080,
      httpPort: 1087,
      mixedPort: 7890,
      logLevel: 'info',
      clashApiSecret: 's',
    };
    const tunName = (svc: any): string | undefined =>
      svc.generateSingBoxConfig(full).inbounds.find((i: { type: string }) => i.type === 'tun')
        ?.interface_name;
    withPlatform('win32', () => {
      const svc = makeSvc();
      svc.coreVersion = '1.14.4';
      expect(tunName(svc)).toBe('flowz-tun0'); // before any start: unchanged
      svc.rotateWinTunName(full);
      expect(tunName(svc)).toBe(svc.winTunName);
      expect(tunName(svc)).toMatch(/^flowz-tun\d{1,2}$/);
    });
  });
});
