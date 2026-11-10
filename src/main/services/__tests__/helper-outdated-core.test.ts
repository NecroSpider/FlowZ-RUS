/**
 * "Installed helper does not trust this app's bundled core" (app update shipped a new core, helper still the old
 * build) → treat the helper as outdated: one reinstall prompt, never silently run an older core.
 */
import * as os from 'os';
import * as fsSync from 'fs';
import * as path from 'path';
import { setPlatform, restorePlatform } from './platform-test-utils';

const TMP = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-outdated-test-'));
jest.mock('electron', () => ({
  app: { getPath: () => TMP, getVersion: () => '9.9.9', isPackaged: false, getAppPath: () => TMP },
  dialog: {},
  BrowserWindow: class {},
  Notification: class {},
  net: {},
  session: {},
}));

import { CoreUpdateService } from '../CoreUpdateService';
import { HelperManager } from '../HelperManager';
import { LinuxServiceHelper } from '../LinuxServiceHelper';
import { WindowsServiceHelper } from '../WindowsServiceHelper';
import { resourceManager } from '../ResourceManager';

afterEach(restorePlatform);
afterAll(() => fsSync.rmSync(TMP, { recursive: true, force: true }));

type Untrusted = { bundledCoreUntrusted(): Promise<boolean>; sendCommand: unknown };

describe('core-info trusted flag → outdated helper', () => {
  for (const [name, mk] of [
    ['mac', () => new HelperManager()],
    ['win', () => new WindowsServiceHelper()],
    ['linux', () => new LinuxServiceHelper()],
  ] as const) {
    it(`${name}: only an explicit trusted=0 marks the helper outdated`, async () => {
      const h = mk() as unknown as Untrusted;
      const sent: string[][] = [];
      let reply = 'OK bundled=aa core=bb trusted=0';
      h.sendCommand = async (rest: string[]) => {
        sent.push(rest);
        return reply;
      };
      await expect(h.bundledCoreUntrusted()).resolves.toBe(true);
      expect(sent[0][0]).toBe('core-info');
      expect(sent[0][1]).toMatch(/^[0-9a-f]{64}$/); // this app's bundled-core pin
      for (reply of ['OK bundled=aa core=bb trusted=1', 'OK bundled=aa core=bb', 'ERR unknown']) {
        await expect(h.bundledCoreUntrusted()).resolves.toBe(false);
      }
    });
  }
});

describe('Linux startCore with an outdated helper', () => {
  function mk(installOk: boolean) {
    const h = new LinuxServiceHelper();
    const calls: string[] = [];
    let trusted = false;
    (h as unknown as { sendCommand: unknown }).sendCommand = async (rest: string[]) => {
      calls.push(rest[0]);
      if (rest[0] === 'core-info') return `OK bundled=a core=b trusted=${trusted ? 1 : 0}`;
      if (rest[0] === 'install-core') return 'OK installed';
      if (rest[0] === 'start') return 'OK started 42';
      return 'OK';
    };
    (h as unknown as { install: unknown }).install = async () => {
      calls.push('INSTALL');
      if (installOk) trusted = true;
      return { success: installOk, error: installOk ? undefined : 'cancelled', status: {} };
    };
    return { h, calls };
  }

  it('reinstalls once, refreshes the managed core from the bundle, then starts', async () => {
    const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-bundle-'));
    fsSync.writeFileSync(path.join(dir, 'sing-box'), 'NEW BUNDLED');
    jest
      .spyOn(resourceManager, 'getBundledSingBoxPath')
      .mockReturnValue(path.join(dir, 'sing-box'));
    jest
      .spyOn(resourceManager, 'getSingBoxPath')
      .mockReturnValue('/usr/local/lib/flowz/core/sing-box');
    const { h, calls } = mk(true);
    await expect(h.startCore('/u/cfg.json', '/u/log', false)).resolves.toEqual({
      ok: true,
      pid: 42,
    });
    expect(calls.filter((c) => c === 'INSTALL')).toHaveLength(1);
    expect(calls.indexOf('install-core')).toBeGreaterThan(calls.indexOf('INSTALL'));
    expect(calls.indexOf('start')).toBeGreaterThan(calls.indexOf('install-core'));
    fsSync.rmSync(dir, { recursive: true, force: true });
  });

  it('declined → error (ProxyManager falls back to setcap) and no second prompt this session', async () => {
    const { h, calls } = mk(false);
    const r1 = await h.startCore('/u/cfg.json', '/u/log', false);
    const r2 = await h.startCore('/u/cfg.json', '/u/log', false);
    expect(r1.ok).toBe(false);
    expect(r2.ok).toBe(false);
    expect(calls.filter((c) => c === 'INSTALL')).toHaveLength(1);
    expect(calls).not.toContain('start'); // never runs the older core through the helper
  });
});

describe('macOS startup bundled-core prompt merged with the helper reinstall', () => {
  function mkSvc(hs: Record<string, unknown>) {
    const svc = new CoreUpdateService({ addLog: () => {} } as never) as unknown as {
      tryElevatedReseedProtectedCoreOnStartup(v: string): Promise<void>;
      setHelperManager(h: unknown): void;
      setPrivilegeService?(p: unknown): void;
      privilegeService: unknown;
      proxyManager: unknown;
    };
    const events: string[] = [];
    svc.setHelperManager({
      getStatus: async () => hs,
      installCore: async () => ({ ok: true }),
      install: async () => {
        events.push('HELPER_REINSTALL');
        return { success: true, status: hs };
      },
    });
    svc.privilegeService = {
      installCoreElevatedMac: async () => {
        events.push('CORE_ELEVATED');
      },
    };
    svc.proxyManager = {
      getCoreVersion: async () => '1.14.4',
      getCoreVersionLine: async () => 'sing-box version 1.14.9',
      refreshCoreVersionAfterExternalReseed: async () => undefined,
    };
    return { svc, events };
  }

  it('outdated helper → exactly one prompt: the helper reinstall (no separate core prompt)', async () => {
    setPlatform('darwin');
    const { svc, events } = mkSvc({
      installed: true,
      needsRepair: true,
      backgroundDisabled: false,
    });
    await svc.tryElevatedReseedProtectedCoreOnStartup('9.9.1');
    expect(events).toEqual(['HELPER_REINSTALL']);
  });

  it('no helper → the one-time elevated core install as before', async () => {
    setPlatform('darwin');
    const { svc, events } = mkSvc({
      installed: false,
      needsRepair: false,
      backgroundDisabled: false,
    });
    await svc.tryElevatedReseedProtectedCoreOnStartup('9.9.2');
    expect(events).toEqual(['CORE_ELEVATED']);
  });
});
