const fsSync = require('fs');
const path = require('path');
const os = require('os');
const TMP = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-default-route-'));
const mockCommand = jest.fn();

jest.mock('electron', () => ({
  app: { getPath: () => TMP, getVersion: () => '9.9.9', isPackaged: false },
  BrowserWindow: class {},
  Notification: class {},
  net: {},
  session: {},
}));
jest.mock('child_process', () => {
  const execFile = jest.fn();
  Object.assign(execFile, {
    [Symbol.for('nodejs.util.promisify.custom')]: (...args: unknown[]) => mockCommand(...args),
  });
  return { ...jest.requireActual('child_process'), execFile };
});

import { ProxyManager } from '../ProxyManager';
import { withPlatformAsync } from './platform-test-utils';

afterEach(() => mockCommand.mockReset());
afterAll(() => fsSync.rmSync(TMP, { recursive: true, force: true }));

function makeSvc(): any {
  const svc: any = new ProxyManager(undefined, undefined, path.join(TMP, 'cfg.json'), '/fake/core');
  svc.savedDefaultGateway = '192.168.119.1';
  svc.helperManager = { restoreDefaultRoute: jest.fn().mockResolvedValue(undefined) };
  svc.logToManager = jest.fn();
  return svc;
}

describe('macOS default route recovery', () => {
  it('preserves a point-to-point VPN default without a gateway line', async () => {
    await withPlatformAsync('darwin', async () => {
      const svc = makeSvc();
      mockCommand.mockResolvedValue({
        stdout: 'destination: default\n  interface: utun8\n flags: <UP,DONE,STATIC,GLOBAL>\n',
      });
      await svc.restoreDefaultRouteIfMissing();
      expect(svc.helperManager.restoreDefaultRoute).not.toHaveBeenCalled();
      expect(mockCommand).toHaveBeenCalledTimes(1);
    });
  });

  it('clears an old physical gateway when the new session has no gateway', async () => {
    await withPlatformAsync('darwin', async () => {
      const svc = makeSvc();
      mockCommand.mockResolvedValue({ stdout: 'destination: default\n interface: utun8\n' });
      await svc.captureDefaultRoute();
      expect(svc.savedDefaultGateway).toBeNull();
    });
  });

  it('still restores a genuinely missing route using the current gateway', async () => {
    await withPlatformAsync('darwin', async () => {
      const svc = makeSvc();
      mockCommand
        .mockRejectedValueOnce(new Error('route: not in table'))
        .mockResolvedValueOnce({ stdout: ' Router : 192.168.120.1\n' });
      await svc.restoreDefaultRouteIfMissing();
      expect(svc.helperManager.restoreDefaultRoute).toHaveBeenCalledWith('192.168.120.1');
    });
  });
});
