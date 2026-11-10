/**
 * 渲染层信任策略（ipc-handler）：本应用页面判定 / IPC 来源校验 / 权限白名单；以及沙箱 preload 内联通道名的一致性。
 */
const handleSpy = jest.fn();
const sendSyncSpy = jest.fn();
jest.mock('electron', () => ({
  app: { isPackaged: true },
  ipcMain: { handle: (...a: any[]) => handleSpy(...a), removeHandler: jest.fn() },
  contextBridge: { exposeInMainWorld: jest.fn() },
  ipcRenderer: {
    on: jest.fn(),
    removeListener: jest.fn(),
    send: jest.fn(),
    sendSync: (...a: any[]) => sendSyncSpy(...a),
  },
}));

import {
  IpcHandlerRegistry,
  isAppRendererUrl,
  configureTrustedRenderer,
  isTrustedIpcSender,
  isPermissionAllowed,
  DEV_SERVER_ORIGIN,
} from '../../ipc/ipc-handler';
import { IPC_CHANNELS } from '../../../shared/ipc-channels';

const posixDir = '/Users/Иван/Новая папка/FlowZ.app/Contents/Resources/app.asar/dist/renderer';
const posix = { rendererDir: posixDir, devOrigin: null, platform: 'darwin' as const };
const winDir = 'C:\\Program Files\\FlowZ\\resources\\app.asar\\dist\\renderer';
const win = { rendererDir: winDir, devOrigin: null, platform: 'win32' as const };

describe('isAppRendererUrl', () => {
  it('accepts the app pages even with percent-encoded Cyrillic / spaces, hash and query', () => {
    const href = new URL(`file://${posixDir}/index.html`).href; // Chromium 同款编码
    expect(href).toContain('%D0%');
    expect(isAppRendererUrl(href, posix)).toBe(true);
    expect(isAppRendererUrl(`${href}#/settings?tab=1`, posix)).toBe(true);
    expect(isAppRendererUrl(new URL(`file://${posixDir}/update-popup.html`).href, posix)).toBe(
      true
    );
  });

  it('macOS/Windows paths compare case-insensitively; Linux does not', () => {
    const upper = new URL(`file://${posixDir.toUpperCase()}/index.html`).href;
    expect(isAppRendererUrl(upper, posix)).toBe(true);
    expect(isAppRendererUrl(upper, { ...posix, platform: 'linux' })).toBe(false);
    expect(
      isAppRendererUrl(
        'file:///c:/program%20files/flowz/resources/app.asar/dist/renderer/index.html',
        win
      )
    ).toBe(true);
  });

  it('tolerates a lone % in a directory name', () => {
    const opts = {
      rendererDir: '/opt/100%/dist/renderer',
      devOrigin: null,
      platform: 'linux' as const,
    };
    expect(isAppRendererUrl('file:///opt/100%/dist/renderer/index.html', opts)).toBe(true);
  });

  it('rejects other local files, traversal out of the renderer dir, and non-file schemes', () => {
    expect(isAppRendererUrl('file:///Users/x/Downloads/evil.html', posix)).toBe(false);
    expect(isAppRendererUrl(new URL(`file://${posixDir}/../evil.html`).href, posix)).toBe(false);
    expect(isAppRendererUrl(new URL(`file://${posixDir}-evil/index.html`).href, posix)).toBe(false);
    expect(isAppRendererUrl('data:text/html,<p>x</p>', posix)).toBe(false);
    expect(isAppRendererUrl('https://example.com/', posix)).toBe(false);
    expect(isAppRendererUrl('http://localhost:5173/', posix)).toBe(false); // 生产不信 dev 源
    expect(isAppRendererUrl('', posix)).toBe(false);
    expect(isAppRendererUrl('not a url', posix)).toBe(false);
  });

  it('dev: trusts only the vite origin', () => {
    const dev = { ...posix, devOrigin: DEV_SERVER_ORIGIN };
    expect(isAppRendererUrl('http://localhost:5173/', dev)).toBe(true);
    expect(isAppRendererUrl('http://localhost:5174/', dev)).toBe(false);
    expect(isAppRendererUrl('http://127.0.0.1:5173/', dev)).toBe(false);
  });
});

describe('IPC sender check', () => {
  afterEach(() => configureTrustedRenderer(null));
  const appUrl = new URL(`file://${posixDir}/index.html`).href;
  const ev = (url: string | null, throws = false) =>
    ({
      get senderFrame() {
        if (throws) throw new Error('Render frame was disposed');
        return url === null ? null : { url };
      },
    }) as any;

  it('no policy configured → unchanged behaviour (unit tests / early calls)', () => {
    expect(isTrustedIpcSender(ev('file:///evil.html'))).toBe(true);
  });

  it('policy configured → only app frames pass; destroyed frames fail closed', () => {
    configureTrustedRenderer(posix);
    expect(isTrustedIpcSender(ev(appUrl))).toBe(true);
    expect(isTrustedIpcSender(ev('file:///Users/x/Downloads/evil.html'))).toBe(false);
    expect(isTrustedIpcSender(ev('data:text/html,x'))).toBe(false);
    expect(isTrustedIpcSender(ev(null))).toBe(false);
    expect(isTrustedIpcSender(ev(appUrl, true))).toBe(false);
  });

  it('registered handlers reject untrusted senders without running the handler', async () => {
    configureTrustedRenderer(posix);
    handleSpy.mockClear();
    const reg = new IpcHandlerRegistry();
    const handler = jest.fn(async () => 'ok');
    reg.register(IPC_CHANNELS.CONFIG_GET, handler);
    const wrapped = handleSpy.mock.calls[0][1];
    await expect(wrapped(ev('file:///tmp/evil.html'), undefined)).resolves.toMatchObject({
      success: false,
      code: 'IPC_FORBIDDEN',
    });
    expect(handler).not.toHaveBeenCalled();
    await expect(wrapped(ev(appUrl), undefined)).resolves.toEqual({ success: true, data: 'ok' });
  });
});

describe('isPermissionAllowed (deny by default)', () => {
  afterEach(() => configureTrustedRenderer(null));
  const appUrl = new URL(`file://${posixDir}/index.html`).href;

  it('only clipboard write, only for the app and the local sing-box dashboard', () => {
    configureTrustedRenderer(posix);
    expect(isPermissionAllowed('clipboard-sanitized-write', appUrl)).toBe(true);
    expect(isPermissionAllowed('clipboard-sanitized-write', 'http://127.0.0.1:9090/ui/')).toBe(
      true
    );
    expect(isPermissionAllowed('clipboard-sanitized-write', 'https://evil.example/')).toBe(false);
    expect(isPermissionAllowed('clipboard-sanitized-write', 'file:///tmp/evil.html')).toBe(false);
    for (const p of ['media', 'geolocation', 'notifications', 'clipboard-read', 'openExternal']) {
      expect(isPermissionAllowed(p, appUrl)).toBe(false);
      expect(isPermissionAllowed(p, 'http://127.0.0.1:9090/ui/')).toBe(false);
    }
  });
});

describe('sandboxed preloads inline channel names (no local requires)', () => {
  it('update popup channels match IPC_CHANNELS', () => {
    jest.isolateModules(() => {
      const m = require('../../preload-update-popup');
      expect(m.POPUP_STATE_CHANNEL).toBe(IPC_CHANNELS.UPDATE_POPUP_STATE);
      expect(m.POPUP_ACTION_CHANNEL).toBe(IPC_CHANNELS.UPDATE_POPUP_ACTION);
    });
  });

  it('compiled-to-be preloads only import electron (sandbox requirement)', () => {
    const fs = require('fs');
    const path = require('path');
    for (const f of ['preload.ts', 'preload-update-popup.ts', 'dashboard-preload.ts']) {
      const src: string = fs.readFileSync(path.join(__dirname, '../..', f), 'utf8');
      const runtimeImports = [...src.matchAll(/^import\s+(?!type\b)[^;]*?from\s+'([^']+)'/gm)].map(
        (m) => m[1]
      );
      expect(runtimeImports.every((s) => s === 'electron')).toBe(true);
    }
  });
});

describe('dashboard preload (sandboxed, secret via sync IPC instead of argv)', () => {
  const { DASHBOARD_BOOTSTRAP_CHANNEL, isDashboardBootstrapSenderAllowed } = jest.requireActual(
    '../../ipc/handlers/helper-handlers'
  ) as typeof import('../../ipc/handlers/helper-handlers');
  const g = globalThis as { localStorage?: unknown };
  afterEach(() => {
    delete g.localStorage;
    sendSyncSpy.mockReset();
  });

  function fakeStorage(initial: Record<string, string> = {}) {
    const m = new Map(Object.entries(initial));
    return {
      map: m,
      getItem: (k: string) => (m.has(k) ? (m.get(k) as string) : null),
      setItem: (k: string, v: string) => void m.set(k, v),
    };
  }

  it('fetches the payload over the bootstrap channel and pre-writes localStorage', () => {
    const store = fakeStorage();
    g.localStorage = store;
    const payload = {
      servers: {
        servers: [{ id: 'a', name: '', url: '127.0.0.1:9090', secret: 's' }],
        activeId: 'a',
      },
      legacy: { url: '127.0.0.1:9090', secret: 's' },
      language: 'ru',
    };
    sendSyncSpy.mockReturnValue(JSON.stringify(payload));
    jest.isolateModules(() => require('../../dashboard-preload'));
    expect(sendSyncSpy).toHaveBeenCalledWith(DASHBOARD_BOOTSTRAP_CHANNEL);
    expect(JSON.parse(store.map.get('sing-box-dashboard.servers') as string)).toEqual(
      payload.servers
    );
    expect(JSON.parse(store.map.get('sing-box-dashboard.server') as string)).toEqual(
      payload.legacy
    );
    expect(store.map.get('sing-box-dashboard.language')).toBe('ru');
  });

  it('denied / missing payload → writes nothing and never throws', () => {
    const store = fakeStorage({ 'sing-box-dashboard.language': 'en' });
    g.localStorage = store;
    sendSyncSpy.mockReturnValue(null);
    expect(() => jest.isolateModules(() => require('../../dashboard-preload'))).not.toThrow();
    expect([...store.map.keys()]).toEqual(['sing-box-dashboard.language']);
    sendSyncSpy.mockImplementation(() => {
      throw new Error('ipc failed');
    });
    expect(() => jest.isolateModules(() => require('../../dashboard-preload'))).not.toThrow();
  });

  it('bootstrap is only answered for the main frame on the local dashboard origin', () => {
    const origin = 'http://127.0.0.1:9090';
    expect(isDashboardBootstrapSenderAllowed({ url: `${origin}/ui/`, parent: null }, origin)).toBe(
      true
    );
    expect(isDashboardBootstrapSenderAllowed({ url: '', parent: null }, origin)).toBe(true);
    expect(isDashboardBootstrapSenderAllowed({ url: 'about:blank', parent: null }, origin)).toBe(
      true
    );
    expect(isDashboardBootstrapSenderAllowed({ url: `${origin}/ui/`, parent: {} }, origin)).toBe(
      false
    );
    expect(
      isDashboardBootstrapSenderAllowed({ url: 'https://evil.example/', parent: null }, origin)
    ).toBe(false);
    expect(
      isDashboardBootstrapSenderAllowed({ url: 'http://127.0.0.1:90901/', parent: null }, origin)
    ).toBe(false);
    expect(isDashboardBootstrapSenderAllowed(null, origin)).toBe(false);
  });
});
