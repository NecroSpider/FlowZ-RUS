/**
 * 更新弹窗状态机的可 mock 单测：并发流互斥闸门 + 下载错误本地化映射。
 * （弹窗创建/定位/焦点/IPC 收发属 runtime 项，由真机 + Xvfb harness 验；此处只钉纯逻辑分支。）
 */
import * as os from 'os';
import * as path from 'path';
import * as fsSync from 'fs';

const TMP = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-updsvc-test-'));

jest.mock('electron', () => ({
  app: { getPath: () => TMP, getVersion: () => '1.0.0', isPackaged: false, getAppPath: () => TMP },
  shell: { openExternal: jest.fn() },
  // 可实例化的 BrowserWindow 桩：让 createUpdatePopup 走完新建路径，暴露 webContents.send 以断言初始态下发。
  BrowserWindow: class {
    webContents = { setWindowOpenHandler: () => {}, on: () => {}, send: jest.fn() };
    loadFile = () => Promise.resolve();
    loadURL = () => Promise.resolve();
    setMenu = () => {};
    once = () => {};
    on = () => {};
    isDestroyed = () => false;
    setContentSize = () => {};
    setPosition = () => {};
    close = () => {};
  },
  nativeTheme: { shouldUseDarkColors: false },
  screen: { getPrimaryDisplay: () => ({ workArea: { x: 0, y: 0, width: 1920, height: 1080 } }) },
  ipcMain: { on: () => {} },
  dialog: { showMessageBox: jest.fn() },
  net: {},
  session: {},
  Notification: class {},
}));

import { shell } from 'electron';
import { UpdateService } from '../UpdateService';
import { setMainLanguage, mt } from '../../i18n';

const log = { addLog: () => {} } as any;
const openExternal = shell.openExternal as unknown as jest.Mock;

describe('UpdateService.showUpdateDialog 并发流互斥闸门', () => {
  it('已有活跃弹窗 → 直接返回 later，不新建弹窗（Med-1：防覆盖 resolver / 双下载）', async () => {
    const svc = new UpdateService(log) as any;
    svc.updatePopupWindow = { isDestroyed: () => false }; // 模拟弹窗流进行中
    await expect(svc.showUpdateDialog({ version: 'v2.0.0', releaseNotes: '' })).resolves.toBe(
      'later'
    );
    // 断言未触碰弹窗创建（updatePopupWindow 仍是注入的假窗，未被替换）
    expect(typeof svc.updatePopupWindow.isDestroyed).toBe('function');
  });
});

describe('UpdateService.createUpdatePopup 新建窗口路径下发初始状态（#300 回归）', () => {
  const state = { phase: 'remind' as const, theme: 'light' as const, version: 'v2.0.0' };

  it('新建弹窗后 seed lastPopupState 并向 renderer 下发（防 did-finish-load 无态可重放 → 白卡片挂死窗）', () => {
    const svc = new UpdateService(log) as any;
    const win = svc.createUpdatePopup(state);
    // lastPopupState 必须被写入：否则 did-finish-load 重放条件恒 false，remind 态永不渲染。
    expect(svc.lastPopupState).toEqual(state);
    // 同步向 renderer 下发一次当前态（页面 onState 晚注册时由 did-finish-load 兜底重放同一 lastPopupState）。
    expect(win.webContents.send).toHaveBeenCalledWith(expect.anything(), state);
  });
});

describe('UpdateService.openReleasesPage 直达本版本 changelog', () => {
  const svc = new UpdateService(log) as any;
  const RELEASES = 'https://github.com/NecroSpider/FlowZ-RUS/releases';
  beforeEach(() => openExternal.mockClear());

  it('传 version（带 v 前缀）→ 直达该版本 tag 页', () => {
    svc.openReleasesPage('v4.2.7');
    expect(openExternal).toHaveBeenCalledWith(`${RELEASES}/tag/v4.2.7`);
  });

  it('version 缺 v 前缀 → 自动补 v 再定位', () => {
    svc.openReleasesPage('4.2.7');
    expect(openExternal).toHaveBeenCalledWith(`${RELEASES}/tag/v4.2.7`);
  });

  it('不传 version → 泛 releases 列表页（无版本上下文入口）', () => {
    svc.openReleasesPage();
    expect(openExternal).toHaveBeenCalledWith(RELEASES);
  });

  it('viewLog 动作用 currentUpdateInfo.version 直达本次更新的 changelog', () => {
    svc.currentUpdateInfo = { version: 'v3.1.0' };
    svc.updatePopupWindow = { webContents: {}, isDestroyed: () => false };
    svc.onPopupAction({ sender: svc.updatePopupWindow.webContents }, 'viewLog');
    expect(openExternal).toHaveBeenCalledWith(`${RELEASES}/tag/v3.1.0`);
  });
});

describe('UpdateService.localizeDownloadError 错误本地化映射（Low-5）', () => {
  const svc = new UpdateService(log) as any;
  beforeAll(() => setMainLanguage('en-US'));

  it('网络/超时类 → updErrNetwork', () => {
    expect(
      svc.localizeDownloadError(
        'Download stalled (no data for 30s, network interrupted or blocked)'
      )
    ).toBe(mt('updErrNetwork'));
    expect(svc.localizeDownloadError('ETIMEDOUT')).toBe(mt('updErrNetwork'));
    expect(svc.localizeDownloadError('net::ERR_INTERNET_DISCONNECTED')).toBe(mt('updErrNetwork'));
  });

  it('不完整/截断 → updErrIncomplete', () => {
    expect(
      svc.localizeDownloadError(
        'Download incomplete: received 1 bytes, expected 100 (possibly truncated)'
      )
    ).toBe(mt('updErrIncomplete'));
  });

  it('HTTP/服务器错误 → updErrServer', () => {
    expect(svc.localizeDownloadError('Download failed: HTTP 404')).toBe(mt('updErrServer'));
    expect(svc.localizeDownloadError('GitHub API rate limit exceeded (403)')).toBe(
      mt('updErrServer')
    );
  });

  it('未知错误 → updErrGeneric 兜底', () => {
    expect(svc.localizeDownloadError('莫名其妙的错误')).toBe(mt('updErrGeneric'));
  });

  it('映射结果随当前语言变化（本地化生效）', () => {
    setMainLanguage('ru');
    expect(svc.localizeDownloadError('ETIMEDOUT')).toBe(mt('updErrNetwork'));
    expect(mt('updErrNetwork')).toMatch(/[А-я]/);
    setMainLanguage('en-US');
  });
});

describe('prerelease confirmation and stable channel', () => {
  const info = {
    version: 'v9.0.0',
    isPrerelease: true,
    fileName: 'test.exe',
    downloadUrl: 'https://example.com/test.exe',
    fileSize: 1,
  };
  /** 下载只认本会话 checkForUpdate 返回过的记录：测试里直接登记（等价于一次成功的检查）。 */
  const seeded = (record: typeof info = info): any => {
    const svc = new UpdateService(log) as any;
    svc.checkedUpdates.set(record.downloadUrl, record);
    return svc;
  };
  afterEach(() => jest.restoreAllMocks());

  it('cancel prevents downloading from settings and is distinguishable from a network error', async () => {
    const { dialog } = require('electron');
    dialog.showMessageBox.mockResolvedValue({ response: 1 });
    const svc = seeded();
    const download = jest.spyOn(svc, 'downloadFile');
    await expect(svc.downloadUpdate(info)).rejects.toMatchObject({ code: 'UPDATE_CANCELLED' });
    expect(download).not.toHaveBeenCalled();
    expect(dialog.showMessageBox).toHaveBeenLastCalledWith(
      expect.objectContaining({ type: 'warning', defaultId: 1, cancelId: 1 })
    );
  });

  it('cancel also prevents popup downloads, while explicit acceptance permits the download', async () => {
    const { dialog } = require('electron');
    const svc = seeded();
    const download = jest.spyOn(svc, 'downloadFile').mockResolvedValue(undefined);
    jest.spyOn(svc, 'verifyInstaller').mockResolvedValue(undefined);
    dialog.showMessageBox.mockResolvedValue({ response: 1 });
    await expect(svc.downloadUpdateWithProgress(info)).resolves.toBeNull();
    expect(download).not.toHaveBeenCalled();
    dialog.showMessageBox.mockResolvedValue({ response: 0 });
    await expect(svc.downloadUpdate(info)).resolves.toContain('test.exe');
    expect(download).toHaveBeenCalledTimes(1);
  });

  it('stable downloads do not request prerelease consent', async () => {
    const { dialog } = require('electron');
    dialog.showMessageBox.mockClear();
    const svc = seeded({ ...info, isPrerelease: false });
    jest.spyOn(svc, 'downloadFile').mockResolvedValue(undefined);
    jest.spyOn(svc, 'verifyInstaller').mockResolvedValue(undefined);
    await svc.downloadUpdate({ ...info, isPrerelease: false });
    expect(dialog.showMessageBox).not.toHaveBeenCalled();
  });

  it('the prerelease flag comes from the last check, not from the renderer', async () => {
    const { dialog } = require('electron');
    dialog.showMessageBox.mockReset();
    dialog.showMessageBox.mockResolvedValue({ response: 1 });
    const svc = seeded(); // 检查结果：预发布
    const download = jest.spyOn(svc, 'downloadFile');
    // 渲染端谎称 isPrerelease:false → 仍弹预发布确认，取消即不下载
    await expect(svc.downloadUpdate({ ...info, isPrerelease: false })).rejects.toMatchObject({
      code: 'UPDATE_CANCELLED',
    });
    expect(dialog.showMessageBox).toHaveBeenCalledTimes(1);
    expect(download).not.toHaveBeenCalled();
  });

  it('refuses updates that were not returned by a check (unknown URL)', async () => {
    const svc = seeded();
    const download = jest.spyOn(svc, 'downloadFile');
    await expect(
      svc.downloadUpdate({ ...info, downloadUrl: 'https://evil.example/x.exe' })
    ).rejects.toMatchObject({ code: 'UPDATE_UNKNOWN' });
    await expect(
      svc.downloadUpdateWithProgress({ ...info, downloadUrl: 'https://evil.example/x.exe' })
    ).resolves.toBeNull();
    expect(download).not.toHaveBeenCalled();
  });

  it('uses the checked file name (basename only) inside a private mkdtemp dir', async () => {
    const { dialog } = require('electron');
    dialog.showMessageBox.mockResolvedValue({ response: 0 });
    const svc = seeded({ ...info, isPrerelease: false });
    const download = jest.spyOn(svc, 'downloadFile').mockResolvedValue(undefined);
    jest.spyOn(svc, 'verifyInstaller').mockResolvedValue(undefined);
    // 渲染端回传的 fileName 含路径穿越 → 忽略，取主进程记录的 test.exe
    const filePath: string = await svc.downloadUpdate({
      ...info,
      fileName: '../../../../etc/passwd',
    });
    expect(path.basename(filePath)).toBe('test.exe');
    const dir = path.dirname(filePath);
    expect(path.basename(dir)).toMatch(/^flowz-update-/);
    expect(path.dirname(dir)).toBe(os.tmpdir());
    if (process.platform !== 'win32') expect(fsSync.statSync(dir).mode & 0o077).toBe(0); // 仅属主可访问
    expect(download.mock.calls[0][1]).toBe(filePath);
    fsSync.rmSync(dir, { recursive: true, force: true });
  });

  it('ordinary checks exclude drafts, flagged prereleases and unflagged beta tags', async () => {
    const svc = new UpdateService(log) as any;
    jest.spyOn(svc, 'fetchReleases').mockResolvedValue([
      { tag_name: 'v9.0.3', draft: true, published_at: '2026-11-04' },
      { tag_name: 'v9.0.2', prerelease: true, published_at: '2026-11-03' },
      { tag_name: 'v9.0.1-beta.1', prerelease: false, published_at: '2026-11-02' },
      { tag_name: 'v9.0.0', prerelease: false, published_at: '2026-11-01' },
    ]);
    jest
      .spyOn(svc, 'findSuitableAsset')
      .mockReturnValue({ name: 'test.exe', browser_download_url: info.downloadUrl, size: 1 });
    expect((await svc.checkForUpdate()).updateInfo).toMatchObject({
      version: 'v9.0.0',
      isPrerelease: false,
    });
    expect((await svc.checkForUpdate(true)).updateInfo).toMatchObject({
      version: 'v9.0.2',
      isPrerelease: true,
    });
  });
});
