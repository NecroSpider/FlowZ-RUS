/**
 * #5 IPC 不再信任渲染端传来的文件路径：手动换核 / 备份导入的「确认」二次调用只认主进程发的一次性 token。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-ipc-tokens-'));
const mockShowOpenDialog = jest.fn();

jest.mock('electron', () => ({
  app: { getPath: () => TMP, getVersion: () => '9.9.9', isPackaged: false },
  dialog: { showOpenDialog: (...a: unknown[]) => mockShowOpenDialog(...a) },
  ipcMain: { handle: jest.fn(), removeHandler: jest.fn() },
  BrowserWindow: { getAllWindows: () => [] },
}));

import { CoreUpdateService } from '../CoreUpdateService';
import {
  issueImportToken,
  takeImportToken,
  markRestoredSubscriptionsImported,
} from '../../ipc/handlers/backup-handlers';

afterAll(() => {
  try {
    fs.rmSync(TMP, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('手动换核 token', () => {
  function svcWithStub() {
    const svc = new CoreUpdateService({ addLog: () => {} } as never);
    const replace = jest.fn();
    (svc as unknown as { replaceManualCore: typeof replace }).replaceManualCore = replace;
    return { svc, replace };
  }

  it('needConfirm 时回传 token（不回传路径）；token 换回文件框路径且一次性', async () => {
    const { svc, replace } = svcWithStub();
    replace.mockResolvedValueOnce({
      ok: false,
      needConfirm: true,
      sameVersion: '1.14.0',
      filePath: '/picked/sing-box',
    });
    const first = await svc.replaceManualCoreFromRenderer();
    expect(first).not.toHaveProperty('filePath');
    expect(typeof first.token).toBe('string');
    expect(replace).toHaveBeenLastCalledWith({ filePath: undefined, force: false });

    replace.mockResolvedValueOnce({ ok: true });
    await svc.replaceManualCoreFromRenderer({ token: first.token, force: true });
    expect(replace).toHaveBeenLastCalledWith({ filePath: '/picked/sing-box', force: true });

    // 重放同一 token → 拒绝，不再调用 replaceManualCore
    replace.mockClear();
    const replay = await svc.replaceManualCoreFromRenderer({ token: first.token, force: true });
    expect(replay.ok).toBe(false);
    expect(replace).not.toHaveBeenCalled();
  });

  it('伪造 token（或旧式路径字段）不会让主进程使用渲染端给的路径', async () => {
    const { svc, replace } = svcWithStub();
    const r = await svc.replaceManualCoreFromRenderer({ token: '/usr/bin/evil', force: true });
    expect(r.ok).toBe(false);
    expect(replace).not.toHaveBeenCalled();
    replace.mockResolvedValueOnce({ ok: false });
    await svc.replaceManualCoreFromRenderer({ filePath: '/usr/bin/evil' } as never);
    // 无 token → 走文件框（filePath undefined），渲染端路径被忽略
    expect(replace).toHaveBeenLastCalledWith({ filePath: undefined, force: false });
  });
});

describe('备份导入 token', () => {
  it('issue → take 得到路径；一次性；未知/过期 → null', () => {
    const t = issueImportToken('/picked/backup.flowz-backup', 1_000);
    expect(takeImportToken(t, 2_000)).toBe('/picked/backup.flowz-backup');
    expect(takeImportToken(t, 2_000)).toBeNull();
    expect(takeImportToken('/etc/passwd')).toBeNull();
    const old = issueImportToken('/x', 0);
    expect(takeImportToken(old, 11 * 60_000)).toBeNull();
  });

  it('恢复的订阅标记 imported（首跳不免 SSRF 判定）', () => {
    const cfg: any = { subscriptions: [{ id: 'a', name: 'a', url: 'http://127.0.0.1:25500/sub' }] };
    markRestoredSubscriptionsImported(cfg);
    expect(cfg.subscriptions[0].imported).toBe(true);
  });
});
