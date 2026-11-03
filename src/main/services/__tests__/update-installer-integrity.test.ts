/**
 * App 自更新安装包完整性（UpdateService）：下载失败会自动改走第三方 gh-proxy 镜像，原先只比对 Content-Length，
 * 被替换的安装包也会被执行。现：摘要取自直连 api.github.com 的 asset.digest（主进程私有表，不信渲染端回传），
 * 下载后比对 sha256，installUpdate 只执行已校验文件且执行前重算。
 * 验：① checkForUpdate 登记 digest；② 校验通过 / 不符 / 无摘要；③ installUpdate 拒绝未校验与校验后被改动的文件；
 * ④ 校验失败文案本地化。
 */
import * as os from 'os';
import * as path from 'path';
import * as fsSync from 'fs';
import { createHash } from 'crypto';

const TMP = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-update-integrity-'));

jest.mock('electron', () => ({
  app: {
    getPath: () => TMP,
    getVersion: () => '1.0.0',
    isPackaged: false,
    getAppPath: () => TMP,
    exit: jest.fn(),
  },
  shell: { openPath: jest.fn(), openExternal: jest.fn() },
  dialog: { showMessageBox: jest.fn() },
  BrowserWindow: class {},
  net: {},
}));

import { UpdateService } from '../UpdateService';
import { mt } from '../../i18n';

const log = { addLog: () => {} } as any;
const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
const URL = 'https://github.com/NecroSpider/FlowZ-RUS/releases/download/v1.1.0/FlowZ-1.1.0.exe';

type Internals = {
  assetSha256ByUrl: Map<string, string>;
  verifiedInstallers: Map<string, string>;
  verifyInstaller(filePath: string, url: string): Promise<void>;
  localizeDownloadError(raw: string): string;
  fetchReleases: () => Promise<any[]>;
  findSuitableAsset: (assets: any[]) => any;
};
const internals = (svc: UpdateService): Internals => svc as unknown as Internals;

const writeFile = (name: string, content: string): string => {
  const p = path.join(TMP, name);
  fsSync.writeFileSync(p, content);
  return p;
};

afterAll(() => {
  try {
    fsSync.rmSync(TMP, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('UpdateService 安装包完整性校验', () => {
  it('checkForUpdate 从 API 的 asset.digest 登记 sha256（按 downloadUrl）', async () => {
    const svc = new UpdateService(log);
    const asset = {
      name: 'FlowZ-1.1.0.exe',
      size: 4,
      browser_download_url: URL,
      digest: `sha256:${sha('good').toUpperCase()}`,
    };
    internals(svc).fetchReleases = async () => [
      {
        tag_name: 'v1.1.0',
        prerelease: false,
        published_at: '2026-11-01T00:00:00Z',
        assets: [asset],
      },
    ];
    internals(svc).findSuitableAsset = () => asset;

    const result = await svc.checkForUpdate();

    expect(result.hasUpdate).toBe(true);
    expect(internals(svc).assetSha256ByUrl.get(URL)).toBe(sha('good'));
  });

  it('摘要一致 → 通过并登记为可安装', async () => {
    const svc = new UpdateService(log);
    internals(svc).assetSha256ByUrl.set(URL, sha('good'));
    const file = writeFile('ok.exe', 'good');

    await internals(svc).verifyInstaller(file, URL);

    expect(internals(svc).verifiedInstallers.get(file)).toBe(sha('good'));
    expect(fsSync.existsSync(file)).toBe(true);
  });

  it('摘要不符（如镜像返回被替换的包）→ 抛「校验失败」、删文件、不登记', async () => {
    const svc = new UpdateService(log);
    internals(svc).assetSha256ByUrl.set(URL, sha('good'));
    const file = writeFile('tampered.exe', 'evil');

    await expect(internals(svc).verifyInstaller(file, URL)).rejects.toThrow('verification failed');

    expect(fsSync.existsSync(file)).toBe(false);
    expect(internals(svc).verifiedInstallers.has(file)).toBe(false);
  });

  it('无官方摘要（URL 不在本会话 API 列表中，如渲染端回传的任意 URL）→ 拒绝', async () => {
    const svc = new UpdateService(log);
    const file = writeFile('unknown.exe', 'good');

    await expect(
      internals(svc).verifyInstaller(file, 'https://example.com/FlowZ.exe')
    ).rejects.toThrow('no official sha256 digest');

    expect(fsSync.existsSync(file)).toBe(false);
  });

  it('installUpdate 拒绝未经校验的文件，且不停代理', async () => {
    const svc = new UpdateService(log);
    const cleanup = jest.fn(async () => {});
    svc.setCleanupCallback(cleanup);
    const file = writeFile('unverified.exe', 'good');

    await expect(svc.installUpdate(file)).resolves.toBe(false);
    expect(cleanup).not.toHaveBeenCalled();
  });

  it('installUpdate 拒绝校验后被改动的文件（执行前重算摘要）', async () => {
    const svc = new UpdateService(log);
    const cleanup = jest.fn(async () => {});
    svc.setCleanupCallback(cleanup);
    internals(svc).assetSha256ByUrl.set(URL, sha('good'));
    const file = writeFile('swapped.exe', 'good');
    await internals(svc).verifyInstaller(file, URL);

    fsSync.writeFileSync(file, 'evil');

    await expect(svc.installUpdate(file)).resolves.toBe(false);
    expect(cleanup).not.toHaveBeenCalled();
  });

  it('校验失败错误映射到本地化文案 updErrIntegrity', () => {
    const svc = new UpdateService(log);
    expect(
      internals(svc).localizeDownloadError('Installer verification failed: sha256 mismatch')
    ).toBe(mt('updErrIntegrity'));
  });
});
