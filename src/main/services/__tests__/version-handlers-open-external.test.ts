/**
 * shell:openExternal 白名单：仅 http(s) + 登录项设置深链（精确常量）可交 OS 打开，其它 scheme 一律拒绝。
 */
const handleSpy = jest.fn();
const openExternal = jest.fn().mockResolvedValue(undefined);
jest.mock('electron', () => ({
  app: { getVersion: () => '1.0.0', isPackaged: false },
  ipcMain: { handle: (...a: any[]) => handleSpy(...a), removeHandler: jest.fn() },
  shell: { openExternal: (...a: any[]) => openExternal(...a) },
}));
jest.mock('../../../shared/build-info', () => ({ BUILD_DATE: '2026-01-01' }));

import { isAllowedExternalUrl, registerVersionHandlers } from '../../ipc/handlers/version-handlers';
import { IPC_CHANNELS } from '../../../shared/ipc-channels';
import { LOGIN_ITEMS_SETTINGS_URL } from '../../../shared/constants';

describe('isAllowedExternalUrl', () => {
  it('allows http(s) and the exact login-items settings URL', () => {
    expect(
      isAllowedExternalUrl('https://github.com/NecroSpider/FlowZ-RUS/issues/new?title=x')
    ).toBe(true);
    expect(isAllowedExternalUrl('http://127.0.0.1:9090/ui/')).toBe(true);
    expect(isAllowedExternalUrl('https://t.me/necro_spider')).toBe(true);
    expect(isAllowedExternalUrl(LOGIN_ITEMS_SETTINGS_URL)).toBe(true);
  });

  it('rejects every other scheme and look-alikes', () => {
    for (const u of [
      'file:///etc/passwd',
      'file://server/share/evil.exe',
      'javascript:alert(1)',
      'smb://host/share',
      'ms-msdt:/id PCWDiagnostic',
      'x-apple.systempreferences:com.apple.preference.security',
      `${LOGIN_ITEMS_SETTINGS_URL}?x`,
      'vscode://file/x',
      'https://',
      '',
      '   ',
      undefined,
      null,
      42,
    ]) {
      expect(isAllowedExternalUrl(u)).toBe(false);
    }
  });
});

describe('SHELL_OPEN_EXTERNAL handler', () => {
  it('opens allowed URLs and refuses others without calling shell.openExternal', async () => {
    registerVersionHandlers();
    const call = handleSpy.mock.calls.find((c) => c[0] === IPC_CHANNELS.SHELL_OPEN_EXTERNAL);
    expect(call).toBeDefined();
    const wrapped = call![1];
    await expect(wrapped({}, 'https://example.com/')).resolves.toEqual({
      success: true,
      data: true,
    });
    expect(openExternal).toHaveBeenCalledWith('https://example.com/');
    openExternal.mockClear();
    await expect(wrapped({}, 'file:///Applications/Calculator.app')).resolves.toMatchObject({
      success: false,
      code: 'URL_NOT_ALLOWED',
    });
    expect(openExternal).not.toHaveBeenCalled();
  });
});
