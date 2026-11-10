/**
 * SystemProxyManager 加固单测（2026-11 审计）：
 *  - 改混合端口后，127.0.0.1:旧端口 不再被存成「原始设置」（旧版先写新 marker 再 stripSelf → 认不出 → 每次断开恢复死端口）；
 *  - 已经中招的状态能自愈（无 marker 时靠 FlowZ 用过的端口历史认出自己）；
 *  - 读状态失败（超时 / 起不来）reject，而不是谎报 {enabled:false}；reg「值不存在」仍是确定的未启用；
 *  - 全部命令带超时；macOS 服务名一律走 execFile argv（无 shell 拼接）。
 * 全程 mock child_process，绝不碰真实系统设置。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

jest.mock('child_process', () => ({
  exec: jest.fn(),
  execFile: jest.fn(),
  execSync: jest.fn(),
  execFileSync: jest.fn(),
}));

let tmpUserData: string;
jest.mock('../../utils/paths', () => ({
  getUserDataPath: () => tmpUserData,
}));

import { exec, execFile } from 'child_process';
import {
  MacOSSystemProxy,
  WindowsSystemProxy,
  SystemProxyBase,
  PROXY_CMD_TIMEOUT_MS,
  isCommandProbeFailure,
} from '../SystemProxyManager';

const execMock = exec as unknown as jest.Mock;
const execFileMock = execFile as unknown as jest.Mock;

type Cb = (e: unknown, r?: { stdout: string; stderr: string }) => void;

/** 可变的 macOS 网络服务代理状态（service → web/secure/socks）。 */
let macState: Record<string, { web?: string; secure?: string; socks?: string }>;

function macGetOutput(hp?: string): string {
  if (!hp) return 'Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n';
  const [server, port] = hp.split(':');
  return `Enabled: Yes\nServer: ${server}\nPort: ${port}\nAuthenticated Proxy Enabled: 0\n`;
}

function installMacMock(): void {
  execFileMock.mockImplementation((file: string, args: string[], ...rest: unknown[]) => {
    const cb = rest[rest.length - 1] as Cb;
    const [sub, service, a, b] = args;
    const st = (macState[service] ??= {});
    const ok = (stdout = '') => cb(null, { stdout, stderr: '' });
    if (file !== 'networksetup') return ok();
    switch (sub) {
      case '-listallnetworkservices':
        return ok(
          `An asterisk (*) denotes that a network service is disabled.\n${Object.keys(macState).join('\n')}\n`
        );
      case '-getwebproxy':
        return ok(macGetOutput(st.web));
      case '-getsecurewebproxy':
        return ok(macGetOutput(st.secure));
      case '-getsocksfirewallproxy':
        return ok(macGetOutput(st.socks));
      case '-setwebproxy':
        st.web = `${a}:${b}`;
        return ok();
      case '-setsecurewebproxy':
        st.secure = `${a}:${b}`;
        return ok();
      case '-setsocksfirewallproxy':
        st.socks = `${a}:${b}`;
        return ok();
      case '-setwebproxystate':
        if (a === 'off') st.web = undefined;
        return ok();
      case '-setsecurewebproxystate':
        if (a === 'off') st.secure = undefined;
        return ok();
      case '-setsocksfirewallproxystate':
        if (a === 'off') st.socks = undefined;
        return ok();
      default:
        return ok();
    }
  });
}

function markerFile(): string {
  return path.join(tmpUserData, 'system-proxy.marker.json');
}

beforeEach(() => {
  tmpUserData = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-sysproxy-'));
  execMock.mockReset();
  execFileMock.mockReset();
  macState = { 'Wi-Fi': {} };
  installMacMock();
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  fs.rmSync(tmpUserData, { recursive: true, force: true });
  jest.restoreAllMocks();
});

describe('macOS：改混合端口后不把自己的旧端口存成原始设置', () => {
  it('上一会话 127.0.0.1:7890（marker 在、stop 腿未清）→ 以 7891 重新 enable → disable 关掉而非恢复 7890', async () => {
    const first = new MacOSSystemProxy();
    await first.enableProxy('127.0.0.1', 7890, 7890, []);
    expect(macState['Wi-Fi'].web).toBe('127.0.0.1:7890');

    // 新实例（换端口重启 / 新进程），marker 仍记 7890
    const second = new MacOSSystemProxy();
    await second.enableProxy('127.0.0.1', 7891, 7891, []);
    expect(SystemProxyBase.readMarker()?.ourHostPort).toBe('127.0.0.1:7891');

    await second.disableProxy();
    expect(macState['Wi-Fi'].web).toBeUndefined();
    expect(macState['Wi-Fi'].secure).toBeUndefined();
    expect(macState['Wi-Fi'].socks).toBeUndefined();
    expect(fs.existsSync(markerFile())).toBe(false);
  });

  it('同一实例重启（stop 腿不清系统代理）→ 用户原本的企业代理不丢，disable 恢复它', async () => {
    macState['Wi-Fi'] = { web: '10.0.0.5:3128', secure: '10.0.0.5:3128' };
    const p = new MacOSSystemProxy();
    await p.enableProxy('127.0.0.1', 7890, 7890, []);
    await p.enableProxy('127.0.0.1', 7890, 7890, []); // 重启腿再 enable：当前值是我们自己
    await p.disableProxy();
    expect(macState['Wi-Fi'].web).toBe('10.0.0.5:3128');
    expect(macState['Wi-Fi'].secure).toBe('10.0.0.5:3128');
  });

  it('已中招的状态自愈：无 marker、系统代理指向 FlowZ 用过的旧端口 → 不存为原始', async () => {
    // 先用 7890 跑一轮（写入端口历史），再模拟「断开时被恢复成 127.0.0.1:7890、marker 已删」
    const old = new MacOSSystemProxy();
    await old.enableProxy('127.0.0.1', 7890, 7890, []);
    SystemProxyBase.clearMarkerFile();
    macState['Wi-Fi'] = {
      web: '127.0.0.1:7890',
      secure: '127.0.0.1:7890',
      socks: '127.0.0.1:7890',
    };

    const p = new MacOSSystemProxy();
    await p.enableProxy('127.0.0.1', 7891, 7891, []);
    await p.disableProxy();
    expect(macState['Wi-Fi'].web).toBeUndefined();
  });

  it('内存里的原始快照指向自己（旧版本遗留）→ disable 时自愈为直接关闭', async () => {
    const p = new MacOSSystemProxy();
    await p.enableProxy('127.0.0.1', 7890, 7890, []);
    (p as unknown as { originalSettings: unknown }).originalSettings = {
      enabled: true,
      httpProxy: '127.0.0.1:7890',
    };
    await p.disableProxy();
    expect(macState['Wi-Fi'].web).toBeUndefined();
  });
});

describe('macOS：服务名走 execFile argv + 全部命令带超时', () => {
  it('含 shell 元字符的服务名原样作为 argv，exec(shell) 从未被调用', async () => {
    const evil = 'Wi-Fi "$(touch /tmp/pwned)"';
    macState = { [evil]: {} };
    const p = new MacOSSystemProxy();
    await p.enableProxy('127.0.0.1', 7890, 7890, []);
    await p.getProxyStatus();
    await p.disableProxy();
    expect(execMock).not.toHaveBeenCalled();
    const setCall = execFileMock.mock.calls.find((c) => c[1]?.[0] === '-setwebproxy');
    expect(setCall?.[1]?.[1]).toBe(evil);
    for (const c of execFileMock.mock.calls) {
      expect((c[2] as { timeout?: number }).timeout).toBe(PROXY_CMD_TIMEOUT_MS);
    }
  });
});

describe('getProxyStatus：读失败 reject，不谎报未启用', () => {
  it('macOS：networksetup 超时（killed）→ reject', async () => {
    execFileMock.mockImplementation((_f: string, args: string[], ...rest: unknown[]) => {
      const cb = rest[rest.length - 1] as Cb;
      if (args[0] === '-listallnetworkservices') {
        return cb(null, { stdout: 'header\nWi-Fi\n', stderr: '' });
      }
      cb(
        Object.assign(new Error('Command failed'), { killed: true, signal: 'SIGTERM', code: null })
      );
    });
    await expect(new MacOSSystemProxy().getProxyStatus()).rejects.toThrow(/Could not read/);
  });

  it('macOS：单服务跑完非零退出 → 跳过该服务（不整体失败）', async () => {
    macState = { Broken: {}, 'Wi-Fi': { web: '10.0.0.5:3128' } };
    installMacMock();
    const base = execFileMock.getMockImplementation()!;
    execFileMock.mockImplementation((f: string, args: string[], ...rest: unknown[]) => {
      if (args[1] === 'Broken') {
        return (rest[rest.length - 1] as Cb)(Object.assign(new Error('exit 1'), { code: 1 }));
      }
      return base(f, args, ...rest);
    });
    await expect(new MacOSSystemProxy().getProxyStatus()).resolves.toMatchObject({
      enabled: true,
      httpProxy: '10.0.0.5:3128',
    });
  });

  it('Windows：reg 值不存在（退出码 1）→ 确定的未启用', async () => {
    execMock.mockImplementation((_cmd: string, ...rest: unknown[]) =>
      (rest[rest.length - 1] as Cb)(Object.assign(new Error('ERROR: not found'), { code: 1 }))
    );
    await expect(new WindowsSystemProxy().getProxyStatus()).resolves.toEqual({ enabled: false });
  });

  it('Windows：reg 超时 → reject；且带超时选项', async () => {
    execMock.mockImplementation((_cmd: string, ...rest: unknown[]) =>
      (rest[rest.length - 1] as Cb)(
        Object.assign(new Error('Command failed'), { killed: true, signal: 'SIGTERM' })
      )
    );
    await expect(new WindowsSystemProxy().getProxyStatus()).rejects.toThrow(/Could not read/);
    expect((execMock.mock.calls[0][1] as { timeout?: number }).timeout).toBe(PROXY_CMD_TIMEOUT_MS);
  });

  it('Windows：正常解析 http=/https= 格式', async () => {
    execMock.mockImplementation((cmd: string, ...rest: unknown[]) => {
      const cb = rest[rest.length - 1] as Cb;
      if (/ProxyEnable/.test(cmd)) {
        return cb(null, { stdout: '    ProxyEnable    REG_DWORD    0x1\r\n', stderr: '' });
      }
      cb(null, {
        stdout: '    ProxyServer    REG_SZ    http=127.0.0.1:7890;https=127.0.0.1:7890\r\n',
        stderr: '',
      });
    });
    await expect(new WindowsSystemProxy().getProxyStatus()).resolves.toEqual({
      enabled: true,
      httpProxy: '127.0.0.1:7890',
      httpsProxy: '127.0.0.1:7890',
    });
  });
});

describe('isCommandProbeFailure', () => {
  it('数字退出码 = 跑完了（非探测失败）；超时 / spawn 失败 = 探测失败', () => {
    expect(isCommandProbeFailure({ code: 1 })).toBe(false);
    expect(isCommandProbeFailure({ code: null, killed: true, signal: 'SIGTERM' })).toBe(true);
    expect(isCommandProbeFailure({ code: 'ENOENT' })).toBe(true);
    expect(isCommandProbeFailure(undefined)).toBe(true);
  });
});
