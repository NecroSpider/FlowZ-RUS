/**
 * #4 备份 / 手改配置驱动的路径穿越：
 *  - Tailscale 节点 id → `<userData>/tailscale/<id>` 被 rm -rf：tailscaleStateDir 拒非法 id，validateConfig 剔除。
 *  - ruleResources[].id / fileName → `<id>.srs` 写入 / fileName 删除：validateConfig 剔除/归一。
 *  - 订阅 imported 标记只保留 true。
 * #6 解压命令不再拼 shell 串。
 */
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'flowz-path-guard-'));

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

import { ConfigManager, isSafeRuleResourceId } from '../ConfigManager';
import { tailscaleStateDir, isSafeNodeId } from '../tailscale-state';
import { buildExtractInvocation } from '../core-downloader';
import type { UserConfig } from '../../../shared/types';

afterAll(() => {
  try {
    fs.rmSync(TMP, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

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
    minimizeToTray: false,
    mixedPort: 7890,
    logLevel: 'info',
    ...over,
  } as unknown as UserConfig;
}

const vless = (id: string) => ({
  id,
  name: `n-${id}`,
  protocol: 'vless',
  address: 'a.example.com',
  port: 443,
  uuid: '00000000-0000-0000-0000-00000000000a',
});

describe('tailscaleStateDir / isSafeNodeId', () => {
  it('UUID 与字母数字/-/_ id 合法；穿越 / 分隔符 / 空串非法且 tailscaleStateDir throw', () => {
    expect(isSafeNodeId('3f2504e0-4f89-11d3-9a0c-0305e82c3301')).toBe(true);
    expect(isSafeNodeId('custom-lq3k_1')).toBe(true);
    for (const bad of ['..', '../..', 'a/b', 'a\\b', '', 'a.b', 'C:x', '%2e%2e']) {
      expect(isSafeNodeId(bad)).toBe(false);
      expect(() => tailscaleStateDir(bad)).toThrow(/Invalid Tailscale node id/);
    }
    expect(tailscaleStateDir('abc')).toBe(path.join(TMP, 'tailscale', 'abc'));
  });
});

describe('validateConfig 路径类字段 sanitize', () => {
  const cm = () => new ConfigManager(path.join(TMP, `c-${Math.random()}.json`));

  it('剔除 id 非法的节点（如 ../..），randomUUID 节点保留', () => {
    const cfg = makeConfig({
      servers: [
        vless('3f2504e0-4f89-11d3-9a0c-0305e82c3301'),
        { ...vless('../../..'), protocol: 'tailscale' },
        vless('a/b'),
      ] as any,
    });
    cm().validateConfig(cfg);
    expect(cfg.servers.map((s) => s.id)).toEqual(['3f2504e0-4f89-11d3-9a0c-0305e82c3301']);
  });

  it('ruleResources：非法 id 剔除；非法 fileName 归一为 <id>.srs；资源库 id（含 ! @）保留', () => {
    const res = (id: string, fileName: string) => ({
      id,
      name: id,
      category: 'geosite',
      sourceUrl: 'https://x/y.srs',
      fileName,
      format: 'binary',
    });
    const cfg = makeConfig({
      ruleResources: [
        res('geosite-geolocation-!cn', 'geosite-geolocation-!cn.srs'),
        res('geosite-apple@cn', 'geosite-apple@cn.srs'),
        res('res_1_abc', '../../evil.srs'),
        res('res_2', '/etc/passwd'),
        res('../escape', 'escape.srs'),
        res('.hidden', 'x.srs'),
      ],
    } as any);
    cm().validateConfig(cfg);
    const out = (cfg.ruleResources ?? []).map((r) => [r.id, r.fileName]);
    expect(out).toEqual([
      ['geosite-geolocation-!cn', 'geosite-geolocation-!cn.srs'],
      ['geosite-apple@cn', 'geosite-apple@cn.srs'],
      ['res_1_abc', 'res_1_abc.srs'],
      ['res_2', 'res_2.srs'],
    ]);
  });

  it('非数组 ruleResources 删除而非 throw；isSafeRuleResourceId 拒 Windows 非法字符', () => {
    const cfg = makeConfig({ ruleResources: 'oops' } as any);
    expect(() => cm().validateConfig(cfg)).not.toThrow();
    expect(cfg.ruleResources).toBeUndefined();
    expect(isSafeRuleResourceId('a:b')).toBe(false);
    expect(isSafeRuleResourceId('a\u0000')).toBe(false);
  });

  it('订阅 imported 仅保留 true', () => {
    const sub = (id: string, imported: unknown) => ({
      id,
      name: id,
      url: 'https://x',
      autoUpdate: false,
      createdAt: '',
      imported,
    });
    const cfg = makeConfig({ subscriptions: [sub('a', true), sub('b', 'yes')] } as any);
    cm().validateConfig(cfg);
    const flags = (cfg.subscriptions ?? []).map((s) => (s as any).imported);
    expect(flags).toEqual([true, undefined]);
  });
});

describe('#6 解压命令：参数数组，不拼 shell 串', () => {
  it('Windows：路径经环境变量传入，命令文本不含路径；-LiteralPath', () => {
    const src = "C:\\Users\\O'Brien\\AppData\\Local\\Temp\\core [1].zip";
    const dst = "C:\\Users\\O'Brien\\x";
    const inv = buildExtractInvocation('win32', src, dst);
    expect(inv.file.toLowerCase()).toMatch(/powershell\.exe$/);
    const cmd = inv.args.join(' ');
    expect(cmd).not.toContain("O'Brien");
    expect(cmd).toContain('-LiteralPath $env:FLOWZ_ARCHIVE');
    expect(inv.env).toEqual({ FLOWZ_ARCHIVE: src, FLOWZ_EXTRACT_DIR: dst });
  });

  it('macOS/Linux：tar / unzip 参数数组原样携带路径', () => {
    expect(buildExtractInvocation('darwin', "/tmp/a'b.tar.gz", '/tmp/o')).toEqual({
      file: 'tar',
      args: ['-xzf', "/tmp/a'b.tar.gz", '-C', '/tmp/o'],
    });
    expect(buildExtractInvocation('linux', '/tmp/a.zip', '/tmp/o')).toEqual({
      file: 'unzip',
      args: ['-o', '/tmp/a.zip', '-d', '/tmp/o'],
    });
  });
});
