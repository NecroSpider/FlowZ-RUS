/**
 * 订阅/导入安全加固回归（node env，mock electron + dns + 设备标识，与 SubscriptionService.test 同套桩）：
 *  - #1  hasProviders 探测对超长正文线性（旧正则 40k 换行 ≈ 3 s、1 MB ≈ 30 min）。
 *  - #3  本地导入：tor / 含可执行·文件系统路径键的透传 outbound 不入库。
 *  - #7  YAML 解析错误不回显正文（js-yaml code frame 含 password）。
 *  - #8  单条畸形 sing-box outbound 不中断整份订阅。
 *  - #12 跨源重定向剥离设备标识头；同源 / http→https 升级保留。
 *  - #13 导入而来的订阅（trustUrl=false）首跳照常过内网判定。
 */

const mockFetch = jest.fn();
jest.mock('electron', () => ({
  app: { getVersion: () => '9.9.9' },
  net: { fetch: (...a: unknown[]) => mockFetch(...a) },
  session: {
    fromPartition: () => ({
      setProxy: jest.fn().mockResolvedValue(undefined),
      fetch: (...a: unknown[]) => mockFetch(...a),
    }),
  },
}));

const mockLookup = jest.fn();
jest.mock('dns', () => ({
  promises: { lookup: (...a: unknown[]) => mockLookup(...a) },
}));

jest.mock('../device-identity', () => ({
  ...jest.requireActual('../device-identity'),
  getDeviceInfo: () =>
    Promise.resolve({ hwid: 'h'.repeat(32), os: 'macOS', osVersion: '26.0.1', model: 'Mac15,6' }),
}));

import { SubscriptionService } from '../SubscriptionService';
import { ProtocolParser } from '../ProtocolParser';
import { tryLoadClashDoc } from '../ClashSubscriptionParser';

class FakeLog {
  entries: { level: string; message: string }[] = [];
  addLog(level: string, message: string) {
    this.entries.push({ level, message });
  }
}

function makeResponse(opts: { status?: number; headers?: Record<string, string>; body?: string }) {
  const status = opts.status ?? 200;
  const headersMap = new Map(
    Object.entries(opts.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v])
  );
  const text = opts.body ?? '';
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (k: string) => headersMap.get(k.toLowerCase()) ?? null },
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(text));
        controller.close();
      },
    }),
    async text() {
      return text;
    },
  };
}

const newService = (log = new FakeLog()) =>
  new SubscriptionService(new ProtocolParser(), log as never);

const NODE_BODY = JSON.stringify({
  proxies: [{ name: 'n', type: 'vless', server: '1.1.1.1', port: 443, uuid: 'a' }],
});

beforeEach(() => {
  mockFetch.mockReset();
  mockLookup.mockReset();
  mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
});

describe('#1 proxy-providers 探测线性', () => {
  it('40k 空行 + 2 MB 空白正文在 200 ms 内完成，且两种键形仍可识别', () => {
    const evil = '\n'.repeat(40_000) + ' \n'.repeat(1_000_000) + 'x';
    const t = Date.now();
    expect(SubscriptionService.detectProviders(evil)).toBe(false);
    expect(Date.now() - t).toBeLessThan(200);
    expect(SubscriptionService.detectProviders('proxies: []\n  proxy-providers :\n  p: {}')).toBe(
      true
    );
    expect(SubscriptionService.detectProviders('{"proxy-providers" : {}}')).toBe(true);
    expect(SubscriptionService.detectProviders('name: my-proxy-providers: x')).toBe(false);
  });
});

describe('#3 本地导入拒绝危险的透传 outbound', () => {
  it('tor 与含 executable/文件系统路径键（含嵌套）的 outbound 不入库，记 warning', async () => {
    const svc = newService();
    const text = JSON.stringify({
      outbounds: [
        { type: 'vless', tag: 'v1', server: '1.2.3.4', server_port: 443, uuid: 'abc' },
        { type: 'tor', tag: 't1', executable_path: '/bin/sh', extra_args: ['-c', 'x'] },
        {
          type: 'hysteria',
          tag: 'h1',
          server: 'a.example',
          server_port: 443,
          tls: { enabled: true, certificate_path: '/etc/passwd' },
        },
        { type: 'hysteria', tag: 'ok', server: 'b.example', server_port: 443, auth_str: 's' },
      ],
    });
    const r = await svc.parseLocalContent(text);
    const names = r.nodes.map((n) => n.name).sort();
    expect(names).toEqual(['ok', 'v1']);
    expect(r.warnings.join('\n')).toMatch(/t1.*not allowed/);
    expect(r.warnings.join('\n')).toMatch(/tls\.certificate_path/);
  });
});

describe('#7 YAML 错误不回显正文', () => {
  it('错误消息只含 reason + 行列号，不含相邻行的 password', () => {
    const yaml = 'proxies:\n  - name: a\n    password: topsecret\n    port: [1, 2\n    type: ss\n';
    let msg = '';
    try {
      tryLoadClashDoc(yaml);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/^Failed to parse Clash YAML: .+\(line \d+/);
    expect(msg).not.toContain('topsecret');
  });
});

describe('#8 单条畸形 sing-box outbound 不中断整份订阅', () => {
  it('null / 数字 / 数字 server_ports / 非字符串 type → 跳过，其余节点照常', () => {
    const log = new FakeLog();
    const svc = newService(log);
    const servers = (svc as any).parseSingboxOutbounds(
      [
        null,
        5,
        [],
        { type: 7, server: 'x', server_port: 1 },
        { type: 'hysteria2', tag: 'num-ports', server: 'h.example', server_ports: [20000] },
        { type: 'hysteria2', tag: 'bad-ports', server: 'h.example', server_ports: 'abc' },
        { type: 'vless', tag: 'good', server: '1.2.3.4', server_port: 443, uuid: 'u' },
      ],
      'sub'
    );
    const names = servers.map((s: { name: string }) => s.name);
    expect(names).toContain('good');
    expect(names).toContain('num-ports');
    expect(log.entries.some((e) => /malformed outbound/.test(e.message))).toBe(true);
  });
});

describe('#12 跨源重定向剥离设备标识头', () => {
  const headersOf = (i: number) =>
    (mockFetch.mock.calls[i][1] as { headers: Record<string, string> }).headers;

  it('跳到其它主机 → 第二跳无 x-hwid / x-device-*，条件 GET 验证器保留', async () => {
    mockFetch
      .mockResolvedValueOnce(
        makeResponse({ status: 302, headers: { location: 'https://cdn.other.example/s' } })
      )
      .mockResolvedValueOnce(makeResponse({ body: NODE_BODY }));
    await newService().fetchSubscription('https://panel.example/sub/x', 'sub', false, undefined, {
      etag: 'W/"1"',
    });
    expect(headersOf(0)['x-hwid']).toBe('h'.repeat(32));
    expect(headersOf(1)['x-hwid']).toBeUndefined();
    expect(headersOf(1)['x-device-os']).toBeUndefined();
    expect(headersOf(1)['x-device-model']).toBeUndefined();
    expect(headersOf(1)['If-None-Match']).toBe('W/"1"');
    expect(headersOf(1)['User-Agent']).toBeTruthy();
  });

  it('同主机 http→https 升级 / 同源路径跳转 → 保留设备头', async () => {
    mockFetch
      .mockResolvedValueOnce(
        makeResponse({ status: 301, headers: { location: 'https://panel.example/sub/x' } })
      )
      .mockResolvedValueOnce(makeResponse({ status: 302, headers: { location: '/sub/y' } }))
      .mockResolvedValueOnce(makeResponse({ body: NODE_BODY }));
    await newService().fetchSubscription('http://panel.example/sub/x', 'sub');
    expect(headersOf(1)['x-hwid']).toBe('h'.repeat(32));
    expect(headersOf(2)['x-hwid']).toBe('h'.repeat(32));
  });

  it('https→http 降级（同主机）→ 剥离', async () => {
    mockFetch
      .mockResolvedValueOnce(
        makeResponse({ status: 302, headers: { location: 'http://panel.example/sub/x' } })
      )
      .mockResolvedValueOnce(makeResponse({ body: NODE_BODY }));
    await newService().fetchSubscription('https://panel.example/sub/x', 'sub');
    expect(headersOf(1)['x-hwid']).toBeUndefined();
  });
});

describe('#13 导入而来的订阅首跳不免内网判定', () => {
  beforeEach(() => {
    mockLookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
    mockFetch.mockResolvedValue(makeResponse({ body: NODE_BODY }));
  });

  it('用户亲手填写（缺省 trustUrl=true）→ 内网地址照常拉取', async () => {
    const r = await newService().fetchSubscription('http://lan.example/sub', 'sub');
    expect(r.servers).toHaveLength(1);
  });

  it('导入而来（trustUrl=false）→ 内网地址被拒、不发请求', async () => {
    await expect(
      newService().fetchSubscription(
        'http://lan.example/sub',
        'sub',
        false,
        undefined,
        undefined,
        true,
        false
      )
    ).rejects.toThrow();
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
