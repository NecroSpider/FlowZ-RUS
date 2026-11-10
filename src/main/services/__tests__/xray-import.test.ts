/**
 * xray-import 单测（node env，零 electron）。覆盖 vmess/vless/trojan/shadowsocks 映射 +
 * streamSettings(tls/reality/ws/grpc) + 不支持协议跳过 + 内部协议忽略 + 缺字段失败。
 */
import { isXrayConfigArray, parseXrayConfigArray, parseXrayOutbounds } from '../xray-import';

const NOW = '2026-06-30T00:00:00.000Z';

describe('parseXrayOutbounds', () => {
  it('normalizes legacy scalar FinalMask fragment ranges', () => {
    const r = parseXrayOutbounds(
      [
        {
          protocol: 'vless',
          settings: { address: 'example.com', port: 443, id: 'u' },
          streamSettings: {
            network: 'tcp',
            finalmask: {
              tcp: [
                {
                  type: 'fragment',
                  settings: { packets: '5-10', length: '10-20', delay: 3, maxSplit: 0 },
                },
              ],
            },
          },
        },
      ],
      NOW
    );
    expect(r.servers[0].xrayTcpFragment).toEqual({
      packets: '5-10',
      lengths: ['10-20'],
      delays: ['3'],
      maxSplit: '0',
    });
  });

  it('vmess + ws + tls → ServerConfig', () => {
    const r = parseXrayOutbounds(
      [
        {
          protocol: 'vmess',
          tag: 'vm1',
          settings: {
            vnext: [
              {
                address: '1.2.3.4',
                port: 443,
                users: [{ id: 'uuid-1', alterId: 2, security: 'auto' }],
              },
            ],
          },
          streamSettings: {
            network: 'ws',
            security: 'tls',
            wsSettings: { path: '/p', headers: { Host: 'h.com' } },
            tlsSettings: { serverName: 'h.com', fingerprint: 'chrome' },
          },
        },
      ],
      NOW
    );
    expect(r.servers).toHaveLength(1);
    const s = r.servers[0];
    expect(s.protocol).toBe('vmess');
    expect(s.address).toBe('1.2.3.4');
    expect(s.port).toBe(443);
    expect(s.uuid).toBe('uuid-1');
    expect(s.alterId).toBe(2);
    expect(s.network).toBe('ws');
    expect(s.security).toBe('tls');
    expect(s.wsSettings?.path).toBe('/p');
    expect(s.wsSettings?.headers?.Host).toBe('h.com');
    expect(s.tlsSettings?.serverName).toBe('h.com');
  });

  it('vless + reality + grpc → flow + realitySettings + grpc', () => {
    const r = parseXrayOutbounds(
      [
        {
          protocol: 'vless',
          tag: 'vl1',
          settings: {
            vnext: [
              {
                address: '5.6.7.8',
                port: 8443,
                users: [{ id: 'uuid-2', flow: 'xtls-rprx-vision' }],
              },
            ],
          },
          streamSettings: {
            network: 'grpc',
            security: 'reality',
            grpcSettings: { serviceName: 'grpc-svc' },
            realitySettings: { publicKey: 'pk', shortId: 'sid', serverName: 'sni.com' },
          },
        },
      ],
      NOW
    );
    expect(r.servers).toHaveLength(1);
    const s = r.servers[0];
    expect(s.protocol).toBe('vless');
    expect(s.uuid).toBe('uuid-2');
    expect(s.flow).toBe('xtls-rprx-vision');
    expect(s.network).toBe('grpc');
    expect(s.grpcSettings?.serviceName).toBe('grpc-svc');
    expect(s.security).toBe('reality');
    expect(s.realitySettings?.publicKey).toBe('pk');
    expect(s.realitySettings?.shortId).toBe('sid');
  });

  it('trojan + shadowsocks 映射凭据', () => {
    const r = parseXrayOutbounds(
      [
        {
          protocol: 'trojan',
          tag: 't1',
          settings: { servers: [{ address: 'a.com', port: 443, password: 'pw' }] },
        },
        {
          protocol: 'shadowsocks',
          tag: 'ss1',
          settings: {
            servers: [{ address: 'b.com', port: 8388, method: 'aes-256-gcm', password: 'sspw' }],
          },
        },
      ],
      NOW
    );
    expect(r.servers).toHaveLength(2);
    const trojan = r.servers.find((s) => s.protocol === 'trojan')!;
    expect(trojan.password).toBe('pw');
    const ss = r.servers.find((s) => s.protocol === 'shadowsocks')!;
    expect(ss.shadowsocksSettings?.method).toBe('aes-256-gcm');
    expect(ss.shadowsocksSettings?.password).toBe('sspw');
  });

  it('不支持协议计 skipped；内部协议(freedom) 忽略不计', () => {
    const r = parseXrayOutbounds(
      [
        { protocol: 'socks', tag: 's', settings: { servers: [{ address: 'x', port: 1 }] } },
        { protocol: 'freedom', tag: 'direct' },
        { protocol: 'blackhole', tag: 'block' },
      ],
      NOW
    );
    expect(r.servers).toHaveLength(0);
    expect(r.skipped).toBe(1); // 仅 socks，freedom/blackhole 不计
  });

  it('imports an Xray Hysteria 2 outbound with Salamander without dropping TLS or auth', () => {
    const outbound = {
      protocol: 'hysteria',
      settings: { address: 'proxy.example.com', port: 443, version: 2 },
      streamSettings: {
        method: 'hysteria',
        security: 'tls',
        tlsSettings: { serverName: 'proxy.example.com', alpn: ['h3'] },
        hysteriaSettings: { version: 2, auth: 'proxy-password' },
        finalmask: { udp: [{ type: 'salamander', settings: { password: 'mask-password' } }] },
      },
    };
    const result = parseXrayOutbounds([outbound], NOW);
    expect(result.servers).toHaveLength(1);
    expect(result.servers[0]).toMatchObject({
      protocol: 'hysteria2',
      password: 'proxy-password',
      security: 'tls',
      tlsSettings: { serverName: 'proxy.example.com', allowInsecure: false, alpn: ['h3'] },
      hysteria2Settings: { obfs: { type: 'salamander', password: 'mask-password' } },
    });
    expect(result.servers[0].network).toBeUndefined();
    const invalid = {
      ...outbound,
      streamSettings: {
        ...outbound.streamSettings,
        finalmask: { udp: [{ type: 'salamander', settings: {} }] },
      },
    };
    expect(parseXrayOutbounds([invalid], NOW)).toMatchObject({ servers: [], failed: 1 });
  });

  it('缺必填字段 → failed，不产出节点', () => {
    const r = parseXrayOutbounds(
      [
        {
          protocol: 'vmess',
          tag: 'bad',
          settings: { vnext: [{ address: '1.1.1.1', port: 443, users: [{}] }] },
        },
      ],
      NOW
    );
    expect(r.servers).toHaveLength(0);
    expect(r.failed).toBe(1);
  });

  it('非数组 → 空结果', () => {
    const r = parseXrayOutbounds(undefined, NOW);
    expect(r.servers).toHaveLength(0);
    expect(r.skipped).toBe(0);
    expect(r.failed).toBe(0);
  });
});

describe('parseXrayConfigArray / isXrayConfigArray', () => {
  const vless = (tag: string, address: string, network = 'tcp') => ({
    tag,
    protocol: 'vless',
    settings: { vnext: [{ address, port: 443, users: [{ id: 'u' }] }] },
    streamSettings: { network },
  });

  it('单出口配置 → 名为 remarks', () => {
    const r = parseXrayConfigArray(
      [{ remarks: 'NL', outbounds: [vless('proxy', '1.1.1.1')] }],
      NOW
    );
    expect(r.servers.map((s) => s.name)).toEqual(['NL']);
  });

  it('无 remarks → 保留 tag 名', () => {
    const r = parseXrayConfigArray([{ outbounds: [vless('proxy', '1.1.1.1')] }], NOW);
    expect(r.servers.map((s) => s.name)).toEqual(['proxy']);
  });

  it('imports XHTTP for VLESS and skips unsupported KCP', () => {
    const r = parseXrayConfigArray(
      [
        { remarks: 'A', outbounds: [vless('proxy', '1.1.1.1', 'xhttp')] },
        { remarks: 'B', outbounds: [vless('proxy', '2.2.2.2', 'raw')] },
        { remarks: 'C', outbounds: [vless('proxy', '2.2.2.2', 'kcp')] },
      ],
      NOW
    );
    expect(r.servers.map((s) => [s.name, s.network])).toEqual([['A', 'xhttp'], ['B', 'tcp']]);
    expect(r.skipped).toBe(1);
    expect(r.warnings.join()).toMatch(/vless\+kcp\(1\)/);
  });

  it('isXrayConfigArray 只认「每项都有 outbounds 数组」的非空数组', () => {
    expect(isXrayConfigArray([{ outbounds: [] }])).toBe(true);
    expect(isXrayConfigArray([])).toBe(false);
    expect(isXrayConfigArray([{ outbounds: [] }, { proxies: [] }])).toBe(false);
    expect(isXrayConfigArray({ outbounds: [] })).toBe(false);
  });
});
