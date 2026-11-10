/**
 * #3 自定义（raw-JSON 透传）outbound 安全闸：随包 sing-box 内置 tor outbound，executable_path / extra_args
 * 会在每次核启动 / 测速时拉起任意本机程序。choke point = buildProxyOutbound（核启动 + 测速唯一出口）+
 * buildOutbounds 的 custom endpoint 分支。
 */
jest.mock('electron', () => ({
  app: { getPath: () => '/fake/userData', getAppPath: () => '/fake/app', isPackaged: false },
  net: {},
}));

import {
  buildOutbounds,
  buildProxyOutbound,
  type OutboundsDeps,
} from '../singbox-outbound-builder';
import { customOutboundRejectReason } from '../../../shared/config-portability';
import type { ServerConfig, UserConfig, InvalidNodeInfo } from '../../../shared/types';

const custom = (id: string, outbound: Record<string, unknown>, isEndpoint = false): ServerConfig =>
  ({
    id,
    name: id,
    protocol: 'custom',
    address: '',
    port: 0,
    customSettings: { outbound, ...(isEndpoint ? { isEndpoint: true } : {}) },
  }) as unknown as ServerConfig;

describe('customOutboundRejectReason', () => {
  it('tor 整类拒绝（大小写/空白不敏感）', () => {
    expect(customOutboundRejectReason({ type: 'tor' })).toMatch(/not allowed/);
    expect(customOutboundRejectReason({ type: ' TOR ' })).toMatch(/not allowed/);
  });

  it('可执行 / 文件系统路径键（任意嵌套层级）拒绝', () => {
    expect(customOutboundRejectReason({ type: 'x', executable_path: '/bin/sh' })).toMatch(
      /executable_path/
    );
    expect(customOutboundRejectReason({ type: 'x', extra_args: [] })).toMatch(/extra_args/);
    expect(
      customOutboundRejectReason({ type: 'x', tls: { ech: { config_path: '/tmp/e' } } })
    ).toMatch(/tls\.ech\.config_path/);
    expect(customOutboundRejectReason({ type: 'tailscale', state_directory: '/' })).toMatch(
      /state_directory/
    );
    expect(customOutboundRejectReason({ type: 'x', list: [{ data_directory: 'd' }] })).toMatch(
      /list\[0\]\.data_directory/
    );
  });

  it('普通透传（含 ws transport.path URL 路径）放行', () => {
    expect(
      customOutboundRejectReason({
        type: 'hysteria',
        server: 'a.example',
        server_port: 443,
        auth_str: 's',
        transport: { type: 'ws', path: '/ray' },
        tls: { enabled: true, server_name: 'a.example' },
      })
    ).toBeNull();
    expect(customOutboundRejectReason(undefined)).toBeNull();
  });
});

describe('buildProxyOutbound / buildOutbounds 拒绝危险 custom 节点', () => {
  const deps = (log: OutboundsDeps['log']): OutboundsDeps => ({
    gateInvalidNodes: new Map<string, InvalidNodeInfo>(),
    log,
  });
  const cfg = (servers: ServerConfig[]): UserConfig =>
    ({
      proxyMode: 'smart',
      servers,
      selectedServerId: servers[0]?.id,
      customRules: [],
      appRules: [],
    }) as unknown as UserConfig;

  it('buildProxyOutbound（测速同路径）对 tor throw', () => {
    const s = custom('t1', { type: 'tor', executable_path: '/bin/sh' });
    expect(() => buildProxyOutbound(s, new Map([[s.id, 't1']]), 'dns-direct')).toThrow(
      /custom outbound refused/
    );
  });

  it('buildOutbounds：tor outbound / 带路径键的 custom endpoint 不下发，合法 custom 照常；均记 warn', () => {
    const logs: string[] = [];
    const ok = custom('ok', { type: 'hysteria', server: 'a.example', server_port: 443 });
    const tor = custom('tor', { type: 'tor', extra_args: ['--x'] });
    const ep = custom('ep', { type: 'tailscale', state_directory: '/etc' }, true);
    const servers = [ok, tor, ep];
    const r = buildOutbounds(
      ok,
      cfg(servers),
      new Map(servers.map((s) => [s.id, s.name])),
      deps((_lvl, msg) => logs.push(msg))
    );
    const json = JSON.stringify([...r.outbounds, ...r.pendingEndpoints]);
    expect(json).not.toMatch(/"type":"tor"/);
    expect(json).not.toContain('state_directory');
    expect(r.outbounds.some((o) => o.tag === 'ok')).toBe(true);
    expect(logs.some((m) => m.includes('tor'))).toBe(true);
    expect(logs.some((m) => m.includes('ep') && m.includes('state_directory'))).toBe(true);
  });
});
