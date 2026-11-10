/**
 * #14 诊断脱敏缺口：*Url 键（ruleResources[].sourceUrl ?token=）、DoH 账号路径（NextDNS profile id）、
 * 导入的 custom 节点无 secretKeys 声明时的通用凭据键（hysteria v1 auth_str 等）。
 */
import { redactDeep, redactDnsValue, REDACTED } from '../diagnostic-redact';

describe('diagnostic redaction gaps', () => {
  it('以 Url/url 结尾的键按 url 处理（只留 origin）', () => {
    const out = redactDeep({
      ruleResources: [{ id: 'r', sourceUrl: 'https://cdn.example/x.srs?token=SECRET' }],
      singboxDashboardUrl: 'https://dash.example/path/TOKEN',
      mirrorUrls: ['https://m.example/a?k=SECRET'],
    }) as any;
    const s = JSON.stringify(out);
    expect(s).not.toContain('SECRET');
    expect(s).not.toContain('TOKEN');
    expect(out.ruleResources[0].sourceUrl).toBe(`https://cdn.example/${REDACTED}`);
  });

  it('DoH 地址：私有路径打码、公共 /dns-query 保留、纯 IP 原样', () => {
    expect(redactDnsValue('https://dns.nextdns.io/abc123')).toBe(
      `https://dns.nextdns.io/${REDACTED}`
    );
    expect(redactDnsValue('https://dns.google/dns-query')).toBe('https://dns.google/dns-query');
    expect(redactDnsValue('tls://user:pw@dns.example')).toBe('tls://dns.example');
    expect(redactDnsValue('77.88.8.8')).toBe('77.88.8.8');
    const out = redactDeep({
      domesticDns: 'https://dns.nextdns.io/abc123',
      foreignDns: 'https://dns.google/dns-query',
    }) as any;
    expect(out.domesticDns).not.toContain('abc123');
    expect(out.foreignDns).toBe('https://dns.google/dns-query');
  });

  it('生成配置里的 https/h3 DNS server 对象：私有 path 打码，ws transport path 不动', () => {
    const out = redactDeep({
      dns: {
        servers: [
          { type: 'https', tag: 'a', server: 'dns.nextdns.io', path: '/abc123' },
          { type: 'h3', tag: 'b', server: 'dns.google', path: '/dns-query' },
        ],
      },
      outbounds: [{ type: 'vless', transport: { type: 'ws', path: '/ray' } }],
    }) as any;
    expect(out.dns.servers[0].path).toBe(`/${REDACTED}`);
    expect(out.dns.servers[1].path).toBe('/dns-query');
    expect(out.outbounds[0].transport.path).toBe('/ray');
  });

  it('无 secretKeys 的导入 custom 节点：auth_str / auth / 字符串 obfs 打码，hy2 obfs 对象只打码 password', () => {
    const out = redactDeep({
      servers: [
        {
          protocol: 'custom',
          customSettings: {
            outbound: {
              type: 'hysteria',
              auth_str: 'S1',
              auth: 'S2',
              obfs: 'S3',
              passphrase: 'S4',
            },
          },
        },
      ],
      outbounds: [{ type: 'hysteria2', obfs: { type: 'salamander', password: 'S5' } }],
    }) as any;
    const s = JSON.stringify(out);
    for (const v of ['S1', 'S2', 'S3', 'S4', 'S5']) expect(s).not.toContain(v);
    expect(out.outbounds[0].obfs.type).toBe('salamander');
  });
});
