/**
 * 解析器安全/健壮性回归（纯模块，无 electron）：
 *  - #2  provider filter 灾难性回溯正则在预算内被中断，按非法 filter 处理（忽略 + warn）。
 *  - #7  vmess / shadow-tls 的 JSON 错误不回显解码内容。
 *  - #9  节点名含字面 `%` 不再丢节点。
 *  - #10 VLESS Encryption support and secret-safe errors for unknown methods.
 *  - #11 证书钉扎（hy2 pinSHA256 / Clash fingerprint）无法执行 → 保留节点 + 逐节点告警。
 */
import {
  applyProviderFilters,
  parseClashProxies,
  runFilterPatternsWithBudget,
} from '../ClashSubscriptionParser';
import { ProtocolParser, decodeNodeName, describeJsonError } from '../ProtocolParser';
import { parseXrayOutbounds } from '../xray-import';
import { classifySubscriptionError } from '../../../shared/subscription-preview';

const named = (names: string[]) => names.map((name) => ({ name }));

function parserWithLog() {
  const logs: { level: string; message: string }[] = [];
  const p = new ProtocolParser();
  p.setLogManager({
    addLog: (level: string, message: string) => logs.push({ level, message }),
  } as never);
  return { p, logs };
}

describe('#2 provider filter ReDoS 预算', () => {
  it('灾难性回溯 filter 在预算内中断 → filter 被忽略（全保留）+ warn', () => {
    const warns: string[] = [];
    const proxies = named(['a'.repeat(40) + 'b', 'HK 01']);
    const t = Date.now();
    const res = applyProviderFilters(proxies, '^(a+)+$', undefined, (m) => warns.push(m), 'p', 100);
    expect(Date.now() - t).toBeLessThan(2000);
    expect(res).toHaveLength(2);
    expect(warns.join('\n')).toMatch(/filter took longer than 100 ms/);
  });

  it('filter 超时 → 其后的 exclude-filter 同样按非法处理', () => {
    const warns: string[] = [];
    const res = applyProviderFilters(
      named(['a'.repeat(40) + 'b', 'US']),
      '^(a+)+$',
      'US',
      (m) => warns.push(m),
      'p',
      100
    );
    expect(res).toHaveLength(2);
    expect(warns.filter((w) => /took longer/.test(w))).toHaveLength(2);
  });

  it('正常 filter + exclude 语义不变（留 HK、剔 IPLC）', () => {
    const res = applyProviderFilters(
      named(['HK 01', 'HK IPLC', 'US 01']),
      'HK',
      'IPLC',
      () => {},
      'p'
    ) as Array<{ name: string }>;
    expect(res.map((r) => r.name)).toEqual(['HK 01']);
  });

  it('runFilterPatternsWithBudget：exclude 阶段超时只丢该阶段，已完成的 filter 结果保留', () => {
    const r = runFilterPatternsWithBudget(['^a', '^(a+)+$'], ['a'.repeat(40) + 'b', 'zz'], 100);
    expect(r.timedOutAt).toBe(1);
    expect(r.results).toEqual([[true, false]]);
  });
});

describe('#7 JSON 错误不回显输入', () => {
  it('vmess base64 非法 JSON → 错误只含位置', () => {
    const { p } = parserWithLog();
    const payload = '{"add":"1.2.3.4","id":"SECRET-UUID-123","port":443,,}';
    const url = 'vmess://' + Buffer.from(payload).toString('base64');
    let msg = '';
    try {
      p.parseUrl(url);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/invalid JSON/);
    expect(msg).not.toContain('SECRET-UUID-123');
  });

  it('describeJsonError 不含原文', () => {
    let err: unknown;
    try {
      JSON.parse('{"password":"hunter2" x}');
    } catch (e) {
      err = e;
    }
    expect(describeJsonError(err)).not.toContain('hunter2');
  });

  it('shadow-tls 参数非法 JSON → 日志不含解码内容', () => {
    const { p, logs } = parserWithLog();
    const bad = Buffer.from('{"password":"st-secret" broken').toString('base64');
    p.parseUrl(
      `ss://${Buffer.from('aes-128-gcm:pw').toString('base64')}@1.2.3.4:8388?shadow-tls=${encodeURIComponent(bad)}#n`
    );
    const all = logs.map((l) => l.message).join('\n');
    expect(all).toMatch(/shadow-tls/);
    expect(all).not.toContain('st-secret');
  });
});

describe('#9 节点名含字面 %', () => {
  it('decodeNodeName：合法 %XX 照常解码，孤立 % 原样保留', () => {
    expect(decodeNodeName('DE%20100%%20speed')).toBe('DE 100% speed');
    expect(decodeNodeName('%F0%9F%87%A9%F0%9F%87%AA%20100%')).toBe('🇩🇪 100%');
    expect(decodeNodeName('plain')).toBe('plain');
  });

  it('vless / ss / tuic 链接名含 % 不丢节点', () => {
    const { p } = parserWithLog();
    expect(p.parseUrl('vless://u@1.2.3.4:443?security=none#DE 100% speed').name).toBe(
      'DE 100% speed'
    );
    const ss = `ss://${Buffer.from('aes-128-gcm:pw').toString('base64')}@1.2.3.4:8388#50% off`;
    expect(p.parseUrl(ss).name).toBe('50% off');
    expect(p.parseUrl('tuic://uuid:pw@1.2.3.4:443?sni=a.b#100%25 ok %').name).toBe('100% ok %');
  });
});

describe('VLESS Encryption', () => {
  const ENC = 'mlkem768x25519plus.native.0rtt.AAAA.BBBB';

  it('round-trips the case-sensitive Xray encryption string', () => {
    const { p } = parserWithLog();
    const node = p.parseUrl(`vless://u@1.2.3.4:443?encryption=${ENC}&security=tls#n`);
    expect(node.encryption).toBe(ENC);
    expect(p.parseUrl(p.generateUrl(node)).encryption).toBe(ENC);
  });

  it('rejects unknown encryption without disclosing keys', () => {
    const { p } = parserWithLog();
    let msg = '';
    try {
      p.parseUrl('vless://u@1.2.3.4:443?encryption=other.native.0rtt.AAAA.BBBB&security=tls#n');
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/Unsupported transport type: vless-encryption:other/);
    expect(msg).not.toContain('AAAA');
    expect(classifySubscriptionError({ message: msg }).errorKind).toBe('transport');
  });

  it('encryption=none / 缺省 / 历史噪声值 auto 仍放行', () => {
    const { p } = parserWithLog();
    expect(p.parseUrl('vless://u@1.2.3.4:443?encryption=none#n').protocol).toBe('vless');
    expect(p.parseUrl('vless://u@1.2.3.4:443#n').protocol).toBe('vless');
    expect(p.parseUrl('vless://u@1.2.3.4:443?encryption=auto#n').protocol).toBe('vless');
  });

  it('keeps VLESS Encryption in a Clash profile', () => {
    const r = parseClashProxies(
      [
        { name: 'enc', type: 'vless', server: '1.2.3.4', port: 443, uuid: 'u', encryption: ENC },
        { name: 'plain', type: 'vless', server: '1.2.3.4', port: 443, uuid: 'u', encryption: '' },
      ],
      's',
      'now'
    );
    expect(r.servers.map((s) => s.encryption)).toEqual([ENC, 'none']);
    expect(r.warnings).toHaveLength(0);
  });

  it('keeps VLESS Encryption in legacy and flat Xray profiles', () => {
    const r = parseXrayOutbounds(
      [
        {
          protocol: 'vless',
          tag: 'enc',
          settings: {
            vnext: [{ address: '1.2.3.4', port: 443, users: [{ id: 'u', encryption: ENC }] }],
          },
        },
        {
          protocol: 'vless',
          tag: 'plain',
          settings: {
            address: '1.2.3.4',
            port: 443,
            id: 'u',
            encryption: 'none',
          },
        },
      ],
      'now'
    );
    expect(r.servers.map((s) => s.encryption)).toEqual([ENC, 'none']);
    expect(r.warnings).toHaveLength(0);
  });
});

describe('#11 证书钉扎无法执行 → 保留节点 + 告警', () => {
  it('hy2 pinSHA256 + insecure=1 → 节点保留，warn 说明连接未校验', () => {
    const { p, logs } = parserWithLog();
    const s = p.parseUrl('hy2://pw@1.2.3.4:443?insecure=1&pinSHA256=AB:CD#pinned');
    expect(s.protocol).toBe('hysteria2');
    const w = logs.filter((l) => l.level === 'warn').map((l) => l.message);
    expect(w.some((m) => /pinned.*pinSHA256.*NOT verified/.test(m))).toBe(true);
  });

  it('Clash fingerprint（证书钉扎）→ 节点保留 + warning；client-fingerprint 不触发', () => {
    const r = parseClashProxies(
      [
        {
          name: 'pin',
          type: 'trojan',
          server: '1.2.3.4',
          port: 443,
          password: 'p',
          'skip-cert-verify': true,
          fingerprint: 'aa'.repeat(32),
        },
        {
          name: 'hy',
          type: 'hysteria2',
          server: '1.2.3.4',
          port: 443,
          password: 'p',
          fingerprint: 'bb'.repeat(32),
        },
        {
          name: 'utls',
          type: 'trojan',
          server: '1.2.3.4',
          port: 443,
          password: 'p',
          'client-fingerprint': 'chrome',
        },
      ],
      's',
      'now'
    );
    expect(r.servers.map((s) => s.name)).toEqual(['pin', 'hy', 'utls']);
    expect(r.warnings.some((w) => /"pin".*NOT verified/.test(w))).toBe(true);
    expect(r.warnings.some((w) => /"hy".*only standard CA verification/.test(w))).toBe(true);
    expect(r.warnings.some((w) => /"utls"/.test(w))).toBe(false);
  });
});
