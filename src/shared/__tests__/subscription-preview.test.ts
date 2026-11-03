import {
  classifySubscriptionError,
  SUBSCRIPTION_ERROR_I18N_KEY,
  type SubscriptionErrorKind,
} from '../subscription-preview';

describe('classifySubscriptionError（订阅预检错误分类）', () => {
  it('httpStatus ≥400 最高优先 → http（带状态码）', () => {
    expect(classifySubscriptionError({ httpStatus: 403 })).toEqual({
      errorKind: 'http',
      httpStatus: 403,
    });
    expect(classifySubscriptionError({ httpStatus: 502, code: 'ECONNREFUSED' })).toEqual({
      errorKind: 'http',
      httpStatus: 502,
    });
    // <400 不算 http（不该有，但防御）
    expect(classifySubscriptionError({ httpStatus: 302 }).errorKind).not.toBe('http');
  });

  it('网络错误码：ENOTFOUND→dns / ETIMEDOUT→timeout / ECONNREFUSED→refused', () => {
    expect(classifySubscriptionError({ code: 'ENOTFOUND' }).errorKind).toBe('dns');
    expect(classifySubscriptionError({ code: 'EAI_AGAIN' }).errorKind).toBe('dns');
    expect(classifySubscriptionError({ code: 'ETIMEDOUT' }).errorKind).toBe('timeout');
    expect(classifySubscriptionError({ code: 'UND_ERR_CONNECT_TIMEOUT' }).errorKind).toBe(
      'timeout'
    );
    expect(classifySubscriptionError({ code: 'ABORT_ERR' }).errorKind).toBe('timeout');
    expect(classifySubscriptionError({ code: 'ECONNREFUSED' }).errorKind).toBe('refused');
    expect(classifySubscriptionError({ code: 'EHOSTUNREACH' }).errorKind).toBe('refused');
  });

  it('Electron net::ERR_* / 英文关键字兜底（code 藏在 message）', () => {
    expect(classifySubscriptionError({ message: 'net::ERR_NAME_NOT_RESOLVED' }).errorKind).toBe(
      'dns'
    );
    expect(
      classifySubscriptionError({ message: 'request to x failed, ERR_TIMED_OUT' }).errorKind
    ).toBe('timeout');
    expect(classifySubscriptionError({ message: 'net::ERR_CONNECTION_REFUSED' }).errorKind).toBe(
      'refused'
    );
    expect(classifySubscriptionError({ message: 'The operation was aborted' }).errorKind).toBe(
      'timeout'
    );
  });

  it('本项目确定性中文文案：体积/协议/空/SSRF/解析', () => {
    expect(
      classifySubscriptionError({
        message: 'Subscription response too large (limit 10485760 bytes), rejected',
      }).errorKind
    ).toBe('toolarge');
    expect(
      classifySubscriptionError({
        message: 'Unsupported subscription URL scheme (only http/https allowed): https://x',
      }).errorKind
    ).toBe('scheme');
    expect(
      classifySubscriptionError({ message: 'sing-box subscription yielded 0 usable nodes' })
        .errorKind
    ).toBe('empty');
    expect(
      classifySubscriptionError({
        message:
          'Subscription URL points to a local/private/link-local address, rejected: 127.0.0.1',
      }).errorKind
    ).toBe('ssrf');
    expect(
      classifySubscriptionError({ message: 'Too many redirects (limit 5), rejected' }).errorKind
    ).toBe('ssrf');
    expect(
      classifySubscriptionError({ message: 'Failed to parse Clash YAML: bad indentation' })
        .errorKind
    ).toBe('parse');
    expect(
      classifySubscriptionError({
        message:
          'Clash subscription detected, but the document structure is malformed (not an object)',
      }).errorKind
    ).toBe('parse');
    expect(
      classifySubscriptionError({
        message:
          'Unrecognized subscription format: not sing-box JSON and no parsable node URLs found',
      }).errorKind
    ).toBe('parse');
    expect(
      classifySubscriptionError({
        message:
          'None of the node URLs in the subscription could be parsed (unsupported protocol or malformed); 0 usable nodes',
      }).errorKind
    ).toBe('empty');
    expect(
      classifySubscriptionError({
        message: 'DNS lookup failed for subscription host, rejected: sub.example.com (ENOTFOUND)',
      }).errorKind
    ).toBe('dns');
  });

  it('http 文案优先于 refused：empty/scheme/toolarge 是主动 throw 文案，先于网络码判', () => {
    // 体积超限文案 + 恰好 message 含 refused 关键字（极端），体积优先（本项目主动 throw 稳定文案）
    expect(
      classifySubscriptionError({
        message:
          'Subscription response too large (limit 10485760 bytes), rejected, connection refused noise',
      }).errorKind
    ).toBe('toolarge');
  });

  it('节点全部栽在内核不支持的传输层（xhttp）→ transport，先于 empty（文案同含「0 个可用节点」）', () => {
    expect(
      classifySubscriptionError({
        message: 'All subscription nodes use an unsupported transport (xhttp); 0 usable nodes',
      })
    ).toEqual({ errorKind: 'transport' });
  });

  it('未覆盖形态 → unknown（不误判，UI 给通用文案 + 原始 message 上报）', () => {
    expect(classifySubscriptionError({ message: 'something entirely novel' }).errorKind).toBe(
      'unknown'
    );
    expect(classifySubscriptionError({}).errorKind).toBe('unknown');
  });

  it('每个 errorKind 都有 i18n title/detail key（无遗漏，防新增分类漏配文案）', () => {
    const kinds: SubscriptionErrorKind[] = [
      'dns',
      'timeout',
      'refused',
      'http',
      'ssrf',
      'scheme',
      'toolarge',
      'parse',
      'empty',
      'unknown',
    ];
    for (const k of kinds) {
      expect(SUBSCRIPTION_ERROR_I18N_KEY[k]?.title).toMatch(/^sub\.preview\./);
      expect(SUBSCRIPTION_ERROR_I18N_KEY[k]?.detail).toMatch(/^sub\.preview\./);
    }
  });
});
