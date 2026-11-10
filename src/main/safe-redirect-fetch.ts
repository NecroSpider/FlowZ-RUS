/**
 * 带逐跳 SSRF 复检的安全重定向 fetch（订阅 / flowz-icon:// 统一安全拉取入口）。
 *
 * 抽出动机：订阅、图标协议各自内联同一段「redirect:'manual' 自管链 + 每跳 Location 过
 * assertHostAllowed + drainBody 上一跳 + 重定向上限」。默认 redirect:'follow' 会让首 URL 过 guard 后被
 * 30x 跳到内网而不复检，构成 SSRF 绕过；逐跳复检是安全关键，分散在多处易漏。收口到本 helper：新入口直接
 * 复用，不会再出现「首 URL 校验了、redirect 没逐跳校验」。
 *
 * 错误以结构化 SafeFetchError(reason) 抛出，调用方按 reason 映射各自语义（icon → HTTP 状态码；订阅 → 中文
 * 错误文案冒泡给 UI）。fetchImpl 自身的网络错误（非 SafeFetchError）原样冒泡，由调用方兜底。
 */
import { promises as dnsPromises } from 'dns';
import { assertHostAllowed, type DnsLookupAll } from '../shared/ssrf-guard';

/** 安全 fetch 拒绝原因：调用方据此映射 HTTP 状态码（icon）或区分错误类别。 */
export type SafeFetchRejectReason = 'redirect-protocol' | 'ssrf' | 'too-many-redirects';

/** redirect 链中的安全拒绝（区别于 fetchImpl 网络错误）。reason 供调用方映射状态码/文案。 */
export class SafeFetchError extends Error {
  constructor(
    readonly reason: SafeFetchRejectReason,
    message: string
  ) {
    super(message);
    this.name = 'SafeFetchError';
  }
}

/** helper 容忍的最小 Response 形状（Electron Response 与 net.fetch GlobalResponse 的同构子集）。 */
interface MinimalResponse {
  status: number;
  headers: { get(name: string): string | null };
  body?: { cancel(): Promise<unknown> } | null;
}

export interface SafeRedirectFetchOptions<R extends MinimalResponse> {
  /** 绑定好会话的 fetch（Session.fetch.bind / net.fetch）；helper 固定下发 redirect:'manual'。 */
  fetchImpl: (
    url: string,
    init: { headers: Record<string, string>; redirect: 'manual'; signal?: AbortSignal }
  ) => Promise<R>;
  /** 起始 URL，调用方已保证为 http(s)。 */
  url: string;
  userAgent: string;
  /** 附加请求头（§16.3.4 条件 GET 的 If-None-Match / If-Modified-Since；订阅设备标识 x-hwid 等）。
   *  与 User-Agent 合并（同名以本字段为准）；缺省不加。跨源重定向一跳起仅保留 CROSS_ORIGIN_SAFE_HEADERS。 */
  headers?: Record<string, string>;
  /** 仅实际经代理（proxied socks 出口、本机内网不可达）时豁免 FlowZ FakeIP；直连/端口回退传 false。 */
  exemptFakeIp: boolean;
  /**
   * 起始 URL 由用户亲手填写（主订阅）：首跳不做内网判定——公司内网（经工作 VPN 解析到 10.x）/ 局域网面板 /
   * 本机 subconverter 都是合法订阅源，而 SSRF 要防的是「远端内容驱使本机去拉内网」。重定向目标仍逐跳复检。
   * provider 等来自订阅正文的地址不得传 true。
   */
  trustInitialUrl?: boolean;
  /** 重定向上限（含首跳之外的跳数），默认 5。 */
  maxRedirects?: number;
  signal?: AbortSignal;
  /** 注入 DNS 解析（默认 dnsPromises.lookup all），便于测试。 */
  lookup?: DnsLookupAll;
}

const DEFAULT_MAX_REDIRECTS = 5;

/**
 * 跨源重定向后仍可携带的请求头（小写）：缓存验证器（§16.3.4 条件 GET 的 validator 来自终态源，跨源跳转后
 * 正需要它）与内容协商头。其余一律视为凭据/身份（x-hwid / x-device-* 设备标识、Authorization、Cookie…）在
 * 跨源一跳起剥离——白名单 fail-closed，新增身份头无需记得登记。User-Agent 由 helper 单独下发、恒携带。
 */
const CROSS_ORIGIN_SAFE_HEADERS = new Set([
  'if-none-match',
  'if-modified-since',
  'accept',
  'accept-language',
]);

const defaultPort = (u: URL): string => u.port || (u.protocol === 'https:' ? '443' : '80');

/**
 * 两跳是否「同源」（可继续携带身份头）：scheme+host+port 全同；或同 host 的 http→https 升级（默认端口）——
 * 面板常把 http 订阅地址 301 到 https，剥掉设备头会让设备数限制面板视为「未带 HWID」。https→http 降级不算同源
 * （明文泄漏）。
 */
export function isSameOriginHop(from: URL, to: URL): boolean {
  if (from.hostname.toLowerCase() !== to.hostname.toLowerCase()) return false;
  if (from.protocol === to.protocol) return defaultPort(from) === defaultPort(to);
  return (
    from.protocol === 'http:' &&
    to.protocol === 'https:' &&
    defaultPort(from) === '80' &&
    defaultPort(to) === '443'
  );
}

/** 剥离跨源不可携带的头（见 CROSS_ORIGIN_SAFE_HEADERS）。 */
export function stripCrossOriginHeaders(
  headers: Record<string, string> | undefined
): Record<string, string> | undefined {
  if (!headers) return headers;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (CROSS_ORIGIN_SAFE_HEADERS.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

/** 释放响应体，避免丢弃上一跳 body 时 socket/内存泄漏。 */
async function drainBody(r: MinimalResponse): Promise<void> {
  try {
    await r.body?.cancel();
  } catch {
    /* ignore */
  }
}

/** SSRF guard：assertHostAllowed 抛错统一归类为 SafeFetchError('ssrf')，保留原始消息（含 hostname/解析结果）。 */
async function guard(urlObj: URL, lookup: DnsLookupAll, exemptFakeIp: boolean): Promise<void> {
  try {
    await assertHostAllowed(urlObj, lookup, exemptFakeIp);
  } catch (e) {
    throw new SafeFetchError('ssrf', e instanceof Error ? e.message : String(e));
  }
}

/**
 * 首跳 + 每一跳 Location 都过 SSRF guard（含 DNS 逐 IP 判定），通过才续跳，最多 maxRedirects 跳。
 * 返回终态（非 30x）response，其 body 未消费、交调用方处理；中途 30x 的 body 由本 helper drain。
 */
export async function safeRedirectFetch<R extends MinimalResponse>(
  opts: SafeRedirectFetchOptions<R>
): Promise<R> {
  const maxRedirects = Math.max(0, opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS);
  const lookup: DnsLookupAll = opts.lookup ?? ((h) => dnsPromises.lookup(h, { all: true }));
  let currentUrl = opts.url;
  // 逐跳请求头：一旦跨源即剥离身份/凭据头，且此后不再恢复（即便又跳回原源，对齐 fetch 规范语义）。
  let hopHeaders = opts.headers;

  // 首跳 guard（起始 URL 协议由调用方保证为 http(s)）；用户亲手填写的起始 URL 免检（见 trustInitialUrl）。
  if (!opts.trustInitialUrl) await guard(new URL(currentUrl), lookup, opts.exemptFakeIp);

  let response: R | null = null;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    response = await opts.fetchImpl(currentUrl, {
      headers: { 'User-Agent': opts.userAgent, ...hopHeaders },
      redirect: 'manual',
      ...(opts.signal ? { signal: opts.signal } : {}),
    });

    const loc =
      response.status >= 300 && response.status < 400 ? response.headers.get('location') : null;
    if (!loc) break; // 非 30x（或无 Location）→ 终态响应（body 交调用方消费）

    // 确认是 30x 重定向：后续无论续跳还是抛错（超上限/协议非法/SSRF）都已离开本跳响应，先释放其 body
    // 防 socket 泄漏（须在抛错分支之前 drain，否则被拒的那一跳 body 不被 cancel）。
    await drainBody(response);
    if (hop >= maxRedirects) {
      throw new SafeFetchError(
        'too-many-redirects',
        `Too many redirects (limit ${maxRedirects}), rejected`
      );
    }
    let nextObj: URL;
    try {
      nextObj = new URL(loc, currentUrl); // 相对 Location 以当前 URL 为基准解析
    } catch {
      throw new SafeFetchError('redirect-protocol', 'Invalid redirect target, rejected');
    }
    if (nextObj.protocol !== 'http:' && nextObj.protocol !== 'https:') {
      throw new SafeFetchError(
        'redirect-protocol',
        'Unsupported redirect target scheme (only http/https allowed), rejected'
      );
    }
    await guard(nextObj, lookup, opts.exemptFakeIp); // 重定向目标过同一 guard（含 DNS 解析）
    if (!isSameOriginHop(new URL(currentUrl), nextObj)) {
      hopHeaders = stripCrossOriginHeaders(hopHeaders);
    }
    currentUrl = nextObj.toString();
  }

  // 循环 hop=0 必执行一次 fetchImpl，response 必非 null（maxRedirects 已 clamp ≥0）。
  return response as R;
}
