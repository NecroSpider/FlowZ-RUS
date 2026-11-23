import * as http2 from 'http2';

export interface SubscriptionFetchInit {
  headers: Record<string, string>;
  redirect: 'manual';
  signal?: AbortSignal;
}

/** One already-validated redirect hop. Never follows redirects or disables TLS verification. */
export function fetchSubscriptionH2(
  url: string,
  init: SubscriptionFetchInit,
  maxBytes: number
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const client = http2.connect(target.origin);
    const chunks: Buffer[] = [];
    let bytes = 0;
    let status = 0;
    let headers = new Headers();
    let done = false;
    const signal = init.signal ?? AbortSignal.timeout(20_000);
    const finish = (error?: Error, response?: Response) => {
      if (done) return;
      done = true;
      signal.removeEventListener('abort', abort);
      client.destroy();
      if (error) reject(error);
      else resolve(response!);
    };
    const abort = () => finish(new Error('Subscription HTTP/2 request timed out or was aborted'));
    client.on('error', (error) => finish(error));
    client.on('close', () => {
      if (!done) finish(new Error('Subscription HTTP/2 session closed before the response ended'));
    });
    if (signal.aborted) return abort();
    signal.addEventListener('abort', abort, { once: true });
    let request: http2.ClientHttp2Stream;
    try {
      request = client.request({
        ...Object.fromEntries(Object.entries(init.headers).map(([k, v]) => [k.toLowerCase(), v])),
        ':method': 'GET',
        ':path': target.pathname + target.search,
        'accept-encoding': 'identity',
      });
    } catch (error) {
      finish(error as Error);
      return;
    }
    request.on('response', (incoming) => {
      status = Number(incoming[':status']);
      headers = new Headers();
      for (const [key, value] of Object.entries(incoming)) {
        if (key.startsWith(':') || value === undefined) continue;
        for (const item of Array.isArray(value) ? value : [value])
          headers.append(key, String(item));
      }
      if (Number(headers.get('content-length')) > maxBytes) {
        finish(new Error(`Subscription response too large (limit ${maxBytes} bytes), rejected`));
      }
    });
    request.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        finish(new Error(`Subscription response too large (limit ${maxBytes} bytes), rejected`));
      } else chunks.push(chunk);
    });
    request.on('error', (error) => finish(error));
    request.on('end', () => {
      if (done) return;
      try {
        const body = [204, 205, 304].includes(status)
          ? null
          : new Uint8Array(Buffer.concat(chunks));
        finish(undefined, new Response(body, { status, headers }));
      } catch (error) {
        finish(error as Error);
      }
    });
    request.on('close', () => {
      if (!done)
        finish(new Error('Subscription HTTP/2 connection closed before the response ended'));
    });
    request.end();
  });
}

/** Direct HTTPS only: retain Chromium normally, then retry a failed TLS/network attempt with HTTP/2. */
export async function fetchDirectSubscription<R>(
  fetchImpl: (url: string, init: SubscriptionFetchInit) => Promise<R>,
  url: string,
  init: SubscriptionFetchInit,
  maxBytes: number,
  onFallback?: () => void,
  h2Fetch = fetchSubscriptionH2
): Promise<R | Response> {
  if (!url.startsWith('https:')) return fetchImpl(url, init);
  const firstAttempt = new AbortController();
  const timer = setTimeout(() => firstAttempt.abort(), 8_000);
  try {
    return await fetchImpl(url, {
      ...init,
      signal: init.signal
        ? AbortSignal.any([init.signal, firstAttempt.signal])
        : firstAttempt.signal,
    });
  } catch (error) {
    if (init.signal?.aborted) throw error;
    onFallback?.();
    return await h2Fetch(url, init, maxBytes);
  } finally {
    clearTimeout(timer);
  }
}
