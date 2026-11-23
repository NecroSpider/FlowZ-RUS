import * as http2 from 'http2';
import { fetchDirectSubscription, fetchSubscriptionH2 } from '../subscription-direct-fetch';

const init = {
  headers: { 'User-Agent': 'FlowZ/test', 'x-hwid': 'test-device' },
  redirect: 'manual' as const,
};

describe('direct subscription HTTP/2 fallback', () => {
  it('retries a direct HTTPS failure with the same headers and manual redirect handling', async () => {
    const response = new Response('subscription');
    const fallback = jest.fn().mockResolvedValue(response);
    const chromium = jest.fn().mockRejectedValue(new Error('net::ERR_TIMED_OUT'));
    expect(
      await fetchDirectSubscription(
        chromium,
        'https://sub.example.com/a',
        init,
        1024,
        undefined,
        fallback
      )
    ).toBe(response);
    expect(fallback).toHaveBeenCalledWith('https://sub.example.com/a', init, 1024);
  });

  it('does not retry an HTTP error response or an explicitly cancelled request', async () => {
    const fallback = jest.fn();
    const denied = new Response('', { status: 403 });
    expect(
      await fetchDirectSubscription(
        async () => denied,
        'https://sub.example.com/a',
        init,
        1024,
        undefined,
        fallback
      )
    ).toBe(denied);
    const controller = new AbortController();
    controller.abort();
    await expect(
      fetchDirectSubscription(
        async () => {
          throw new Error('cancelled');
        },
        'https://sub.example.com/a',
        { ...init, signal: controller.signal },
        1024,
        undefined,
        fallback
      )
    ).rejects.toThrow('cancelled');
    expect(fallback).not.toHaveBeenCalled();
  });

  it('keeps HTTP requests on the original transport', async () => {
    const fallback = jest.fn();
    await expect(
      fetchDirectSubscription(
        async () => {
          throw new Error('offline');
        },
        'http://sub.example.com/a',
        init,
        1024,
        undefined,
        fallback
      )
    ).rejects.toThrow('offline');
    expect(fallback).not.toHaveBeenCalled();
  });
});

describe('HTTP/2 response handling (loopback)', () => {
  let server: http2.Http2Server;
  let origin: string;
  beforeEach(async () => {
    server = http2.createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('returns a redirect without following it and preserves subscription validators', async () => {
    const hops: string[] = [];
    server.on('stream', (stream, headers) => {
      hops.push(String(headers[':path']));
      expect(headers['x-hwid']).toBe('test-device');
      (stream as http2.ServerHttp2Stream).respond({
        ':status': 302,
        location: 'http://127.0.0.2/private',
        etag: 'revision',
      });
      stream.end('redirect');
    });
    const response = await fetchSubscriptionH2(`${origin}/sub?key=example`, init, 1024);
    expect(response.status).toBe(302);
    expect(response.headers.get('etag')).toBe('revision');
    expect(await response.text()).toBe('redirect');
    expect(hops).toEqual(['/sub?key=example']);
  });

  it('rejects a response that exceeds the body limit without a content-length', async () => {
    server.on('stream', (stream) => {
      (stream as http2.ServerHttp2Stream).respond({ ':status': 200 });
      stream.end('x'.repeat(256));
    });
    await expect(fetchSubscriptionH2(`${origin}/sub`, init, 64)).rejects.toThrow('too large');
  });
});
