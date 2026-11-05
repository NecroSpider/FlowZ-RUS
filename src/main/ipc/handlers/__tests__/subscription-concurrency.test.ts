import type { UserConfig, SubscriptionConfig } from '../../../../shared/types';
const mockHandlers = new Map<string, (...args: any[]) => Promise<any>>();
jest.mock('../../ipc-handler', () => ({
  registerIpcHandler: (key: string, fn: any) => mockHandlers.set(key, fn),
}));
jest.mock('electron', () => ({ app: { getVersion: () => 'test' }, dialog: {} }));
jest.mock('../../../services/SubscriptionService', () => ({ SubscriptionService: {} }));
import { registerSubscriptionHandlers } from '../subscription-handlers';

const sub = (id: string): SubscriptionConfig => ({
  id,
  name: id,
  url: `https://example.com/${id}`,
  autoUpdate: false,
  createdAt: 'today',
});
function setup() {
  let config = { subscriptions: [sub('a'), sub('b')], servers: [] } as unknown as UserConfig;
  const pending = new Map<string, (result: any) => void>();
  const service = {
    fetchSubscription: jest.fn(
      (_url: string, id: string) => new Promise((resolve) => pending.set(id, resolve))
    ),
  };
  const manager = {
    loadConfig: async () => structuredClone(config),
    saveConfig: async (next: UserConfig) => {
      await Promise.resolve();
      config = structuredClone(next);
    },
  };
  registerSubscriptionHandlers(service as any, manager as any);
  const call = (channel: string, args: unknown) =>
    mockHandlers.get(`subscription:${channel}`)!(null, args);
  return { call, pending, read: () => config };
}
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

it('adding and editing other subscriptions finish while a provider is still pending', async () => {
  const s = setup();
  const refresh = s.call('updateServers', { subscriptionId: 'a' });
  await tick();
  const added = await s.call('add', { subscription: sub('c') });
  await s.call('update', { subscription: { ...sub('b'), name: 'edited' } });
  expect(s.read().subscriptions!).toHaveLength(3);
  s.pending.get('a')!({ notModified: true });
  expect((await refresh).success).toBe(true);
  expect(s.read().subscriptions!.some((x) => x.id === added.id)).toBe(true);
  expect(s.read().subscriptions!.find((x) => x.id === 'b')?.name).toBe('edited');
});

it('does not apply a response from the previous URL after editing that subscription', async () => {
  const s = setup();
  const refresh = s.call('updateServers', { subscriptionId: 'a' });
  await tick();
  await s.call('update', { subscription: { ...sub('a'), url: 'https://example.com/new' } });
  s.pending.get('a')!({ notModified: true, etag: 'old' });
  expect((await refresh).success).toBe(false);
  expect(s.read().subscriptions![0].url).toBe('https://example.com/new');
  expect(s.read().subscriptions![0].etag).toBeUndefined();
});

it('does not resurrect a deleted subscription after a delayed response', async () => {
  const s = setup();
  const refresh = s.call('updateServers', { subscriptionId: 'a' });
  await tick();
  await s.call('delete', { subscriptionId: 'a' });
  s.pending.get('a')!({ notModified: true });
  expect((await refresh).success).toBe(false);
  expect(s.read().subscriptions!.map((x) => x.id)).toEqual(['b']);
});

it('concurrent additions retain both records', async () => {
  const s = setup();
  await Promise.all(['c', 'd'].map((id) => s.call('add', { subscription: sub(id) })));
  expect(s.read().subscriptions!.map((x) => x.name)).toEqual(['a', 'b', 'c', 'd']);
});
