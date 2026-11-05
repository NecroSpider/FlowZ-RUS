import type { UserConfig, SubscriptionConfig } from '../../shared/types';

/** Only short read/modify/write sections are serialized; provider requests stay outside this queue. */
export function createSubscriptionConfigEditor(load: () => Promise<UserConfig>) {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(edit: (config: UserConfig) => Promise<T>): Promise<T> => {
    const result = tail.then(async () => edit(await load()));
    tail = result.catch(() => {});
    return result;
  };
}

export function subscriptionRequestKey(config: UserConfig, sub: SubscriptionConfig): string {
  return JSON.stringify([
    sub.url,
    sub.userAgent ?? config.subscriptionUserAgent,
    config.subscriptionProxyPolicy,
    sub.updateViaProxy,
    sub.sendHwid,
  ]);
}

const editors = new WeakMap<object, ReturnType<typeof createSubscriptionConfigEditor>>();
export function getSubscriptionConfigEditor(manager: { loadConfig(): Promise<UserConfig> }) {
  let editor = editors.get(manager);
  if (!editor) {
    editor = createSubscriptionConfigEditor(() => manager.loadConfig());
    editors.set(manager, editor);
  }
  return editor;
}
