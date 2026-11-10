import type { UserConfig, SubscriptionConfig } from '../../shared/types';

// A previous parser may have skipped nodes even if the HTTP body is unchanged.
export const SUBSCRIPTION_PARSER_REVISION = 3;

export function subscriptionValidators(subscription: SubscriptionConfig) {
  if (subscription.hasProviders) return undefined;
  const current = subscription.parserRevision === SUBSCRIPTION_PARSER_REVISION;
  return {
    etag: current ? subscription.etag : undefined,
    lastModified: current ? subscription.lastModified : undefined,
  };
}

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
