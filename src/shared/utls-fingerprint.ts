/**
 * uTLS fingerprint values that sing-box accepts (core 1.14, verified with `sing-box check`).
 * The match is case-sensitive: "Firefox" and "CHROME" are rejected by the core.
 */
const SINGBOX_UTLS_FINGERPRINTS: ReadonlySet<string> = new Set([
  'chrome',
  'firefox',
  'edge',
  'safari',
  '360',
  'qq',
  'ios',
  'android',
  'random',
  'randomized',
  'chrome_psk',
  'chrome_psk_shuffle',
  'chrome_padding_psk_shuffle',
  'chrome_pq',
  'chrome_pq_psk',
]);

/** Browser families that Xray/uTLS presets name as `hello<family>_<version>` (e.g. hellofirefox_120). */
const HELLO_FAMILIES = [
  'chrome',
  'firefox',
  'safari',
  'ios',
  'android',
  'edge',
  '360',
  'qq',
] as const;

/**
 * Maps a fingerprint from a subscription or share link to a value sing-box understands.
 *
 * Panels built on Xray emit uTLS preset names such as `hellofirefox_120` or `hellochrome_131`; sing-box
 * rejects them with "unknown uTLS fingerprint" and a node that carries one cannot start at all. We map
 * `hello<family>_<version>` to the plain family (`firefox`, `chrome`, ...), `hellorandomized*` to `randomized`,
 * lowercase the value, and fall back to `chrome` for anything unknown so one odd value does not take down
 * every node of a subscription.
 *
 * Returns `undefined` for an empty value so callers keep their own default, and passes `none` through
 * (callers use it to mean "no uTLS").
 */
export function normalizeUtlsFingerprint(raw: string | undefined | null): string | undefined {
  const fp = (raw ?? '').trim().toLowerCase();
  if (!fp) return undefined;
  if (fp === 'none') return 'none';
  if (SINGBOX_UTLS_FINGERPRINTS.has(fp)) return fp;
  if (fp.startsWith('hellorandomized') || fp === 'randomizedalpn' || fp === 'randomizednoalpn') {
    return 'randomized';
  }
  for (const family of HELLO_FAMILIES) {
    if (fp === `hello${family}` || fp.startsWith(`hello${family}_`)) return family;
  }
  return 'chrome';
}
