import { normalizeUtlsFingerprint } from '../utls-fingerprint';

describe('normalizeUtlsFingerprint', () => {
  it('maps Xray uTLS preset names to the family sing-box knows (the hellofirefox_120 regression)', () => {
    expect(normalizeUtlsFingerprint('hellofirefox_120')).toBe('firefox');
    expect(normalizeUtlsFingerprint('hellochrome_131')).toBe('chrome');
    expect(normalizeUtlsFingerprint('HelloChrome_112_PQ')).toBe('chrome');
    expect(normalizeUtlsFingerprint('helloios_14')).toBe('ios');
    expect(normalizeUtlsFingerprint('helloandroid_11_okhttp')).toBe('android');
    expect(normalizeUtlsFingerprint('helloedge_106')).toBe('edge');
    expect(normalizeUtlsFingerprint('hellosafari_16_0')).toBe('safari');
    expect(normalizeUtlsFingerprint('hello360_11_0')).toBe('360');
    expect(normalizeUtlsFingerprint('helloqq_11_1')).toBe('qq');
  });

  it('maps the randomized variants to randomized', () => {
    expect(normalizeUtlsFingerprint('hellorandomizedalpn')).toBe('randomized');
    expect(normalizeUtlsFingerprint('randomizednoalpn')).toBe('randomized');
  });

  it('keeps values the core already accepts, lowercased', () => {
    for (const v of [
      'chrome',
      'firefox',
      'edge',
      'safari',
      '360',
      'qq',
      'ios',
      'android',
      'random',
    ]) {
      expect(normalizeUtlsFingerprint(v)).toBe(v);
    }
    expect(normalizeUtlsFingerprint('Firefox')).toBe('firefox');
    expect(normalizeUtlsFingerprint(' CHROME ')).toBe('chrome');
    expect(normalizeUtlsFingerprint('chrome_pq')).toBe('chrome_pq');
  });

  it('returns undefined for empty input and passes none through', () => {
    expect(normalizeUtlsFingerprint(undefined)).toBeUndefined();
    expect(normalizeUtlsFingerprint(null)).toBeUndefined();
    expect(normalizeUtlsFingerprint('  ')).toBeUndefined();
    expect(normalizeUtlsFingerprint('none')).toBe('none');
  });

  it('falls back to chrome for unknown values instead of letting the core reject the node', () => {
    expect(normalizeUtlsFingerprint('unsafe')).toBe('chrome');
    expect(normalizeUtlsFingerprint('hellogolang')).toBe('chrome');
    expect(normalizeUtlsFingerprint('something-else')).toBe('chrome');
  });
});
