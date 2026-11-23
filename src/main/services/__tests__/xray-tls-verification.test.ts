import { ProtocolParser } from '../ProtocolParser';
import { makeXrayOutbound } from '../xray-bridge';
import { parseXrayOutbounds } from '../xray-import';
import { canUseXray, requiresXray, wantsXray } from '../../../shared/xray-node';

const parser = new ProtocolParser();
const pin = 'ab'.repeat(32);
const otherPin = 'cd'.repeat(32);
const baseUrl =
  'vless://00000000-0000-4000-8000-000000000001@proxy.example.com:443?security=tls&type=tcp';

describe('VLESS Xray TLS verification', () => {
  it('preserves certificate pins and verification names through import, export and the sidecar', () => {
    const pcs = pin.toUpperCase().match(/../g)!.join(':') + ',' + otherPin;
    const names = 'cert.example.com, second.example.com';
    const node = parser.parseUrl(
      `${baseUrl}&pcs=${encodeURIComponent(pcs)}&vcn=${encodeURIComponent(names)}`
    );
    expect(node.tlsSettings).toMatchObject({
      pinnedPeerCertSha256: pin + ',' + otherPin,
      verifyPeerCertByName: 'cert.example.com,second.example.com',
    });
    expect(node.tlsSettings?.allowInsecure).not.toBe(true);
    expect(requiresXray(node)).toBe(true);
    expect(wantsXray(node, false)).toBe(true);
    expect(canUseXray(node)).toBe(true);
    const exported = parser.parseUrl(parser.generateUrl(node));
    expect(exported.tlsSettings).toEqual(node.tlsSettings);
    const outbound = makeXrayOutbound(node, 'test');
    expect(outbound.streamSettings.tlsSettings).toEqual({
      serverName: 'proxy.example.com',
      fingerprint: undefined,
      alpn: undefined,
      pinnedPeerCertSha256: pin + ',' + otherPin,
      verifyPeerCertByName: 'cert.example.com,second.example.com',
    });
  });

  it('uses Xray for name verification without a certificate pin or VLESS encryption', () => {
    const node = parser.parseUrl(`${baseUrl}&vcn=cert.example.com`);
    expect(node.encryption).toBe('none');
    expect(wantsXray(node, false)).toBe(true);
    expect(makeXrayOutbound(node, 'test').streamSettings.tlsSettings).toMatchObject({
      verifyPeerCertByName: 'cert.example.com',
    });
  });

  it.each(['', 'abc', 'z'.repeat(64), pin + ',', pin + '\nextra'])(
    'rejects malformed pins instead of dropping verification: %j',
    (pcs) => {
      expect(() => parser.parseUrl(`${baseUrl}&pcs=${encodeURIComponent(pcs)}`)).toThrow(
        'Invalid Xray certificate pin'
      );
    }
  );

  it.each(['', 'cert.example.com,,other.example.com', 'cert.example.com\nother.example.com'])(
    'rejects malformed verification names: %j',
    (vcn) => {
      expect(() => parser.parseUrl(`${baseUrl}&vcn=${encodeURIComponent(vcn)}`)).toThrow(
        'Invalid Xray certificate verification names'
      );
    }
  );

  it('never falls back to sing-box when a pinned profile cannot use the bridge', () => {
    const node = { ...parser.parseUrl(`${baseUrl}&pcs=${pin}`), detour: 'other-node' };
    expect(requiresXray(node)).toBe(true);
    expect(canUseXray(node)).toBe(false);
    expect(wantsXray(node, false)).toBe(true);
  });

  it('does not silently ignore a pin on a different protocol or without TLS', () => {
    expect(() => parser.parseUrl(`trojan://password@proxy.example.com:443?pcs=${pin}`)).toThrow(
      'only supported for VLESS TLS'
    );
    expect(() => parser.parseUrl(`vless://u@proxy.example.com:443?pcs=${pin}`)).toThrow(
      'requires VLESS TLS'
    );
    const node = parser.parseUrl(`${baseUrl}&pcs=${pin}`);
    expect(() => parser.generateUrl({ ...node, protocol: 'trojan' })).toThrow(
      'only supported for VLESS TLS'
    );
  });

  it('keeps malformed saved settings unavailable rather than bypassing their pin', () => {
    const node = parser.parseUrl(`${baseUrl}&pcs=${pin}`);
    node.tlsSettings!.pinnedPeerCertSha256 = 'invalid';
    expect(requiresXray(node)).toBe(true);
    expect(canUseXray(node)).toBe(false);
    expect(() => parser.generateUrl(node)).toThrow('Invalid Xray certificate pin');
  });

  it('retains the same verification when importing native Xray JSON', () => {
    const result = parseXrayOutbounds(
      [
        {
          protocol: 'vless',
          settings: { address: 'proxy.example.com', port: 443, id: 'u', encryption: 'none' },
          streamSettings: {
            network: 'tcp',
            security: 'tls',
            tlsSettings: {
              pinnedPeerCertSha256: pin.toUpperCase(),
              verifyPeerCertByName: 'cert.example.com',
            },
          },
        },
      ],
      '2026-11-23T00:00:00.000Z'
    );
    expect(result.failed).toBe(0);
    expect(result.servers[0].tlsSettings).toMatchObject({
      pinnedPeerCertSha256: pin,
      verifyPeerCertByName: 'cert.example.com',
    });
    expect(requiresXray(result.servers[0])).toBe(true);
  });
});
