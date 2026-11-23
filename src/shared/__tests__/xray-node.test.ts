import type { ServerConfig } from '../types';
import { canUseXray, requiresXray, wantsXray } from '../xray-node';

const visionNode: ServerConfig = {
  id: 'vision-udp443',
  name: 'Vision UDP 443',
  protocol: 'vless',
  address: 'proxy.example.com',
  port: 443,
  uuid: '00000000-0000-4000-8000-000000000001',
  network: 'tcp',
  security: 'tls',
  flow: 'xtls-rprx-vision-udp443',
  tlsSettings: { serverName: 'proxy.example.com', fingerprint: 'firefox' },
  createdAt: '2026-11-23T00:00:00.000Z',
  updatedAt: '2026-11-23T00:00:00.000Z',
};

describe('VLESS Vision core selection', () => {
  it('routes the Xray-only UDP 443 flow through Xray even when Reality preference is off', () => {
    expect(canUseXray(visionNode)).toBe(true);
    expect(requiresXray(visionNode)).toBe(true);
    expect(wantsXray(visionNode, false)).toBe(true);
    expect(wantsXray(visionNode)).toBe(true);
  });

  it('keeps ordinary TLS Vision available to sing-box', () => {
    const node = { ...visionNode, flow: 'xtls-rprx-vision' };
    expect(requiresXray(node)).toBe(false);
    expect(wantsXray(node, false)).toBe(false);
  });

  it('does not fall back to sing-box when an Xray-only flow has unsupported bridge options', () => {
    const node = { ...visionNode, detour: 'another-node' };
    expect(canUseXray(node)).toBe(false);
    expect(requiresXray(node)).toBe(true);
    expect(wantsXray(node, false)).toBe(true);
  });
});
