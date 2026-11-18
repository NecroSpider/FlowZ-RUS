import { execFile } from 'child_process';
import { promisify } from 'util';
import { applyWorkVpnToSingBoxConfig } from '../../../shared/work-vpn';
import { detectHostWorkVpn } from '../work-vpn-detector';

jest.mock('child_process', () => {
  const { promisify } = jest.requireActual<typeof import('util')>('util');
  const execFile = jest.fn();
  Object.defineProperty(execFile, promisify.custom, { value: jest.fn() });
  return { execFile };
});

const execFileMock = jest.mocked(promisify(execFile));
const originalPlatform = Object.getOwnPropertyDescriptor(process, 'platform')!;
const vpnName = 'Рабочая сеть';
const routes = {
  adapters: [{ n: vpnName, d: 'OpenVPN Data Channel Offload', status: 'Up' }],
  addrs: [{ n: vpnName, a: '10.8.0.2' }],
  routes: [{ n: vpnName, p: '10.50.0.0/24', g: '10.8.0.1' }],
};
const dns = { ...routes, dns: [{ n: vpnName, s: ['10.50.0.53'] }] };
const frame = (stage: string, data: object) => `WORKVPN_JSON:${stage}:${JSON.stringify(data)}\n`;

beforeEach(() => {
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
  execFileMock.mockReset();
});

afterEach(() => {
  Object.defineProperty(process, 'platform', originalPlatform);
});

function mockSnapshot(stdout: string, timeout = false) {
  if (timeout) {
    execFileMock.mockRejectedValueOnce(
      Object.assign(new Error('Timed out'), { killed: true, stdout })
    );
    return;
  }
  execFileMock.mockResolvedValueOnce({ stdout, stderr: '' });
}

const context = { ownTunAddrs: ['172.19.0.1'], ownMeshCidrs: [], ownTunExcludes: [] };

it('uses recovered VPN DNS and routes when PowerShell times out writing the final frame', async () => {
  mockSnapshot(frame('routes', routes) + frame('dns', dns) + 'WORKVPN_JSON:complete:{', true);
  const onWindowsProbe = jest.fn();
  const snapshot = await detectHostWorkVpn({ ...context, onWindowsProbe });
  expect(onWindowsProbe).toHaveBeenCalledWith(
    expect.objectContaining({ stage: 'dns', failure: 'timeout' })
  );

  const config = {
    inbounds: [{ type: 'tun', strict_route: true }],
    outbounds: [],
    dns: { servers: [], rules: [] },
    route: { rules: [] },
  };
  applyWorkVpnToSingBoxConfig(config, {
    snapshot,
    serverIps: [],
    serverHosts: [],
    userDomains: [],
    autoDetectDomains: false,
    tunMode: true,
    realResolverTag: 'dns-local',
    ownLanCidrs: [],
    fakeipRanges: [],
    platform: 'win32',
  });
  expect(config.inbounds[0]).toMatchObject({
    strict_route: false,
    route_exclude_address: ['10.50.0.0/24'],
  });
  expect(config.dns.servers).toContainEqual(
    expect.objectContaining({ server: '10.50.0.53', bind_interface: vpnName })
  );
});

it('prefers a complete snapshot and keeps the VPN DNS policy domains', async () => {
  mockSnapshot(
    frame('routes', routes) +
      frame('dns', dns) +
      frame('complete', { ...dns, nrpt: [{ ns: ['.corp.example'], s: ['10.50.0.53'] }] })
  );
  const onWindowsProbe = jest.fn();
  await expect(detectHostWorkVpn({ ...context, onWindowsProbe })).resolves.toMatchObject({
    interfaces: [{ name: vpnName, domains: ['corp.example'] }],
  });
  expect(onWindowsProbe).toHaveBeenCalledWith(expect.objectContaining({ stage: 'complete' }));
});

it('reports a timeout with no usable snapshot separately from an empty VPN route table', async () => {
  mockSnapshot('', true);
  const onWindowsProbe = jest.fn();
  await expect(detectHostWorkVpn({ ...context, onWindowsProbe })).resolves.toBeNull();
  expect(onWindowsProbe).toHaveBeenCalledWith(
    expect.objectContaining({ stage: 'none', failure: 'timeout' })
  );
});
