import {
  FLOWZ_WIN_TUN_INTERFACE,
  WIN_TUN_ROTATION_SLOTS,
  isFlowzWinTunName,
  resolveWinTunInterfaceName,
} from '../tun-interface';
import type { UserConfig } from '../types';

const cfg = (interfaceName?: string): UserConfig =>
  ({ tunConfig: interfaceName === undefined ? {} : { interfaceName } }) as unknown as UserConfig;

describe('resolveWinTunInterfaceName', () => {
  it('without a rotation keeps the historical name (config snapshots and the release gate rely on it)', () => {
    expect(resolveWinTunInterfaceName(cfg())).toBe(FLOWZ_WIN_TUN_INTERFACE);
    expect(FLOWZ_WIN_TUN_INTERFACE).toBe('flowz-tun0');
  });

  it('a rotation picks flowz-tun<N>, so every start gets a different adapter (and GUID)', () => {
    expect(resolveWinTunInterfaceName(cfg(), 0)).toBe('flowz-tun0');
    expect(resolveWinTunInterfaceName(cfg(), 7)).toBe('flowz-tun7');
    expect(resolveWinTunInterfaceName(cfg(), 7)).not.toBe(resolveWinTunInterfaceName(cfg(), 8));
  });

  it('wraps around and tolerates odd numbers', () => {
    expect(resolveWinTunInterfaceName(cfg(), WIN_TUN_ROTATION_SLOTS)).toBe('flowz-tun0');
    expect(resolveWinTunInterfaceName(cfg(), WIN_TUN_ROTATION_SLOTS + 3)).toBe('flowz-tun3');
    expect(resolveWinTunInterfaceName(cfg(), -1)).toBe(`flowz-tun${WIN_TUN_ROTATION_SLOTS - 1}`);
    expect(resolveWinTunInterfaceName(cfg(), 2.9)).toBe('flowz-tun2');
    expect(resolveWinTunInterfaceName(cfg(), Number.NaN)).toBe('flowz-tun0');
  });

  it('a name the user set in tunConfig.interfaceName is never rotated', () => {
    expect(resolveWinTunInterfaceName(cfg('my-tun'), 5)).toBe('my-tun');
    expect(resolveWinTunInterfaceName(cfg(' my-tun '), 5)).toBe('my-tun');
  });

  it('an invalid custom name falls back to the (rotated) FlowZ name', () => {
    expect(resolveWinTunInterfaceName(cfg('bad name!'), 5)).toBe('flowz-tun5');
    expect(resolveWinTunInterfaceName(cfg('x'.repeat(33)))).toBe('flowz-tun0');
  });
});

describe('isFlowzWinTunName', () => {
  it('recognises the default and every rotated name', () => {
    for (const n of ['flowz-tun0', 'flowz-tun7', 'flowz-tun99', 'FLOWZ-TUN12']) {
      expect(isFlowzWinTunName(n)).toBe(true);
    }
  });

  it('does not claim other adapters', () => {
    for (const n of ['flowz-tun', 'flowz-tunnel', 'VPN flowz-tun0', 'flowz-tun1000', 'tun0', '']) {
      expect(isFlowzWinTunName(n)).toBe(false);
    }
  });
});
