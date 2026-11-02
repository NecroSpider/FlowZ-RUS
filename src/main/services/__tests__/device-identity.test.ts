jest.mock('electron', () => ({ app: { getPath: () => '/nonexistent' } }));

import {
  parseIoregPlatformUuid,
  parseRegValue,
  deriveHwid,
  sanitizeHeaderValue,
  deviceHeaders,
} from '../device-identity';

describe('device-identity', () => {
  it('ioreg → IOPlatformUUID', () => {
    const out = `+-o J416sAP  <class IOPlatformExpertDevice, id 0x100000213>
    {
      "IOPlatformSerialNumber" = "XXXXXXXXXX"
      "IOPlatformUUID" = "3F2504E0-4F89-11D3-9A0C-0305E82C3301"
      "model" = <"Mac15,6">
    }`;
    expect(parseIoregPlatformUuid(out)).toBe('3F2504E0-4F89-11D3-9A0C-0305E82C3301');
    expect(parseIoregPlatformUuid('')).toBeNull();
  });

  it('reg query → 值（大小写不敏感，CRLF）', () => {
    const out =
      '\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    6c0b5e2a-1f3d-4c8e-9a7b-2d4e6f8a0b1c\r\n\r\n';
    expect(parseRegValue(out, 'machineguid')).toBe('6c0b5e2a-1f3d-4c8e-9a7b-2d4e6f8a0b1c');
    expect(parseRegValue(out, 'Other')).toBeNull();
    const bios = '    SystemProductName    REG_SZ    ThinkPad X1 Carbon Gen 11\r\n';
    expect(parseRegValue(bios, 'SystemProductName')).toBe('ThinkPad X1 Carbon Gen 11');
  });

  it('HWID：32 位十六进制，同机稳定（不分大小写 / 空白），不含原始 ID', () => {
    const a = deriveHwid('3F2504E0-4F89-11D3-9A0C-0305E82C3301');
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(deriveHwid(' 3f2504e0-4f89-11d3-9a0c-0305e82c3301\n')).toBe(a);
    expect(deriveHwid('other-machine')).not.toBe(a);
    expect(a).not.toContain('3f2504e0');
  });

  it('头值只留可打印 ASCII、截 64', () => {
    expect(sanitizeHeaderValue('  Лаптоп™ Pro\t15  ')).toBe('Pro 15');
    expect(sanitizeHeaderValue('x'.repeat(100))).toHaveLength(64);
  });

  it('deviceHeaders：空值的头不发', () => {
    expect(
      deviceHeaders({ hwid: 'h', os: 'Windows', osVersion: '10.0.26200', model: '™' })
    ).toEqual({ 'x-hwid': 'h', 'x-device-os': 'Windows', 'x-ver-os': '10.0.26200' });
  });
});
