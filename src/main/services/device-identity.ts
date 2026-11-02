/**
 * 订阅设备标识（HWID）：Remnawave 等面板的「设备数限制」要求客户端在拉订阅时带 x-hwid 与设备信息头。
 * Happ / v2RayTun / Hiddify 默认都发；面板开了限制而客户端不发时，订阅只回一条「⛔ 应用未传设备 ID」占位节点
 * （响应头 x-hwid-not-supported: true）。
 *
 * HWID = sha256(固定前缀 + 本机机器 ID) 的前 32 个十六进制字符：同一台机器重装 FlowZ 也不变（不多占设备名额），
 * 又不把原始硬件 UUID / MachineGuid 交给订阅方。机器 ID 取不到 → 随机 UUID 落盘到 userData 沿用。
 * 全部 best-effort：任何一步失败都退到兜底值，绝不阻断订阅更新。
 */

import { execFile } from 'child_process';
import { createHash, randomUUID } from 'crypto';
import { promises as fsp } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { promisify } from 'util';
import { app } from 'electron';
import { system32 } from '../utils/win-system32';

const execFileAsync = promisify(execFile);
const CMD_TIMEOUT_MS = 3000;
const HWID_PREFIX = 'flowz-hwid:';
const FALLBACK_ID_FILE = 'device-id';

export interface DeviceInfo {
  hwid: string;
  /** x-device-os：macOS / Windows / Linux（面板按此显示设备类型）。 */
  os: string;
  osVersion: string;
  model: string;
}

/** `ioreg -rd1 -c IOPlatformExpertDevice` → IOPlatformUUID。 */
export function parseIoregPlatformUuid(stdout: string): string | null {
  const m = /"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{16,})"/.exec(stdout);
  return m ? m[1] : null;
}

/** `reg query <key> /v <name>` → 值（REG_SZ）。 */
export function parseRegValue(stdout: string, name: string): string | null {
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^\s*(\S+)\s+REG_\w+\s+(.+?)\s*$/.exec(line);
    if (m && m[1].toLowerCase() === name.toLowerCase()) return m[2];
  }
  return null;
}

export function deriveHwid(machineId: string): string {
  return createHash('sha256')
    .update(HWID_PREFIX + machineId.trim().toLowerCase())
    .digest('hex')
    .slice(0, 32);
}

/** 请求头值只留可打印 ASCII（net.fetch 拒绝非 Latin-1；型号名偶有中文/商标符号），截 64 字符。 */
export function sanitizeHeaderValue(v: string): string {
  return v
    .replace(/\s+/g, ' ')
    .replace(/[^\x20-\x7E]/g, '')
    .replace(/ {2,}/g, ' ')
    .trim()
    .slice(0, 64);
}

export function deviceHeaders(info: DeviceInfo): Record<string, string> {
  const out: Record<string, string> = { 'x-hwid': info.hwid };
  const add = (key: string, value: string): void => {
    const v = sanitizeHeaderValue(value);
    if (v) out[key] = v;
  };
  add('x-device-os', info.os);
  add('x-ver-os', info.osVersion);
  add('x-device-model', info.model);
  return out;
}

async function run(file: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(file, args, {
      timeout: CMD_TIMEOUT_MS,
      windowsHide: true,
    });
    return String(stdout);
  } catch {
    return '';
  }
}

async function readMachineId(): Promise<string | null> {
  if (process.platform === 'darwin') {
    return parseIoregPlatformUuid(
      await run('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'])
    );
  }
  if (process.platform === 'win32') {
    return parseRegValue(
      await run(system32('reg.exe'), [
        'query',
        'HKLM\\SOFTWARE\\Microsoft\\Cryptography',
        '/v',
        'MachineGuid',
      ]),
      'MachineGuid'
    );
  }
  for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
    try {
      const id = (await fsp.readFile(f, 'utf-8')).trim();
      if (id) return id;
    } catch {
      /* 下一个 */
    }
  }
  return null;
}

/** 机器 ID 取不到时的兜底：userData 里的随机 UUID（首次生成后沿用）。 */
async function fallbackMachineId(): Promise<string> {
  let file: string | null = null;
  try {
    file = path.join(app.getPath('userData'), FALLBACK_ID_FILE);
    const id = (await fsp.readFile(file, 'utf-8')).trim();
    if (id) return id;
  } catch {
    /* 首次 / 不可读 */
  }
  const id = randomUUID();
  if (file) {
    try {
      await fsp.writeFile(file, id, 'utf-8');
    } catch {
      /* 写不了就只在本次会话用 */
    }
  }
  return id;
}

async function readModel(): Promise<string> {
  if (process.platform === 'darwin') {
    return (await run('/usr/sbin/sysctl', ['-n', 'hw.model'])).trim() || 'Mac';
  }
  if (process.platform === 'win32') {
    const out = await run(system32('reg.exe'), [
      'query',
      'HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS',
      '/v',
      'SystemProductName',
    ]);
    return parseRegValue(out, 'SystemProductName') || 'PC';
  }
  try {
    return (await fsp.readFile('/sys/class/dmi/id/product_name', 'utf-8')).trim() || 'PC';
  } catch {
    return 'PC';
  }
}

function osName(): string {
  if (process.platform === 'darwin') return 'macOS';
  if (process.platform === 'win32') return 'Windows';
  return 'Linux';
}

function osVersion(): string {
  try {
    // Electron：macOS 给产品版本（26.0.1），Windows 给 10.0.<build>；os.release() 在 macOS 上是 Darwin 内核号。
    const v = (
      process as NodeJS.Process & { getSystemVersion?: () => string }
    ).getSystemVersion?.();
    if (v) return v;
  } catch {
    /* 非 Electron 上下文 */
  }
  return os.release();
}

let cached: Promise<DeviceInfo> | null = null;

/** 本机设备信息（进程内缓存：机器 ID 与型号不会在运行期变化）。 */
export function getDeviceInfo(): Promise<DeviceInfo> {
  cached ??= (async () => {
    const [machineId, model] = await Promise.all([readMachineId(), readModel()]);
    return {
      hwid: deriveHwid(machineId || (await fallbackMachineId())),
      os: osName(),
      osVersion: osVersion(),
      model,
    };
  })();
  return cached;
}
