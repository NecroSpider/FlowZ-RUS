/**
 * macOS 更新脚本**行为**单测：真跑 buildMacUpdateScript 生成的 bash，外部命令（hdiutil/ditto/osascript/open/
 * xattr/sleep）用 PATH 桩替身。钉死：
 *  ① 标准用户（/Applications 无写权、授权失败）→ 旧版 app 被重新打开、旧版原样保留、DMG 保留（旧实现：删 DMG 退出、
 *     app 永不重启 → 用户断网）。
 *  ② 管理员可写 → 原子替换为新版、删 DMG、打开新版。
 *  ③ 无写权但授权成功（osascript 桩执行提权脚本）→ 替换成功。
 *  ④ 挂载失败 → 重启旧版、保留 DMG。
 * 仅 POSIX 且非 root（root 下 chmod 无效）运行。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { buildMacUpdateScript } from '../update-install-script';

const runnable =
  process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() !== 0;
const d = runnable ? describe : describe.skip;

interface Fixture {
  root: string;
  apps: string;
  dest: string;
  dmg: string;
  mnt: string;
  bin: string;
  openLog: string;
}

function makeFixture(): Fixture {
  // hdiutil 桩的挂载点必须形如 /tmp/...（脚本按 "/tmp/[^[:space:]]*" 解析 hdiutil 输出）。
  const root = fs.mkdtempSync('/tmp/flowz-macupd-');
  const apps = path.join(root, 'Applications');
  const dest = path.join(apps, 'FlowZ.app');
  const mnt = path.join(root, 'mnt');
  const bin = path.join(root, 'bin');
  const dmg = path.join(root, 'FlowZ.dmg');
  const openLog = path.join(root, 'open.log');
  fs.mkdirSync(path.join(dest, 'Contents'), { recursive: true });
  fs.writeFileSync(path.join(dest, 'Contents', 'version'), 'old');
  fs.mkdirSync(path.join(mnt, 'FlowZ.app', 'Contents'), { recursive: true });
  fs.writeFileSync(path.join(mnt, 'FlowZ.app', 'Contents', 'version'), 'new');
  fs.writeFileSync(dmg, 'dmg');
  fs.mkdirSync(bin);
  const stub = (name: string, body: string) =>
    fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`, { mode: 0o755 });
  stub('sleep', 'exit 0');
  stub('xattr', 'exit 0');
  stub('ditto', 'cp -R "$1" "$2"');
  stub('open', `echo "$*" >> '${openLog}'`);
  stub(
    'hdiutil',
    `if [ "$1" = attach ]; then [ -f "$FAKE_MOUNT_FAIL" ] && exit 1; echo "/dev/disk9 Apple_HFS ${mnt}"; fi; exit 0`
  );
  // osascript：FAKE_ADMIN=1 → 模拟授权成功（恢复目录写权后执行提权脚本）；否则模拟取消/非管理员。
  stub(
    'osascript',
    [
      'if [ "$FAKE_ADMIN" = 1 ]; then',
      `  chmod u+w '${apps}'`,
      `  f=$(echo "$2" | sed -E "s/.*bash '([^']+)'.*/\\1/")`,
      '  bash "$f"; exit $?',
      'fi',
      'exit 1',
    ].join('\n')
  );
  return { root, apps, dest, dmg, mnt, bin, openLog };
}

function run(fx: Fixture, env: Record<string, string> = {}) {
  const script = buildMacUpdateScript({ dmgPath: fx.dmg, appBundlePath: fx.dest });
  const r = spawnSync('/bin/bash', ['-c', script], {
    env: { PATH: `${fx.bin}:/usr/bin:/bin`, TMPDIR: os.tmpdir(), ...env },
    encoding: 'utf8',
    timeout: 20000,
  });
  return r;
}

const version = (app: string) =>
  fs.readFileSync(path.join(app, 'Contents', 'version'), 'utf8').trim();
const opened = (fx: Fixture) =>
  fs.existsSync(fx.openLog) ? fs.readFileSync(fx.openLog, 'utf8').trim().split('\n') : [];

d('buildMacUpdateScript（真跑）', () => {
  let fx: Fixture;
  beforeEach(() => {
    fx = makeFixture();
  });
  afterEach(() => {
    try {
      fs.chmodSync(fx.apps, 0o755);
    } catch {
      /* ignore */
    }
    fs.rmSync(fx.root, { recursive: true, force: true });
  });

  it('标准用户（无写权 + 授权失败）→ 重启旧版、旧版完好、保留 DMG、/Applications 无残留', () => {
    fs.chmodSync(fx.apps, 0o555);
    const r = run(fx);
    expect(r.status).toBe(0);
    expect(version(fx.dest)).toBe('old');
    expect(opened(fx)).toEqual([fx.dest]);
    expect(fs.existsSync(fx.dmg)).toBe(true);
    expect(fs.readdirSync(fx.apps)).toEqual(['FlowZ.app']);
  });

  it('可写（管理员）→ 原子替换为新版、删 DMG、打开新版、无 .bak 残留', () => {
    const r = run(fx);
    expect(r.status).toBe(0);
    expect(version(fx.dest)).toBe('new');
    expect(opened(fx)).toEqual([fx.dest]);
    expect(fs.existsSync(fx.dmg)).toBe(false);
    expect(fs.readdirSync(fx.apps)).toEqual(['FlowZ.app']);
  });

  it('无写权但授权成功 → 提权脚本完成替换', () => {
    fs.chmodSync(fx.apps, 0o555);
    const r = run(fx, { FAKE_ADMIN: '1' });
    expect(r.status).toBe(0);
    expect(version(fx.dest)).toBe('new');
    expect(opened(fx)).toEqual([fx.dest]);
    expect(fs.existsSync(fx.dmg)).toBe(false);
  });

  it('挂载失败 → 重启旧版、保留 DMG', () => {
    const flag = path.join(fx.root, 'mount-fail');
    fs.writeFileSync(flag, '1');
    const r = run(fx, { FAKE_MOUNT_FAIL: flag });
    expect(r.status).toBe(0);
    expect(version(fx.dest)).toBe('old');
    expect(opened(fx)).toEqual([fx.dest]);
    expect(fs.existsSync(fx.dmg)).toBe(true);
  });
});
