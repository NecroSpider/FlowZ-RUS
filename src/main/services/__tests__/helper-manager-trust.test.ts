/**
 * macOS HelperManager — helper proto v10 client side (core trust, elevated core install, verified root scripts).
 * Pure logic + local script execution as the current user; nothing is elevated or installed.
 */
const os = require('os');
const path = require('path');
const fsSync = require('fs');
const cp = require('child_process');

const TMP = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-hm-test-'));

jest.mock('electron', () => ({
  app: { getPath: () => TMP, getVersion: () => '9.9.9', isPackaged: false, getAppPath: () => TMP },
}));

import {
  HelperManager,
  buildMacElevatedCoreInstallScript,
  macVerifiedRunCommand,
} from '../HelperManager';
import { resourceManager } from '../ResourceManager';

afterAll(() => fsSync.rmSync(TMP, { recursive: true, force: true }));

const H = 'c'.repeat(64);

describe('buildMacElevatedCoreInstallScript', () => {
  it('copies once, checks the app hash, signs, allowlists the final hash, then moves into place', () => {
    const s = buildMacElevatedCoreInstallScript(
      '/Library/Application Support/FlowZ/core',
      [{ src: "/Users/o'neil/dl/sing-box", name: 'sing-box', sha256: H, codesign: true }],
      { pkillCore: true }
    );
    expect(s).toContain("COREDIR='/Library/Application Support/FlowZ/core'");
    expect(s).toContain('AL="$COREDIR/trusted-hashes"');
    expect(s).toContain('/bin/cp -X "$2" "$TMP"');
    expect(s).toContain('if [ "$GOT" != "$3" ]');
    expect(s.indexOf('codesign')).toBeLessThan(s.indexOf('FINAL=$('));
    expect(s.indexOf('FINAL=$(')).toBeLessThan(s.indexOf('mv -f "$TMP"'));
    expect(s).toContain(`install_one sing-box '/Users/o'\\''neil/dl/sing-box' ${H} 1`);
    expect(s).toContain('pkill -x sing-box');
    expect(cp.spawnSync('/bin/bash', ['-n'], { input: s }).status).toBe(0);
  });

  it('refuses unexpected names and malformed hashes', () => {
    expect(() =>
      buildMacElevatedCoreInstallScript('/c', [{ src: '/x', name: '../../etc/x', sha256: H }])
    ).toThrow();
    expect(() =>
      buildMacElevatedCoreInstallScript('/c', [{ src: '/x', name: 'sing-box', sha256: 'zz' }])
    ).toThrow();
  });
});

const describeDarwin = process.platform === 'darwin' ? describe : describe.skip;
describeDarwin('macVerifiedRunCommand (run as the current user, no elevation)', () => {
  it('runs a verified copy and refuses a script modified after hashing', () => {
    const crypto = require('crypto');
    const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-vr-'));
    const out = path.join(dir, 'out');
    const script = `echo ok > '${out}'\n`;
    const sp = path.join(dir, 's.sh');
    fsSync.writeFileSync(sp, script);
    const sha = crypto.createHash('sha256').update(script).digest('hex');
    expect(cp.spawnSync('/bin/sh', ['-c', macVerifiedRunCommand(sp, sha)]).status).toBe(0);
    expect(fsSync.readFileSync(out, 'utf8').trim()).toBe('ok');
    fsSync.writeFileSync(sp, `echo pwned > '${out}'\n`);
    expect(cp.spawnSync('/bin/sh', ['-c', macVerifiedRunCommand(sp, sha)]).status).toBe(90);
    expect(fsSync.readFileSync(out, 'utf8').trim()).toBe('ok');
    fsSync.rmSync(dir, { recursive: true, force: true });
  });
});

describe('HelperManager v10 client', () => {
  type Priv = {
    sendCommand: (r: string[], t: number) => Promise<string>;
    installCoreElevated: (d: string) => Promise<{ ok: boolean; error?: string }>;
    buildInstallScript(a: string, b: string, c: string, d: string, e: string): string;
    installCore: HelperManager['installCore'];
    startCore: HelperManager['startCore'];
  };

  it('install-core: an untrusted core never prompts unless the caller allows elevation', async () => {
    const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-ic-'));
    fsSync.writeFileSync(path.join(dir, 'sing-box'), 'USER CORE');
    const hm = new HelperManager() as unknown as Priv;
    hm.sendCommand = async () => 'ERR untrusted-hash sing-box 00';
    let elevated = 0;
    hm.installCoreElevated = async () => {
      elevated++;
      return { ok: true };
    };
    expect((await hm.installCore(dir)).ok).toBe(false);
    expect(elevated).toBe(0);
    expect(await hm.installCore(dir, { allowElevation: true })).toEqual({ ok: true });
    expect(elevated).toBe(1);
    fsSync.rmSync(dir, { recursive: true, force: true });
  });

  it('start: ERR core-untrusted → silent re-seed from the bundle → retry', async () => {
    const bundleDir = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-b-'));
    fsSync.writeFileSync(path.join(bundleDir, 'sing-box'), 'BUNDLED');
    jest
      .spyOn(resourceManager, 'getBundledSingBoxPath')
      .mockReturnValue(path.join(bundleDir, 'sing-box'));
    const sent: string[][] = [];
    const hm = new HelperManager() as unknown as Priv;
    let starts = 0;
    hm.sendCommand = async (rest: string[]) => {
      sent.push(rest);
      if (rest[0] === 'start') return ++starts === 1 ? 'ERR core-untrusted 1234' : 'OK started 5';
      return 'OK';
    };
    await expect(hm.startCore('/u/cfg.json', '/u/log', false)).resolves.toEqual({
      ok: true,
      pid: 5,
    });
    const ic = sent.find((r) => r[0] === 'install-core');
    expect(ic?.[1]).toBe(bundleDir);
    fsSync.rmSync(bundleDir, { recursive: true, force: true });
  });

  it('install script: plist records --bundledcore; no unverified re-sign of the protected core', () => {
    const hm = new HelperManager() as unknown as Priv;
    const s = hm.buildInstallScript(
      '/Applications/FlowZ.app/Contents/Resources/mac/com.flowz.helper',
      '/Applications/FlowZ.app/Contents/Resources/mac/sing-box',
      '/Users/u/Library/Application Support/flowz',
      'deadbeef',
      '/Library/Application Support/FlowZ/core'
    );
    expect(s).toContain(
      '<string>--bundledcore</string><string>/Applications/FlowZ.app/Contents/Resources/mac/sing-box</string>'
    );
    expect(s).not.toContain('codesign');
    expect(s).toContain('if [ ! -e "$COREDIR/sing-box" ]');
  });
});
