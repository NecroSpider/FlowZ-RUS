/**
 * LinuxServiceHelper 纯逻辑单测（无 systemd / 无 socket）：
 *  - 平台门控：非 linux 安全降级（supported=false / ready=false），绝不触发 pkexec/socket。
 *  - 安装/卸载脚本生成（runtime 最脆点）：systemd unit、授权 uid 写入、enable --now、卸载对称清理。
 *  - 第一性不变量：不用 setcap、无 install-core、无 token、helper 本体 root 跑（unit 无 User=）。
 *  - linux 宿主未装态：supported=true 但 installed/ready=false（不连 socket）。
 * 真机行为（pkexec、systemctl、SO_PEERCRED setuid+ambient 拉核）属 Linux 真机必验清单，不在单测范围。
 */
import {
  LinuxServiceHelper,
  LINUX_POLKIT_RULE_FILES,
  pkexecVerifiedArgs,
  writePrivateScript,
} from '../LinuxServiceHelper';

// 「非 Linux 安全降级」只在非 Linux 宿主可测：helper 直接读 process.platform（无注入点）。
const describeNonLinux = process.platform === 'linux' ? describe.skip : describe;
const describeLinux = process.platform === 'linux' ? describe : describe.skip;

describe('LinuxServiceHelper', () => {
  describeNonLinux('非 Linux 平台安全降级', () => {
    const helper = new LinuxServiceHelper();

    it('getStatus 返回 supported=false 的空状态', async () => {
      const s = await helper.getStatus();
      expect(s.supported).toBe(false);
      expect(s.installed).toBe(false);
      expect(s.ready).toBe(false);
      expect(s.needsRepair).toBe(false);
      expect(s.loaded).toBeNull();
    });

    it('isReady 返回 false（不尝试连接 socket）', async () => {
      await expect(helper.isReady()).resolves.toBe(false);
    });

    it('install/uninstall 在非 Linux 报「仅 Linux 支持」', async () => {
      const i = await helper.install();
      expect(i.success).toBe(false);
      expect(i.error).toContain('Linux');
      const u = await helper.uninstall();
      expect(u.success).toBe(false);
      expect(u.error).toContain('Linux');
    });
  });

  describe('systemd unit / 安装脚本生成', () => {
    const helper = new LinuxServiceHelper() as unknown as {
      buildUnit(): string;
      buildInstallScript(src: string, uid: number, bundledCore: string): string;
      buildUninstallScript(): string;
    };

    it('unit：helper root 跑（无 User=）、ExecStart 带 socket/authfile/coredir(路径锁)、cap 不在 unit 层', () => {
      const unit = helper.buildUnit();
      expect(unit).toContain('ExecStart=/usr/local/lib/flowz/flowz-helper');
      expect(unit).toContain('--coredir=/usr/local/lib/flowz/core'); // 路径锁：helper 只跑此目录内的核
      expect(unit).toContain('RuntimeDirectory=flowz');
      expect(unit).toContain('WantedBy=multi-user.target');
      expect(unit).not.toContain('User='); // root 跑（setuid 拉 child + 穿越 userData）
      expect(unit).not.toContain('AmbientCapabilities'); // child cap 由代码赋，不在 unit
    });

    it('install：拷 helper + 播种 root 受管核(仅缺时) + 授权 uid 合并追加 + enable --now', () => {
      const s = helper.buildInstallScript(
        '/pkg/resources/linux/flowz-helper-linux',
        1000,
        '/pkg/resources/linux/sing-box'
      );
      expect(s).toContain(
        "install -D -o root -g root -m 0755 '/pkg/resources/linux/flowz-helper-linux' '/usr/local/lib/flowz/flowz-helper'"
      );
      // 播种 root 受管核：仅当尚无核（重装/修复不覆盖已 install-core 更新的核）
      expect(s).toContain("if [ ! -x '/usr/local/lib/flowz/core/sing-box' ]");
      expect(s).toContain("'/pkg/resources/linux/sing-box' '/usr/local/lib/flowz/core/sing-box'");
      expect(s).toContain('libcronet.so'); // 配套随核播种
      // 授权 uid **合并追加**（不覆写 → 多用户/repair 不互抹）
      expect(s).toContain("grep -qxF '1000'");
      expect(s).toContain(">> '/var/lib/flowz/authorized-uids'");
      expect(s).toContain('systemctl enable flowz-helper.service');
      expect(s).toContain('systemctl restart flowz-helper.service'); // replace a running older helper now
      // 第一性不变量
      expect(s).not.toContain('setcap'); // 能力挂进程 ambient，不 setcap 二进制
      expect(s).not.toContain('/opt/FlowZ'); // 避开 electron-builder deb 应用目录
      expect(s.toLowerCase()).not.toContain('token'); // SO_PEERCRED 鉴权，无 token
    });

    it('uninstall：disable --now + 删受管安装根/状态/运行目录（对称、不碰 /opt/FlowZ）', () => {
      const s = helper.buildUninstallScript();
      expect(s).toContain('systemctl disable --now flowz-helper.service');
      expect(s).toContain('/etc/systemd/system/flowz-helper.service');
      expect(s).toContain("rm -rf '/usr/local/lib/flowz'"); // 整删受管安装根(helper+root 核)
      expect(s).toContain('/var/lib/flowz');
      expect(s).toContain('/run/flowz');
      expect(s).toContain('systemctl daemon-reload');
      expect(s).not.toContain('/opt/FlowZ');
      // item 6: the resolve1 polkit rule (installed by the TUN setup) is removed too
      for (const f of LINUX_POLKIT_RULE_FILES) expect(s).toContain(f);
    });
  });

  describeLinux('Linux 宿主未装态', () => {
    const helper = new LinuxServiceHelper();

    it('未装时 getStatus：supported=true、installed/ready=false、mac 专属字段默认', async () => {
      const s = await helper.getStatus();
      expect(s.supported).toBe(true);
      expect(s.installed).toBe(false);
      expect(s.ready).toBe(false);
      expect(s.backgroundDisabled).toBe(false);
      expect(s.pathMismatch).toBe(false);
      expect(s.installedSingboxPath).toBeNull();
    });

    it('isReady 返回 false（未装不连 socket）', async () => {
      await expect(helper.isReady()).resolves.toBe(false);
    });

    it('route*/restoreDefaultRoute 为 no-op（Linux 不需要）', async () => {
      await expect(helper.routeAdd('flowz-tun', ['10.0.0.0/8'])).resolves.toEqual({
        ok: false,
        error: 'unsupported',
      });
      await expect(helper.restoreDefaultRoute('1.2.3.4')).resolves.toEqual({
        ok: false,
        error: 'unsupported',
      });
    });
  });

  describe('installCore 协议（换核免密 socket）', () => {
    it('发出 [install-core, srcDir, sha256(srcDir/sing-box)] 三元组', async () => {
      const os = require('os');
      const fsSync = require('fs');
      const pathMod = require('path');
      const dir = fsSync.mkdtempSync(pathMod.join(os.tmpdir(), 'flowz-installcore-'));
      fsSync.writeFileSync(pathMod.join(dir, 'sing-box'), 'CORE-BYTES');
      const helper = new LinuxServiceHelper();
      const sent: string[][] = [];
      (
        helper as unknown as { sendCommand: (r: string[], t: number) => Promise<string> }
      ).sendCommand = async (rest: string[]) => {
        sent.push(rest);
        return 'OK installed';
      };
      const r = await helper.installCore(dir);
      expect(r).toEqual({ ok: true });
      expect(sent).toHaveLength(1);
      expect(sent[0][0]).toBe('install-core');
      expect(sent[0][1]).toBe(dir);
      expect(sent[0][2]).toMatch(/^[0-9a-f]{64}$/); // sha256 hex
      fsSync.rmSync(dir, { recursive: true, force: true });
    });
  });

  describe('core trust (helper proto v2)', () => {
    const os = require('os');
    const fsSync = require('fs');
    const pathMod = require('path');

    it('untrusted core: no prompt unless the caller allows elevation', async () => {
      const dir = fsSync.mkdtempSync(pathMod.join(os.tmpdir(), 'flowz-installcore-'));
      fsSync.writeFileSync(pathMod.join(dir, 'sing-box'), 'USER-PICKED-CORE');
      const helper = new LinuxServiceHelper();
      (
        helper as unknown as { sendCommand: (r: string[], t: number) => Promise<string> }
      ).sendCommand = async () => 'ERR untrusted-hash sing-box abc';
      let elevated = 0;
      (helper as unknown as { installCoreElevated: () => Promise<unknown> }).installCoreElevated =
        async () => {
          elevated++;
          return { ok: true };
        };
      const auto = await helper.installCore(dir);
      expect(auto.ok).toBe(false);
      expect(elevated).toBe(0); // automatic / startup paths never prompt
      const manual = await helper.installCore(dir, { allowElevation: true });
      expect(manual).toEqual({ ok: true });
      expect(elevated).toBe(1);
      fsSync.rmSync(dir, { recursive: true, force: true });
    });

    it('elevated core script verifies each copy against the app hash and allowlists it', () => {
      const helper = new LinuxServiceHelper() as unknown as {
        buildElevatedCoreInstallScript(i: { name: string; src: string; sha256: string }[]): string;
      };
      const h = 'a'.repeat(64);
      const s = helper.buildElevatedCoreInstallScript([
        { name: 'sing-box', src: "/tmp/it's here/sing-box", sha256: h },
      ]);
      expect(s).toContain("COREDIR='/usr/local/lib/flowz/core'");
      expect(s).toContain('AL="$COREDIR/trusted-hashes"');
      expect(s).toContain('if [ "$GOT" != "$3" ]');
      expect(s).toContain(`install_one sing-box '/tmp/it'\\''s here/sing-box' ${h}`);
      expect(() =>
        helper.buildElevatedCoreInstallScript([{ name: '../evil', src: '/x', sha256: h }])
      ).toThrow();
    });

    it('pkexec runs a hash-verified root-only copy of a privately written script', () => {
      const w = writePrivateScript('t.sh', 'echo hi\n');
      expect((fsSync.statSync(w.dir).mode & 0o777).toString(8)).toBe('700');
      expect((fsSync.statSync(w.scriptPath).mode & 0o777).toString(8)).toBe('600');
      expect(() => fsSync.writeFileSync(w.scriptPath, 'x', { flag: 'wx' })).toThrow();
      const args = pkexecVerifiedArgs(w.scriptPath, w.sha256);
      expect(args.slice(0, 2)).toEqual(['/bin/sh', '-c']);
      expect(args.slice(3)).toEqual(['flowz-elevated', w.scriptPath, w.sha256, '/bin/sh']);
      expect(args[2]).not.toContain(w.scriptPath); // passed positionally, never interpolated
      fsSync.rmSync(w.dir, { recursive: true, force: true });
    });

    const hasSha256sum = (() => {
      try {
        require('child_process').execFileSync('sha256sum', ['--version'], { stdio: 'ignore' });
        return true;
      } catch {
        return false;
      }
    })();
    (hasSha256sum ? it : it.skip)(
      'the verified wrapper runs the script and refuses a modified one',
      () => {
        const cp = require('child_process');
        const out = pathMod.join(os.tmpdir(), `flowz-wrap-${process.pid}`);
        const w = writePrivateScript('t.sh', `echo ok > '${out}'\n`);
        const args = pkexecVerifiedArgs(w.scriptPath, w.sha256);
        cp.execFileSync(args[0], args.slice(1));
        expect(fsSync.readFileSync(out, 'utf8').trim()).toBe('ok');
        fsSync.chmodSync(w.scriptPath, 0o600);
        fsSync.writeFileSync(w.scriptPath, `echo pwned > '${out}'\n`);
        const r = cp.spawnSync(args[0], args.slice(1));
        expect(r.status).toBe(90);
        expect(fsSync.readFileSync(out, 'utf8').trim()).toBe('ok');
        fsSync.rmSync(w.dir, { recursive: true, force: true });
        fsSync.rmSync(out, { force: true });
      }
    );
  });
});
