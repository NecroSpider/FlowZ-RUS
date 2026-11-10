/**
 * WindowsServiceHelper 纯逻辑单测（无 Windows 机/无命名管道）：
 *  - 平台门控：非 win32 安全降级（supported=false / ready=false），绝不触发 SCM/管道。
 *  - 提权脚本生成（runtime 最脆点）：sc create/start、binPath 锁定 exe+flags、token ACL、卸载脚本。
 *  - PowerShell 单引号转义。
 * 真机行为（UAC、sc 引号语义、管道连通）属 Windows 真机必验清单，不在单测范围。
 */
import {
  WindowsServiceHelper,
  authServerProof,
  authClientProof,
  parseAuthChallenge,
  buildAuthRequest,
} from '../WindowsServiceHelper';
import { system32 } from '../../utils/win-system32';
import { resourceManager } from '../ResourceManager';

// 「非 Windows 安全降级」只在非 Windows 宿主可测：helper 直接读 process.platform（无注入点），
// 在 Windows CI runner（win32）上该降级路径不可达 → 跳过；其逻辑由 macOS/Linux runner 覆盖。
const describeNonWin = process.platform === 'win32' ? describe.skip : describe;

describe('WindowsServiceHelper', () => {
  describeNonWin('非 Windows 平台安全降级', () => {
    // 测试宿主非 Windows（process.platform !== 'win32'）→ 所有方法降级，不连 SCM/管道。
    const helper = new WindowsServiceHelper();

    it('getStatus 返回 supported=false 的空状态', async () => {
      const s = await helper.getStatus();
      expect(s.supported).toBe(false);
      expect(s.installed).toBe(false);
      expect(s.ready).toBe(false);
      expect(s.needsRepair).toBe(false);
      expect(s.backgroundDisabled).toBe(false);
      expect(s.pathMismatch).toBe(false);
      expect(s.loaded).toBeNull();
    });

    it('isReady 返回 false（不尝试连接管道）', async () => {
      await expect(helper.isReady()).resolves.toBe(false);
    });

    it('install/uninstall 在非 Windows 报「仅 Windows 支持」', async () => {
      const i = await helper.install();
      expect(i.success).toBe(false);
      expect(i.error).toContain('Windows');
      const u = await helper.uninstall();
      expect(u.success).toBe(false);
      expect(u.error).toContain('Windows');
    });
  });

  describe('提权脚本生成', () => {
    const helper = new WindowsServiceHelper() as unknown as {
      buildInstallScript(exe: string, sb: string, conf: string, token: string): string;
      buildUninstallScript(): string;
      psq(s: string): string;
    };

    it('psq 转义单引号（PowerShell 双写规则）', () => {
      expect(helper.psq("a'b")).toBe("a''b");
      expect(helper.psq('plain')).toBe('plain');
    });

    it('install 脚本锁定 exe + flags、设 token ACL、sc create LocalSystem auto-start', () => {
      const script = helper.buildInstallScript(
        'C:\\Program Files\\FlowZ\\com.flowz.helper.exe',
        'C:\\Program Files\\FlowZ\\sing-box.exe',
        'C:\\Users\\doveh\\AppData\\Roaming\\FlowZ',
        'deadbeefdeadbeef'
      );
      // New-Service（非 sc create binPath=）：BinaryPathName 单一字符串直达 CreateService，绕开 CommandLineToArgvW 碎裂
      expect(script).toContain('New-Service -Name FlowZHelper -BinaryPathName $bp');
      expect(script).toContain('-StartupType Automatic');
      expect(script).not.toContain('binPath='); // 不得再用 sc create binPath= 的脆弱引号路径
      expect(script).not.toContain('-Credential'); // 锁定默认账户=LocalSystem 不变量（防误加凭据改成 NetworkService）
      // MED-1：sc delete 异步「标记删除」→ 轮询等服务消失 + New-Service 1072 退避重试
      expect(script).toContain('Get-Service');
      expect(script).toContain('1072');
      // 各含空格路径用**真双引号**包裹（非 \"），锁定 exe + 三参
      // v6: the service runs only its protected copy under ProgramData\FlowZ\core; the (user-writable) bundled
      // core is passed only as the hash-verified seed source.
      expect(script).toMatch(/--singbox "[^"]*ProgramData[^"]*FlowZ[^"]*core[^"]*sing-box\.exe"/);
      expect(script).toMatch(/--coredir "[^"]*ProgramData[^"]*FlowZ[^"]*core"/);
      expect(script).toContain('--bundledcore "C:\\Program Files\\FlowZ\\sing-box.exe"');
      expect(script).not.toContain('--singbox "C:\\Program Files');
      expect(script).not.toContain('core_update');
      expect(script).toContain('--confdir "C:\\Users\\doveh\\AppData\\Roaming\\FlowZ"');
      expect(script).toContain('--support');
      // U1 外置：binPath 的引导 exe 必须指向 ProgramData 外置副本、而非 app 安装目录内的 helper.exe（根因修复——
      // 否则服务锁定 app 内文件 → 更新覆盖失败 + 卸载留孤儿）。slash 方向随测试宿主不同，故用 ProgramData 子串判定。
      expect(script).toMatch(/\$bp = '"[^']*ProgramData[^']*com\.flowz\.helper\.exe" --singbox/);
      // 反向不变量：binPath 引导 exe 绝不再是 app 的 Program Files 路径（防回归到「锁 app 内二进制」）。
      expect(script).not.toMatch(/\$bp = '"[^']*Program Files[^']*com\.flowz\.helper\.exe"/);
      // 复制源是 app 内置 helper.exe；目的是 ProgramData\FlowZ；带 -Force 覆盖 + 退避重试兜解锁窗口竞态。
      expect(script).toContain("$helperSrc = 'C:\\Program Files\\FlowZ\\com.flowz.helper.exe'");
      expect(script).toMatch(
        /\$helperDst = '[^']*ProgramData[^']*FlowZ[^']*com\.flowz\.helper\.exe'/
      );
      expect(script).toContain('Copy-Item -LiteralPath $helperSrc -Destination $helperDst -Force');
      expect(script).toContain('Failed to copy helper.exe to ProgramData'); // 复制失败 fail-loud（不静默留旧副本）
      // 目录 ACL 硬化（防本地提权 + 闭 token TOCTOU）：去继承 + 仅 SYSTEM/Administrators 完全控制并 (OI)(CI) 下传。
      // ProgramData 默认让 Users 能在子目录建/删文件 → 不锁目录则普通用户可替换以 SYSTEM 运行的 helper.exe（=提权）。
      // icacls 经 System32 绝对路径调（规避 PATH 缺失），PS 调用算子 & '<abs>'
      // 主体用众所周知 SID（S-1-5-18 = SYSTEM，S-1-5-32-544 = Administrators）——账户名随系统语言本地化。
      const icacls = system32('icacls.exe');
      const grantSupport = `& '${icacls}' $support /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)"`;
      const stripSupport = `& '${icacls}' $support /inheritance:r`;
      expect(script).toContain(grantSupport);
      expect(script).toContain(stripSupport);
      // 外置副本再显式收紧：去继承、仅 SYSTEM/Administrators 完全控制。
      const grantDst = `& '${icacls}' $helperDst /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)"`;
      const stripDst = `& '${icacls}' $helperDst /inheritance:r`;
      expect(script).toContain(grantDst);
      expect(script).toContain(stripDst);
      // 先授权后去继承：授权失败时不能留下空 DACL 把目录/副本锁死。
      expect(script.indexOf(grantSupport)).toBeLessThan(script.indexOf(stripSupport));
      expect(script.indexOf(grantDst)).toBeLessThan(script.indexOf(stripDst));
      // 每次 icacls 后查退出码（外部命令不受 ErrorActionPreference=Stop 约束）。
      expect(script.match(/if \(\$LASTEXITCODE -ne 0\) \{ throw "icacls /g)?.length).toBe(4);
      // 关键不变量：SYSTEM helper 目录/二进制对 Users 零授权（绝不出现 Users 授权 → 杜绝替换/提权）。
      expect(script).not.toContain('Users:(RX)');
      expect(script).not.toContain('"Users');
      // 本地化 Windows（ru：Администраторы / СИСТЕМА）上英文账户名无法映射 → 不得再按名授权。
      expect(script).not.toMatch(/"(SYSTEM|Administrators):/);
      // 启动服务（sc.exe 经 System32 绝对路径调）
      expect(script).toContain(`& '${system32('sc.exe')}' start FlowZHelper`);
      // 幂等：重装先停删旧服务
      expect(script).toContain(`& '${system32('sc.exe')}' stop FlowZHelper`);
      expect(script).toContain(`& '${system32('sc.exe')}' delete FlowZHelper`);
      // token 值写入
      expect(script).toContain('deadbeefdeadbeef');
      // 重装可重入：写 token 前先删旧 token（自愈旧版「Admin 只读」残留——否则 Set-Content 覆盖只读文件被拒，真机根因）。
      // .NET File.Delete：不改属性、只靠目录的 FILE_DELETE_CHILD，失败不被吞（Remove-Item -Force 会先改属性而被拒）。
      expect(script).toContain('[System.IO.File]::Delete($tokenFile)');
      expect(script).not.toContain('Remove-Item -Force -Path $tokenFile');
      // 关键不变量：token **绝不**被设成 Admin 只读（机密性靠目录锁，不靠 token 只读；只读会破坏重装覆盖）。
      expect(script).not.toContain('icacls $tokenFile');
      expect(script).not.toContain('SYSTEM:(R)');
      // 删 token 必须在写 token 之前（顺序正确才自愈）。
      expect(script.indexOf('[System.IO.File]::Delete($tokenFile)')).toBeLessThan(
        script.indexOf('Set-Content -Path $tokenFile')
      );
    });

    it('install 脚本修复属主被改的支持目录：先 takeown /A，授权仍失败则挪开旧目录、新建后再授权', () => {
      const script = helper.buildInstallScript(
        'C:\\Program Files\\FlowZ\\com.flowz.helper.exe',
        'C:\\Program Files\\FlowZ\\sing-box.exe',
        'C:\\Users\\Ярослав\\AppData\\Roaming\\flowz',
        'deadbeefdeadbeef'
      );
      const takeown = `& '${system32('takeown.exe')}' /F $support /A | Out-Null`;
      const grant = `& '${system32('icacls.exe')}' $support /grant:r "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)"`;
      const move = '[System.IO.Directory]::Move($support, $broken)';
      expect(script).toContain(takeown);
      // 不带 /R：递归时的确认提示 /D 选项随系统语言本地化（ru 为 Д），会在隐藏窗口里卡住。
      expect(script).not.toMatch(/takeown\.exe' [^\n]*\/R/);
      expect(script.indexOf(takeown)).toBeLessThan(script.indexOf(grant));
      expect(script).toContain('$grantCode = $LASTEXITCODE');
      expect(script).toContain(move);
      // 挪开后在新目录上重新授权，且这次必须检查退出码；然后才去继承。
      const afterMove = script.slice(script.indexOf(move));
      expect(afterMove.indexOf(grant)).toBeGreaterThan(-1);
      expect(afterMove.indexOf(grant)).toBeLessThan(afterMove.indexOf('/inheritance:r'));
      expect(script).toContain('the old directory could not be moved aside');
    });

    it('install 脚本自愈旧版留下的空 DACL helper 副本（先补授权、再删、再拷，报错带真实原因）', () => {
      const script = helper.buildInstallScript(
        'C:\\Program Files\\FlowZ\\com.flowz.helper.exe',
        'C:\\Program Files\\FlowZ\\sing-box.exe',
        'C:\\Users\\Ярослав\\AppData\\Roaming\\flowz',
        'deadbeefdeadbeef'
      );
      const icacls = system32('icacls.exe');
      const repair = `if (Test-Path -LiteralPath $helperDst) {\n  & '${icacls}' $helperDst /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null\n}`;
      const del = '[System.IO.File]::Delete($helperDst); Copy-Item -LiteralPath $helperSrc';
      expect(script).toContain(repair);
      expect(script).toContain(del);
      // 顺序：停删服务 → 补授权 → 删+拷
      expect(script.indexOf(`& '${system32('sc.exe')}' delete FlowZHelper`)).toBeLessThan(
        script.indexOf(repair)
      );
      expect(script.indexOf(repair)).toBeLessThan(script.indexOf(del));
      expect(script).toContain('$copyErr = $_');
      expect(script).toContain('$($copyErr.Exception.Message)');
      // 受保护目录（默认 ProgramData\FlowZ）
      expect(script).toContain('FlowZ');
    });

    it('uninstall 脚本停 + 删服务 + 清受保护目录', () => {
      const script = helper.buildUninstallScript();
      expect(script).toContain(`& '${system32('sc.exe')}' stop FlowZHelper`);
      expect(script).toContain(`& '${system32('sc.exe')}' delete FlowZHelper`);
      expect(script).toContain('Remove-Item');
      expect(script).toContain('FlowZ');
      // 删目录前先递归补回 Admin 权限（旧版可能留下空 DACL，否则 Remove-Item 静默删不掉）。
      const grant = `& '${system32('icacls.exe')}' `;
      expect(script).toMatch(
        /icacls\.exe' '[^']*FlowZ' \/grant:r "\*S-1-5-32-544:\(OI\)\(CI\)\(F\)" \/T \/C \| Out-Null/
      );
      expect(script.indexOf(grant)).toBeLessThan(script.indexOf('Remove-Item'));
    });

    it('提权 .ps1 带 UTF-8 BOM（PS5.1 无 BOM 按 ANSI 解码，非 ASCII 字节被读成弯引号 → 整脚本解析失败）', () => {
      const h = helper as unknown as {
        buildElevatedScriptFile(inner: string, flag: string, err: string): string;
      };
      const inner = helper.buildInstallScript(
        'C:\\Users\\Дмитрий\\AppData\\Local\\Programs\\FlowZ\\resources\\win\\com.flowz.helper.exe',
        'C:\\Users\\Дмитрий\\AppData\\Roaming\\flowz\\core_update\\sing-box.exe',
        'C:\\Users\\Дмитрий\\AppData\\Roaming\\flowz',
        'deadbeefdeadbeef'
      );
      const bytes = Buffer.from(
        h.buildElevatedScriptFile(inner, 'C:\\t\\x.done', 'C:\\t\\x.err'),
        'utf8'
      );
      expect([...bytes.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
      // 反证 BOM 的必要性：同一脚本若按 cp1251/cp1252 逐字节解码，会冒出 PS 词法视作引号的 ‚ „ ‘ ’ “ ”（0x82/0x84/0x91–0x94）。
      const ansiQuoteBytes = [0x82, 0x84, 0x91, 0x92, 0x93, 0x94];
      expect([...bytes.subarray(3)].some((b) => ansiQuoteBytes.includes(b))).toBe(true);
    });
  });

  // 真管道不可单测：覆盖 sendCommand 成脚本化应答，专测 startCore 的重试与「旧核残留」守卫。
  describe('startCore（脚本化管道：重试 + 旧核残留守卫）', () => {
    class ScriptedHelper extends WindowsServiceHelper {
      constructor(private readonly handler: (rest: string[]) => string) {
        super();
      }
      protected async sendCommand(rest: string[], _timeoutMs: number): Promise<string> {
        if (rest[0] === 'core-info') return 'ERR unknown'; // pre-v6 service: no protected-core sync
        return this.handler(rest);
      }
    }

    it('stop 未确认 + helper 报 already → 不冒充成功（疑似旧核残留）', async () => {
      const h = new ScriptedHelper((rest) =>
        rest[0] === 'stop' ? 'ERR stop-failed' : 'OK already 4242'
      );
      const r = await h.startCore('C:\\cfg.json', 'C:\\core.log', true);
      expect(r.ok).toBe(false);
      expect(r.error).toContain('stale core');
    });

    it('stop 确认 + start OK started → 成功并返回 pid', async () => {
      const h = new ScriptedHelper((rest) =>
        rest[0] === 'stop' ? 'OK stopped 111' : 'OK started 222'
      );
      await expect(h.startCore('C:\\cfg.json', 'C:\\core.log', true)).resolves.toEqual({
        ok: true,
        pid: 222,
      });
    });

    it('start 瞬态失败（管道异常）→ 循环内重试后成功', async () => {
      let starts = 0;
      const h = new ScriptedHelper((rest) => {
        if (rest[0] === 'stop') return 'OK notrunning';
        starts += 1;
        if (starts === 1) throw new Error('pipe reset');
        return 'OK started 333';
      });
      await expect(h.startCore('C:\\cfg.json', 'C:\\core.log', true)).resolves.toEqual({
        ok: true,
        pid: 333,
      });
      expect(starts).toBe(2);
    });

    it('start 返回 ERR → 立即失败，不重试', async () => {
      let starts = 0;
      const h = new ScriptedHelper((rest) => {
        if (rest[0] === 'stop') return 'OK notrunning';
        starts += 1;
        return 'ERR config-path-denied';
      });
      await expect(h.startCore('C:\\cfg.json', 'C:\\core.log', true)).resolves.toEqual({
        ok: false,
        error: 'ERR config-path-denied',
      });
      expect(starts).toBe(1);
    });
  });

  describe('v6: protected core re-seed on start', () => {
    it('ERR core-untrusted → install-core from the bundled dir (no UAC) → retry start', async () => {
      const sent: string[][] = [];
      class V6 extends WindowsServiceHelper {
        protected async sendCommand(rest: string[]): Promise<string> {
          sent.push(rest);
          if (rest[0] === 'stop') return 'OK notrunning';
          if (rest[0] === 'core-info') return 'ERR unknown';
          if (rest[0] === 'install-core') return 'OK installed';
          return sent.filter((r) => r[0] === 'start').length === 1
            ? 'ERR core-untrusted ab12'
            : 'OK started 77';
        }
      }
      jest
        .spyOn(resourceManager, 'getBundledSingBoxPath')
        .mockReturnValue('C:\\FlowZ\\resources\\win\\sing-box.exe');
      let elevated = 0;
      const h = new V6();
      (h as unknown as { runElevatedPowerShell: () => Promise<unknown> }).runElevatedPowerShell =
        async () => {
          elevated++;
          return { success: true };
        };
      await expect(h.startCore('C:\\cfg.json', '', false)).resolves.toEqual({ ok: true, pid: 77 });
      expect(sent.filter((r) => r[0] === 'install-core')).toHaveLength(1);
      expect(elevated).toBe(0); // connect never prompts
    });

    it('untrusted user core: install-core refused → UAC only when allowElevation', async () => {
      class V6 extends WindowsServiceHelper {
        protected async sendCommand(): Promise<string> {
          return 'ERR untrusted-hash sing-box.exe ff';
        }
      }
      const h = new V6();
      let elevated = 0;
      (h as unknown as { installCoreElevated: () => Promise<unknown> }).installCoreElevated =
        async () => {
          elevated++;
          return { ok: true };
        };
      expect((await h.installCore('C:\\x')).ok).toBe(false);
      expect(elevated).toBe(0);
      expect(await h.installCore('C:\\x', { allowElevation: true })).toEqual({ ok: true });
      expect(elevated).toBe(1);
    });

    it('elevated core script hashes the bytes it writes and appends to trusted-hashes', () => {
      const h = new WindowsServiceHelper() as unknown as {
        buildElevatedCoreInstallScript(i: { name: string; src: string; sha256: string }[]): string;
        buildVerifiedLoader(p: string, sha: string, f: string, e: string): string;
      };
      const sha = 'b'.repeat(64);
      const s = h.buildElevatedCoreInstallScript([
        { name: 'sing-box.exe', src: "C:\\Users\\O'Neil\\core\\sing-box.exe", sha256: sha },
      ]);
      expect(s).toContain('[System.IO.File]::ReadAllBytes($src)');
      expect(s).toContain('if ($got -ne $want)');
      expect(s).toContain("$al = Join-Path $core 'trusted-hashes'");
      expect(s).toContain(
        `Install-One 'sing-box.exe' 'C:\\Users\\O''Neil\\core\\sing-box.exe' '${sha}'`
      );
      expect(() =>
        h.buildElevatedCoreInstallScript([{ name: 'x.exe', src: 'C:\\x', sha256: sha }])
      ).toThrow();
      // item 8: the elevated loader reads the script bytes once, checks the hash and runs those bytes (no -File)
      const loader = h.buildVerifiedLoader('C:\\t\\a.ps1', sha, 'C:\\t\\f', 'C:\\t\\e');
      expect(loader).toContain("ReadAllBytes('C:\\t\\a.ps1')");
      expect(loader).toContain(`if ($h -ne '${sha}')`);
      expect(loader).toContain('[ScriptBlock]::Create($t)');
    });
  });

  describe('v6 AUTH2 pipe authentication', () => {
    const tvToken = '00112233445566778899aabbccddeeff';
    const tvNc = '0123456789abcdef0123456789abcdef';
    const tvNs = 'fedcba9876543210fedcba9876543210';

    it('matches the Go helper test vectors (helper-win/auth_test.go)', () => {
      expect(authServerProof(tvToken, tvNc, tvNs)).toBe(
        '22d63aed5e2728581eb9d9f0ff8c92d88ecb7904c63283370bf5bfbb9582f10f'
      );
      expect(authClientProof(tvToken, tvNc, tvNs, ['start', 'C:\\cfg.json', '', '0', '42'])).toBe(
        '697891738d0b577d2bede6e59bf378b9580cfe604786e6f053daf9dcf861f8a5'
      );
      const chal = `CHAL ${tvNs} ${authServerProof(tvToken, tvNc, tvNs)}`;
      expect(parseAuthChallenge(tvToken, tvNc, chal)).toBe(tvNs);
      expect(parseAuthChallenge('wrong-token', tvNc, chal)).toBeNull();
      expect(parseAuthChallenge(tvToken, tvNc, 'ERR auth')).toBeNull();
      expect(() => buildAuthRequest(tvToken, tvNc, tvNs, ['a\nb'])).toThrow();
    });

    // Real socket round-trip (unix socket stands in for the named pipe; same net.Socket code path).
    const describePosix = process.platform === 'win32' ? describe.skip : describe;
    describePosix('round-trip', () => {
      const net = require('net');
      const os = require('os');
      const fsSync = require('fs');
      const pathMod = require('path');
      const crypto = require('crypto');

      function serve(sockPath: string, token: string | null, seen: string[]): Promise<() => void> {
        const server = net.createServer((c: import('net').Socket) => {
          let buf = '';
          let ns = '';
          let nc = '';
          c.on('data', (d: Buffer) => {
            buf += d.toString();
            seen.push(d.toString());
            if (!ns) {
              const nl = buf.indexOf('\n');
              if (nl < 0) return;
              nc = buf.slice(6, nl);
              buf = buf.slice(nl + 1);
              ns = crypto.randomBytes(16).toString('hex');
              // an impostor (token === null) cannot compute the proof
              const proof = token ? authServerProof(token, nc, ns) : 'f'.repeat(64);
              c.write(`CHAL ${ns} ${proof}\n`);
              return;
            }
            const lines = buf.split('\n');
            const [mac, n] = lines[0].split(' ');
            if (lines.length < Number(n) + 2) return;
            const req = lines.slice(1, 1 + Number(n));
            const ok = token && mac === authClientProof(token, nc, ns, req);
            c.end(ok ? `OK echo ${req.join('|')}\n` : 'ERR auth\n');
          });
        });
        return new Promise((resolve) =>
          server.listen(sockPath, () => resolve(() => server.close()))
        );
      }

      class PipeHelper extends WindowsServiceHelper {
        constructor(
          sockPath: string,
          private readonly tok: string
        ) {
          super();
          this.pipePath = sockPath;
        }
        protected token(): string {
          return this.tok;
        }
        call(rest: string[]): Promise<string> {
          return this.sendCommandAuth2(rest, 3000);
        }
      }

      it('authenticates without ever sending the token; an impostor server learns nothing', async () => {
        const dir = fsSync.mkdtempSync(pathMod.join(os.tmpdir(), 'fz-'));
        const token = crypto.randomBytes(16).toString('hex');
        const sock = pathMod.join(dir, 's');
        const seen: string[] = [];
        let close = await serve(sock, token, seen);
        const h = new PipeHelper(sock, token);
        await expect(h.call(['start', 'C:\\cfg.json', '', '1', '9'])).resolves.toBe(
          'OK echo start|C:\\cfg.json||1|9'
        );
        expect(seen.join('')).not.toContain(token);
        close();

        const sock2 = pathMod.join(dir, 's2');
        const seen2: string[] = [];
        close = await serve(sock2, null, seen2);
        await expect(new PipeHelper(sock2, token).call(['ping'])).rejects.toThrow(
          /failed authentication/
        );
        expect(seen2.join('')).not.toContain(token);
        expect(seen2.join('')).not.toContain('ping'); // request not sent to an unproven server
        close();
        fsSync.rmSync(dir, { recursive: true, force: true });
      });
    });
  });
});
