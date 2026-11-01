/**
 * WindowsServiceHelper 纯逻辑单测（无 Windows 机/无命名管道）：
 *  - 平台门控：非 win32 安全降级（supported=false / ready=false），绝不触发 SCM/管道。
 *  - 提权脚本生成（runtime 最脆点）：sc create/start、binPath 锁定 exe+flags、token ACL、卸载脚本。
 *  - PowerShell 单引号转义。
 * 真机行为（UAC、sc 引号语义、管道连通）属 Windows 真机必验清单，不在单测范围。
 */
import { WindowsServiceHelper } from '../WindowsServiceHelper';
import { system32 } from '../../utils/win-system32';

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
      expect(script).toContain('--singbox "C:\\Program Files\\FlowZ\\sing-box.exe"');
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
      expect(script).toContain('复制 helper.exe 到 ProgramData 失败'); // 复制失败 fail-loud（不静默留旧副本）
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
      expect(script).toContain('旧目录也无法挪开');
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
});
