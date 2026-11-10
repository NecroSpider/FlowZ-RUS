/**
 * 「起核尾部被停止」竞态与相关加固（2026-11 审计 #1 / #5 / #7）：
 *  - 系统代理 / 系统 DNS 写入与终态清理串行（netOpTail），且每次写入前后复核 start 世代；
 *    被接管的 start 撤销自己写过的东西，但绝不拆更新的 start 写的；
 *  - 读不到系统代理状态时保留 marker；
 *  - 起核 1 s 窗口内被停止 → 让位（不重试、不发幻影 started）；旧进程迟到的 exit 不冲掉新会话；
 *  - 健康检查：探测失败 ≠ 核已死，判死需连续两次。
 * 全部依赖打桩：不起真进程、不碰系统代理/DNS。
 */
const os = require('os');
const path = require('path');
const fsSync = require('fs');
const { EventEmitter } = require('events');

const TMP = fsSync.mkdtempSync(path.join(os.tmpdir(), 'flowz-stopstart-'));
const FAKE_CORE = path.join(TMP, 'sing-box');
fsSync.writeFileSync(FAKE_CORE, '#!/bin/sh\n');

jest.mock('electron', () => ({
  app: { getPath: () => TMP, getVersion: () => '9.9.9', isPackaged: false, getAppPath: () => TMP },
  BrowserWindow: class {},
  Notification: class {},
  net: {},
  session: {},
  powerMonitor: { on: () => {}, removeListener: () => {} },
}));
jest.mock('../../utils/paths', () => ({
  ...jest.requireActual('../../utils/paths'),
  getUserDataPath: () => TMP,
}));

const spawnMock = jest.fn();
jest.mock('child_process', () => ({
  ...jest.requireActual('child_process'),
  spawn: (...args: unknown[]) => spawnMock(...args),
}));

import { ProxyManager } from '../ProxyManager';
import { SystemProxyBase } from '../SystemProxyManager';
import { CoreStartSupersededError } from '../core-readiness';

afterAll(() => {
  try {
    fsSync.rmSync(TMP, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

const MARKER = path.join(TMP, 'system-proxy.marker.json');
afterEach(() => {
  try {
    fsSync.rmSync(MARKER, { force: true });
  } catch {
    /* ignore */
  }
});

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

/** 假系统代理：marker 走真实文件（SystemProxyBase 静态读写），开关态在内存。enable 可被闸住模拟 networksetup 慢。 */
function fakeProxyManager(gate?: Promise<void>) {
  const state = { enabled: false, hostPort: '' };
  const mgr = {
    state,
    enableProxy: jest.fn(async (address: string, port: number) => {
      // 与真实 Win/mac 实现一致：先写 intent marker，再慢慢写系统设置。
      fsSync.writeFileSync(MARKER, JSON.stringify({ ourHostPort: `${address}:${port}`, at: 1 }));
      if (gate) await gate;
      state.enabled = true;
      state.hostPort = `${address}:${port}`;
    }),
    disableProxy: jest.fn(async () => {
      state.enabled = false;
      SystemProxyBase.clearMarkerFile();
    }),
    disableProxySync: jest.fn(),
    getProxyStatus: jest.fn(async () =>
      state.enabled
        ? { enabled: true, httpProxy: state.hostPort, httpsProxy: state.hostPort }
        : { enabled: false }
    ),
    setLogManager: jest.fn(),
  };
  return mgr;
}

function fakeDnsManager(gate?: Promise<void>) {
  let marker = false;
  return {
    get marker() {
      return marker;
    },
    setDns: jest.fn(async () => {
      if (gate) await gate;
      marker = true;
    }),
    restoreDns: jest.fn(async () => {
      marker = false;
    }),
    reconcileDns: jest.fn(async () => {}),
    restoreDnsSync: jest.fn(),
    hasMarker: jest.fn(() => marker),
    getLanResolverForDns: jest.fn(async () => null),
    getEffectiveResolvers: jest.fn(async () => []),
    setLogManager: jest.fn(),
  };
}

function makeSvc(): any {
  const configPath = path.join(TMP, `sb-${Math.random().toString(36).slice(2)}.json`);
  fsSync.writeFileSync(configPath, '{}');
  const svc: any = new ProxyManager(undefined, undefined, configPath, FAKE_CORE);
  svc.logToManager = jest.fn();
  svc.sendEventToRenderer = jest.fn();
  return svc;
}

const SP_CFG: any = { proxyModeType: 'systemProxy', servers: [], mixedPort: 7890 };
const TUN_CFG: any = { proxyModeType: 'tun', servers: [], dnsConfig: {} };

describe('#1 起核尾部的系统代理写入与「停止」串行', () => {
  it('enableProxy 在飞时用户点停止 → 清理排在 enable 之后，最终代理关闭、marker 删除', async () => {
    const svc = makeSvc();
    const gate = deferred();
    const mgr = fakeProxyManager(gate.promise);
    svc.setSystemProxyManager(mgr);
    const startGen = svc.lifecycleGeneration;

    const syncing = svc.syncSystemNetworkStateAfterStart(SP_CFG, startGen);
    await new Promise((r) => setImmediate(r)); // enable 已进队、marker 已写，系统设置还没写
    expect(mgr.enableProxy).toHaveBeenCalled();

    // IPC PROXY_STOP：先 ensureSystemProxyCleared，完成后 stop()（这里只模拟其世代 +1）
    const stopping = svc.ensureSystemProxyCleared().then(() => {
      svc.lifecycleGeneration++;
    });
    gate.resolve();
    await stopping;
    const applied = await syncing.catch((e: unknown) => e);
    // startInternal 的最后一道复核
    if (!(applied instanceof Error)) {
      await expect(svc.yieldSupersededStart(startGen, applied)).rejects.toBeInstanceOf(
        CoreStartSupersededError
      );
    }

    // 修复前：清理读到「还没开」→ 删 marker；随后 enable 才把代理写成开 → 死端口 + 无 marker。
    expect(mgr.state.enabled).toBe(false);
    expect(fsSync.existsSync(MARKER)).toBe(false);
  });

  it('停止的清理先于 enable 轮到 → enable 在队内发现世代已变，根本不写；本次 start 让位', async () => {
    const svc = makeSvc();
    const mgr = fakeProxyManager();
    svc.setSystemProxyManager(mgr);
    const startGen = svc.lifecycleGeneration;

    // 队列被占（例如上一条清理还在跑）
    const blocker = deferred();
    void svc.runNetOp(() => blocker.promise);
    const syncing = svc.syncSystemNetworkStateAfterStart(SP_CFG, startGen);
    const clearing = svc.ensureSystemProxyCleared();
    svc.lifecycleGeneration++; // stop() 接管
    blocker.resolve();

    await expect(syncing).rejects.toBeInstanceOf(CoreStartSupersededError);
    await clearing;
    expect(mgr.enableProxy).not.toHaveBeenCalled();
    expect(mgr.state.enabled).toBe(false);
  });

  it('TUN：setDns 写完才发现已被停止 → 撤销（还原 DNS）后让位', async () => {
    const svc = makeSvc();
    const gate = deferred();
    const dns = fakeDnsManager(gate.promise);
    svc.setSystemDnsManager(dns);
    const startGen = svc.lifecycleGeneration;

    const syncing = svc.syncSystemNetworkStateAfterStart(TUN_CFG, startGen);
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    expect(dns.setDns).toHaveBeenCalled();
    svc.lifecycleGeneration++; // 停止在 setDns 进行中发生
    gate.resolve();
    const applied = await syncing;
    expect(applied).toEqual({ proxy: false, dns: true });

    await expect(svc.yieldSupersededStart(startGen, applied)).rejects.toBeInstanceOf(
      CoreStartSupersededError
    );
    expect(dns.restoreDns).toHaveBeenCalledTimes(1);
    expect(dns.marker).toBe(false);
  });

  it('更新的 start 已写过系统 DNS（属主已变）→ 旧 start 让位时绝不拆它', async () => {
    const svc = makeSvc();
    const dns = fakeDnsManager();
    svc.setSystemDnsManager(dns);
    await dns.setDns();
    svc.netStateOwnerGen = 7; // 新 start（gen 7）写的
    await expect(svc.yieldSupersededStart(5, { proxy: false, dns: true })).rejects.toBeInstanceOf(
      CoreStartSupersededError
    );
    expect(dns.restoreDns).not.toHaveBeenCalled();
    expect(dns.marker).toBe(true);
  });
});

describe('#3 读不到系统代理状态 → 保留 marker', () => {
  it('getProxyStatus reject（超时）→ 不删 marker、不 disable', async () => {
    const svc = makeSvc();
    const mgr = fakeProxyManager();
    mgr.getProxyStatus.mockRejectedValue(new Error('Could not read the macOS system proxy state'));
    svc.setSystemProxyManager(mgr);
    fsSync.writeFileSync(MARKER, JSON.stringify({ ourHostPort: '127.0.0.1:7890', at: 1 }));

    await svc.ensureSystemProxyCleared();

    expect(fsSync.existsSync(MARKER)).toBe(true);
    expect(mgr.disableProxy).not.toHaveBeenCalled();
  });

  it('确实已不指向我们 → 照旧只删失真 marker', async () => {
    const svc = makeSvc();
    const mgr = fakeProxyManager();
    svc.setSystemProxyManager(mgr);
    fsSync.writeFileSync(MARKER, JSON.stringify({ ourHostPort: '127.0.0.1:7890', at: 1 }));
    await svc.ensureSystemProxyCleared();
    expect(fsSync.existsSync(MARKER)).toBe(false);
    expect(mgr.disableProxy).not.toHaveBeenCalled();
  });
});

/** spawn 出的假进程：只需 pid + exit 事件。 */
function makeFakeChild(pid = 4321): any {
  const child: any = new EventEmitter();
  child.pid = pid;
  child.stdout = null;
  child.stderr = null;
  child.kill = jest.fn();
  return child;
}

function makeSpawnSvc(): any {
  const svc = makeSvc();
  svc.currentConfig = { proxyModeType: 'systemProxy', servers: [] };
  svc.needsOsascript = () => false;
  svc.needsWindowsUAC = () => false;
  svc.privilegeService = { needsPrivilege: () => false, ensureCapabilities: jest.fn() };
  svc.helperManager = undefined;
  svc.cleanup = jest.fn();
  svc.startHealthCheck = jest.fn();
  svc.startLogFileWatcher = jest.fn();
  svc.ensureSystemProxyCleared = jest.fn().mockResolvedValue(undefined);
  svc.attemptAutoRestart = jest.fn().mockResolvedValue(undefined);
  return svc;
}

async function spawnedChild(): Promise<any> {
  for (let i = 0; i < 200 && spawnMock.mock.calls.length === 0; i++) {
    await new Promise((r) => setImmediate(r));
  }
  expect(spawnMock).toHaveBeenCalled();
  return spawnMock.mock.results[spawnMock.mock.results.length - 1].value;
}

describe('#1 变体 / #7 起核窗口与迟到的 exit', () => {
  beforeEach(() => {
    spawnMock.mockReset();
    spawnMock.mockImplementation(() => makeFakeChild());
  });

  it('1 s 起核窗口内被停止（SIGTERM）→ 让位错误（不可重试），而不是「启动期退出」', async () => {
    const svc = makeSpawnSvc();
    const gen = svc.lifecycleGeneration;
    const p = svc.startSingBoxProcess(gen);
    const child = await spawnedChild();
    svc.lifecycleGeneration++; // stop() 接管
    child.emit('exit', null, 'SIGTERM');
    const err = await p.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CoreStartSupersededError);
    expect(svc.shouldRetryStartError(err)).toBe(false);
  });

  it('被接管但进程还没退（停止腿仍在等它）→ 1 s 判定不发 started、不起健康检查', async () => {
    const svc = makeSpawnSvc();
    const started = jest.fn();
    svc.on('started', started);
    const gen = svc.lifecycleGeneration;
    const p = svc.startSingBoxProcess(gen);
    await spawnedChild();
    svc.lifecycleGeneration++;
    await expect(p).rejects.toBeInstanceOf(CoreStartSupersededError);
    expect(started).not.toHaveBeenCalled();
    expect(svc.startHealthCheck).not.toHaveBeenCalled();
  });

  it('旧进程迟到的 exit（新会话已换了进程）→ 不走 handleProcessExit', async () => {
    const svc = makeSpawnSvc();
    const handleExit = jest.fn();
    svc.handleProcessExit = handleExit;
    const p = svc.startSingBoxProcess(svc.lifecycleGeneration);
    const oldChild = await spawnedChild();
    await p; // 1 s 后判定成功
    svc.singboxProcess = makeFakeChild(9999); // 停止硬上限 cleanup 后，新会话 spawn 了新进程
    oldChild.emit('exit', 0, null);
    expect(handleExit).not.toHaveBeenCalled();

    // 对照：当前进程的 exit 照常走崩溃恢复
    const cur = svc.singboxProcess;
    svc.singboxProcess = oldChild;
    oldChild.emit('exit', 1, null);
    expect(handleExit).toHaveBeenCalledTimes(1);
    svc.singboxProcess = cur;
  });
});

describe('#5 健康检查：探测失败 ≠ 核已死；判死需连续两次', () => {
  function armHealth(svc: any, verdicts: Array<'alive' | 'dead' | 'unknown'>): jest.Mock {
    svc.startedViaWrapper = true;
    svc.singboxPid = 4321;
    svc.pid = 4321;
    svc.healthDeadConfirmDelayMs = 0;
    svc.getProcessExitInfo = () => '';
    svc.stopLogFileWatcher = () => {};
    svc.readLastStartupFatal = () => null;
    svc.reconcileLoginFallback = () => {};
    svc.selectedExitBackendState = () => null;
    svc.recordMemoryTimelineFrame = async () => {};
    svc.checkMemoryUsage = () => {};
    svc.shouldAutoRestart = () => true;
    const autoRestart = jest.fn();
    svc.attemptAutoRestart = autoRestart;
    const queue = [...verdicts];
    svc.isProcessAliveAsync = jest.fn(async () => queue.shift() ?? 'alive');
    return autoRestart;
  }

  it('tasklist 探测失败（unknown）且零 spawn 判据说进程在 → 不重启、不清状态', async () => {
    const svc = makeSvc();
    const autoRestart = armHealth(svc, ['unknown']);
    svc.processExistsNoSpawn = () => true;
    await svc.performHealthCheck();
    expect(autoRestart).not.toHaveBeenCalled();
    expect(svc.singboxPid).toBe(4321);
  });

  it('一次 dead、复核 alive（瞬时误判）→ 不重启', async () => {
    const svc = makeSvc();
    const autoRestart = armHealth(svc, ['dead', 'alive']);
    await svc.performHealthCheck();
    expect(autoRestart).not.toHaveBeenCalled();
    expect(svc.isProcessAliveAsync).toHaveBeenCalledTimes(2);
  });

  it('连续两次 dead → 照常自动重启', async () => {
    const svc = makeSvc();
    const autoRestart = armHealth(svc, ['dead', 'dead']);
    await svc.performHealthCheck();
    expect(autoRestart).toHaveBeenCalledTimes(1);
  });
});
