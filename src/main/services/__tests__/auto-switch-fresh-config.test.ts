/**
 * AutoSwitchService（2026-11 审计 #9）：换节点落盘必须基于**测速之后**重新读到的配置，只改 selectedServerId。
 * 旧实现保存测速前（数秒前）的快照 → 期间的订阅刷新 / 用户编辑被整份写回而丢失。
 */
jest.mock('electron', () => ({ BrowserWindow: class {} }));

import { AutoSwitchService } from '../AutoSwitchService';

const server = (id: string, name = id) => ({ id, name, address: `${id}.example`, port: 443 });

function setup(initial: any) {
  let disk = JSON.parse(JSON.stringify(initial));
  const configManager = {
    loadConfig: jest.fn(async () => JSON.parse(JSON.stringify(disk))),
    saveConfig: jest.fn(async (c: any) => {
      disk = JSON.parse(JSON.stringify(c));
    }),
  };
  const proxyManager = {
    switchMode: jest.fn(async () => {}),
    getStatus: () => ({ running: true }),
  };
  const logManager = { addLog: jest.fn() };
  const svc: any = new AutoSwitchService(
    configManager as any,
    proxyManager as any,
    logManager as any,
    () => null
  );
  return {
    svc,
    configManager,
    proxyManager,
    getDisk: () => disk,
    setDisk: (fn: (d: any) => void) => fn(disk),
  };
}

describe('AutoSwitchService：测速后重读配置，只改 selectedServerId', () => {
  it('测速期间订阅刷新新增了节点、改了规则 → 保存结果保留这些变更', async () => {
    const h = setup({
      servers: [server('a'), server('b')],
      selectedServerId: 'a',
      customRules: [],
    });
    h.svc.measureLatency = jest.fn(async () => {
      // 测速进行中：订阅刷新 + 用户加了一条规则
      h.setDisk((d) => {
        d.servers.push(server('c'));
        d.customRules = [{ id: 'r1' }];
      });
      return 50;
    });

    await h.svc.triggerSwitch('test');

    const saved = h.getDisk();
    expect(saved.selectedServerId).toBe('b');
    expect(saved.servers.map((s: any) => s.id)).toEqual(['a', 'b', 'c']);
    expect(saved.customRules).toEqual([{ id: 'r1' }]);
    expect(h.proxyManager.switchMode).toHaveBeenCalledWith(
      expect.objectContaining({ selectedServerId: 'b' })
    );
  });

  it('测速期间用户手动换了节点 → 不覆盖用户选择', async () => {
    const h = setup({ servers: [server('a'), server('b'), server('c')], selectedServerId: 'a' });
    h.svc.measureLatency = jest.fn(async () => {
      h.setDisk((d) => {
        d.selectedServerId = 'c';
      });
      return 50;
    });
    await h.svc.triggerSwitch('test');
    expect(h.configManager.saveConfig).not.toHaveBeenCalled();
    expect(h.proxyManager.switchMode).not.toHaveBeenCalled();
    expect(h.getDisk().selectedServerId).toBe('c');
  });

  it('选出的最优节点在测速期间被移除 → 不切换', async () => {
    const h = setup({ servers: [server('a'), server('b')], selectedServerId: 'a' });
    h.svc.measureLatency = jest.fn(async () => {
      h.setDisk((d) => {
        d.servers = d.servers.filter((s: any) => s.id !== 'b');
      });
      return 50;
    });
    await h.svc.triggerSwitch('test');
    expect(h.configManager.saveConfig).not.toHaveBeenCalled();
    expect(h.proxyManager.switchMode).not.toHaveBeenCalled();
  });
});
