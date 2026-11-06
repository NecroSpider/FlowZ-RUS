import * as fs from 'fs';
import * as path from 'path';
import { APP_PRESETS, defaultAppRules, seedDefaultAppRules } from '../app-rules-preset';
import type { AppRule } from '../types';

const DATA_DIR = path.resolve(__dirname, '../../../resources/data');
const OWN_LISTS_DIR = path.resolve(__dirname, '../../../scripts/rule-sets');

describe('app-rules-preset bundled rule sets', () => {
  it('every preset geosite/geoip tag ships as a bundled .srs (offline, no 404 at startup)', () => {
    const missing: string[] = [];
    for (const p of APP_PRESETS) {
      const files = [
        // category-ai is stored upstream as category-ai-!cn (see builtin-geo-rulesets.ts)
        ...p.geositeTags.map((t) => `geosite-${t === 'category-ai' ? 'category-ai-!cn' : t}.srs`),
        ...(p.geoipTags ?? []).map((t) => `geoip-${t}.srs`),
      ];
      for (const f of files)
        if (!fs.existsSync(path.join(DATA_DIR, f))) missing.push(`${p.id}: ${f}`);
    }
    expect(missing).toEqual([]);
  });

  it('self-made lists (no upstream) keep their JSON source next to the compiled .srs', () => {
    for (const tag of ['bungie', 'blitz']) {
      expect(fs.existsSync(path.join(OWN_LISTS_DIR, `geosite-${tag}.json`))).toBe(true);
      expect(fs.existsSync(path.join(DATA_DIR, `geosite-${tag}.srs`))).toBe(true);
    }
  });

  it('Blitz.gg preset is a game preset routed by the self-made geosite-blitz list', () => {
    const blitz = APP_PRESETS.find((p) => p.id === 'blitz');
    expect(blitz).toBeDefined();
    expect(blitz?.category).toBe('game');
    expect(blitz?.geositeTags).toEqual(['blitz']);
    expect(blitz?.processNames).toEqual(expect.arrayContaining(['Blitz.exe', 'Blitz']));
  });
});

describe('app-rules-preset 默认注入', () => {
  it('已下线预设 apple / bilibili 不在 APP_PRESETS', () => {
    const ids = APP_PRESETS.map((p) => p.id);
    expect(ids).not.toContain('apple');
    expect(ids).not.toContain('bilibili');
  });

  describe('defaultAppRules', () => {
    it('为每个预设生成 proxy·enabled·无目标节点 规则', () => {
      const rules = defaultAppRules();
      expect(rules).toHaveLength(APP_PRESETS.length);
      expect(
        rules.every((r) => r.action === 'proxy' && r.enabled && r.targetServerId === undefined)
      ).toBe(true);
      expect(rules.map((r) => r.appId).sort()).toEqual(APP_PRESETS.map((p) => p.id).sort());
    });
  });

  describe('seedDefaultAppRules', () => {
    it('空配置 → 注入全部预设默认规则', () => {
      expect(seedDefaultAppRules([])).toEqual(defaultAppRules());
    });

    it('保留用户已配置的预设规则（不覆盖 action/节点）并补齐其余', () => {
      const userRule: AppRule = { appId: 'youtube', action: 'direct', enabled: true };
      const merged = seedDefaultAppRules([userRule]);
      expect(merged.find((r) => r.appId === 'youtube')).toEqual(userRule);
      expect(merged).toHaveLength(APP_PRESETS.length);
    });

    it('保留自定义 app（custom-*）', () => {
      const custom: AppRule = { appId: 'custom-123', action: 'proxy', enabled: true };
      expect(seedDefaultAppRules([custom])).toContainEqual(custom);
    });

    it('剔除已下线预设（apple/bilibili）的残留规则', () => {
      const stale: AppRule[] = [
        { appId: 'apple', action: 'direct', enabled: true },
        { appId: 'bilibili', action: 'proxy', enabled: true },
      ];
      const ids = seedDefaultAppRules(stale).map((r) => r.appId);
      expect(ids).not.toContain('apple');
      expect(ids).not.toContain('bilibili');
    });

    it('幂等：二次注入结果不变', () => {
      const once = seedDefaultAppRules([]);
      expect(seedDefaultAppRules(once)).toEqual(once);
    });
  });
});
