import type { RuleType, RuleCondition } from './types/rules';

const isProcessRuleType = (t: RuleType): boolean => t === 'processName' || t === 'processPath';

/**
 * 判断一条自定义规则是否含进程匹配条件（processName/processPath）。
 *
 * 这类规则平台特定（进程名/路径在 win/mac/linux 各异，如 chrome.exe / Google Chrome / chrome），
 * 跨平台 backup 导入会静默失效。导入侧据此【禁用】（enabled=false，保留供重映射，不静默移除/失效），
 * 详见 docs/design/config-portability.md §3。覆盖首条件镜像(type)与多条件(conditions[]) 两种承载。
 */
export function ruleHasProcessCondition(rule: {
  type: RuleType;
  conditions?: RuleCondition[];
}): boolean {
  if (isProcessRuleType(rule.type)) return true;
  return (rule.conditions ?? []).some((c) => isProcessRuleType(c.type));
}

// ── 自定义（raw-JSON 透传）outbound 安全闸 ──────────────────────────────────────
/**
 * 拒绝的 outbound/endpoint type：随包 sing-box 内置 `tor` outbound，其 executable_path / extra_args 会在每次
 * 核启动 / 测速时**拉起任意本机程序**。自定义节点 JSON 可来自订阅导入、本地文件导入、备份恢复（均非用户逐字段
 * 审阅），故整类拒绝。
 */
const FORBIDDEN_CUSTOM_TYPES = new Set(['tor']);

/**
 * 拒绝的键（任意嵌套层级）：可执行程序 / 启动参数 / 本机文件系统路径。sing-box 中这类键都以 `_path` /
 * `_directory` / `_dir` 结尾（certificate_path、key_path、private_key_path、ech.config_path、state_directory、
 * data_directory、executable_path…）外加 tor 的 extra_args / torrc。注意 ws/http 传输的 `path` 是 URL 路径，
 * 不在此列（精确键名 `path` 放行）。
 */
const FORBIDDEN_CUSTOM_KEY_RE = /(_path|_paths|_directory|_dir)$|^(extra_args|torrc|executable)$/i;

/** 遍历深度上限（防恶意深嵌套栈溢出）；超限按拒绝处理。 */
const MAX_CUSTOM_OUTBOUND_DEPTH = 32;

/**
 * 自定义 outbound/endpoint JSON 安全检查。返回 null=可下发；字符串=拒绝理由（英文，供日志）。
 * 单一真值：outbound 构造（核启动 + 测速唯一出口）与本地导入两处共用。
 */
export function customOutboundRejectReason(outbound: unknown): string | null {
  if (!outbound || typeof outbound !== 'object' || Array.isArray(outbound)) return null;
  const type = (outbound as Record<string, unknown>).type;
  if (typeof type === 'string' && FORBIDDEN_CUSTOM_TYPES.has(type.trim().toLowerCase())) {
    return `outbound type "${type}" is not allowed (it can launch local programs)`;
  }
  const walk = (v: unknown, depth: number, at: string): string | null => {
    if (depth > MAX_CUSTOM_OUTBOUND_DEPTH)
      return `nesting deeper than ${MAX_CUSTOM_OUTBOUND_DEPTH}`;
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        const r = walk(v[i], depth + 1, `${at}[${i}]`);
        if (r) return r;
      }
      return null;
    }
    if (v && typeof v === 'object') {
      for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
        const p = at ? `${at}.${k}` : k;
        if (FORBIDDEN_CUSTOM_KEY_RE.test(k)) {
          return `key "${p}" is not allowed (local programs / file-system paths)`;
        }
        const r = walk(child, depth + 1, p);
        if (r) return r;
      }
    }
    return null;
  };
  return walk(outbound, 0, '');
}
