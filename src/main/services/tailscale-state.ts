/**
 * Tailscale state 目录工具：`<userData>/tailscale/<serverId>` 的路径与存在性判定。
 *
 * 交互登录（无 auth_key）产出的是该目录下的会话文件（跨重启免重认证）。1.14 起登录态判定全量迁移到
 * 管理 API STATUS 流（见 docs/design/tailscale-1.14-management-api.md），此模块仅余两用途：
 * 1) `tailscaleStateDir`：buildTailscaleEndpoint 的 state_directory + 删节点/登出时清理目录；
 * 2) `tailscaleStateExists`：proxy-handlers 登录态秒显兜底 + startInternal reassert 登录期出口让位预置的
 *    「是否曾登录」判据（tailscaleEndpointInRunningCore 改 always-emit 后已不再用它，见该函数）。
 * 已剥离登录成功轮询（pollTailscaleLoginSuccess，stateExists 误判未认证为已登录是 #132 根因）。
 */

import * as path from 'path';
import { getUserDataPath } from '../utils/paths';

/**
 * 可安全作为路径段的节点 id（现网 id 全部由 randomUUID 生成）。id 可来自备份恢复 / 手改配置，且本模块的目录
 * 会被 `fs.rm(..., {recursive, force})` 清理——`../..` 之类的 id 会把删除指向 userData 之外。
 */
export const SAFE_NODE_ID_RE = /^[A-Za-z0-9_-]+$/;

export function isSafeNodeId(id: unknown): id is string {
  return typeof id === 'string' && id.length <= 128 && SAFE_NODE_ID_RE.test(id);
}

/** Tailscale state 目录：`<userData>/tailscale/<serverId>`，跨重启免重认证、删节点时清理。非法 id → throw。 */
export function tailscaleStateDir(serverId: string): string {
  if (!isSafeNodeId(serverId)) {
    throw new Error('Invalid Tailscale node id (refusing to build a state directory path)');
  }
  return path.join(getUserDataPath(), 'tailscale', serverId);
}

/** state 目录存在且非空 → 已有持久登录会话。缺失/空/读失败 → false（失败安全）。 */
export function tailscaleStateExists(serverId: string): boolean {
  try {
    // readdirSync 在目录缺失时抛 ENOENT → catch 返 false，无需先 existsSync（省一次 stat）。
    return require('fs').readdirSync(tailscaleStateDir(serverId)).length > 0;
  } catch {
    return false;
  }
}
