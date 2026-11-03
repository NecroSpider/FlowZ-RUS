/**
 * 「报告问题」预填 issue —— 纯函数，把当前运行环境拼进 GitHub 新建 issue 的 URL。
 * 无 electron / DOM 依赖，可单测。正文结构与 .github/ISSUE_TEMPLATE/bug_report.md 对齐，
 * 区别仅在「环境」段自动带值（手动走模板时该段为空待填）。
 */

export interface BugReportEnv {
  /** app.getVersion() */
  appVersion?: string;
  /** process.platform：darwin | win32 | linux */
  platform?: string;
  /** process.arch：arm64 | x64 */
  arch?: string;
  /** os.release()，如 macOS 的 24.5.0 / Windows 的 10.0.22631 */
  osVersion?: string;
  singBoxVersion?: string;
  /** UserConfig.proxyModeType：'systemProxy' | 'tun' */
  proxyModeType?: string;
}

const PLATFORM_LABEL: Record<string, string> = {
  darwin: 'macOS',
  win32: 'Windows',
  linux: 'Linux',
};

const PROXY_MODE_LABEL: Record<string, string> = {
  systemProxy: 'System proxy',
  tun: 'TUN',
};

/** process.platform + arch + os.release 拼成可读串，如「macOS arm64 (24.5.0)」。缺项自动略过。 */
export function formatSystemInfo(env: BugReportEnv): string {
  const platform = env.platform ? (PLATFORM_LABEL[env.platform] ?? env.platform) : '';
  const head = [platform, env.arch].filter(Boolean).join(' ');
  const rel = env.osVersion ? ` (${env.osVersion})` : '';
  return `${head}${rel}`.trim();
}

/** proxyModeType → 中文标签（系统代理 / TUN）；未知值原样返回，缺省空串。 */
export function formatProxyMode(env: BugReportEnv): string {
  if (!env.proxyModeType) return '';
  return PROXY_MODE_LABEL[env.proxyModeType] ?? env.proxyModeType;
}

/** 生成预填的 issue 正文：环境段自动填好，其余段留空待用户补全。 */
export function buildBugReportBody(env: BugReportEnv): string {
  return [
    '## Environment (auto-filled, please keep)',
    `- FlowZ version: ${env.appVersion ?? ''}`,
    `- OS + architecture: ${formatSystemInfo(env)}`,
    `- sing-box core version: ${env.singBoxVersion ?? ''}`,
    `- Proxy mode: ${formatProxyMode(env)}`,
    '',
    '## What happened',
    '',
    '',
    '## Steps to reproduce',
    '1. ',
    '2. ',
    '3. ',
    '',
    '## Expected / actual',
    '- Expected:',
    '- Actual:',
    '',
    '## Raw logs (most important)',
    '<!-- Settings -> Logs: copy a few lines around the core log in square brackets [...] at the end of the error and paste them into the code block below -->',
    '',
    '```',
    '(paste logs here)',
    '```',
    '',
    '## Extra context (optional, often decisive)',
    '<!-- Does another client work? Only specific nodes (e.g. Argo / CDN-optimized)? Address type (optimized IP / optimized domain)? Subscription in use? -->',
    '',
  ].join('\n');
}

/** 生成 GitHub 新建 issue 的完整 URL：标题预填 [Bug] 、打 bug 标签、正文为 buildBugReportBody。 */
export function buildBugReportUrl(repositoryUrl: string, env: BugReportEnv): string {
  const base = repositoryUrl.replace(/\/+$/, '');
  const params = new URLSearchParams({
    title: '[Bug] ',
    labels: 'bug',
    body: buildBugReportBody(env),
  });
  return `${base}/issues/new?${params.toString()}`;
}
