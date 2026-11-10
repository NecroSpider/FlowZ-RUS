import { app, ipcMain, IpcMainInvokeEvent } from 'electron';
import * as path from 'path';
import * as url from 'url';
import { ApiResponse } from '../../shared/types';
import { IpcChannel } from '../../shared/ipc-channels';
import type { LogManager } from '../services/LogManager';

/** 开发环境标识（与 index.ts 一致：仅 NODE_ENV=development 暴露堆栈等调试信息） */
const isDevelopment = process.env.NODE_ENV === 'development';

// ── 渲染层信任策略（导航锁 / IPC 来源校验 / 权限判定共用的单一真值）────────────────────────────
// 「本应用自己的页面」= 生产：dist/renderer 目录下的 file:// 页面（index.html / update-popup.html）；
// 开发：vite dev server 源（http://localhost:5173）。其它一切（拖进窗口的 .html / 远端页 / data: 页）都不可信。

/** vite dev server 源（与 vite.config.ts server.port + strictPort 一致）。 */
export const DEV_SERVER_ORIGIN = 'http://localhost:5173';

export interface TrustedRendererOptions {
  /** 打包后 renderer 目录的绝对路径（dist/renderer）。 */
  rendererDir: string;
  /** 开发期 vite 源；生产传 null（生产绝不信任 http 源）。 */
  devOrigin: string | null;
  /** 路径语义所属平台（测试可注入；默认 process.platform）。 */
  platform?: NodeJS.Platform;
}

/**
 * 判定 URL 是否为本应用自己的渲染页。纯函数，可单测。
 * file: 比对用「解码后的文件系统路径」而非原始字符串：Chromium 会对非 ASCII（如西里尔字母目录名）/空格做
 * percent-encoding，盘符大小写也可能不同；Windows/macOS 默认文件系统大小写不敏感 → 比较前小写化 + NFC 归一。
 * 解码异常（目录名含裸 `%`）先把孤立 `%` 转义为 `%25` 再解码，避免误判把真用户拒之门外（拒绝 = 整个 UI 不可用）。
 */
export function isAppRendererUrl(rawUrl: string, opts: TrustedRendererOptions): boolean {
  if (!rawUrl) return false;
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return false;
  }
  if (opts.devOrigin && u.origin === opts.devOrigin) return true;
  if (u.protocol !== 'file:') return false;
  const platform = opts.platform ?? process.platform;
  const isWin = platform === 'win32';
  const p = isWin ? path.win32 : path.posix;
  let filePath: string;
  try {
    u.hash = '';
    u.search = '';
    const href = u.href.replace(/%(?![0-9A-Fa-f]{2})/g, '%25');
    // Node ≥22 支持 { windows } 选项（按目标平台语义解析，测试可在 mac 上验 Windows 路径）。
    filePath = (url.fileURLToPath as (u: string, o?: { windows?: boolean }) => string)(href, {
      windows: isWin,
    });
  } catch {
    return false;
  }
  const caseInsensitive = isWin || platform === 'darwin';
  const norm = (s: string) => {
    const r = p.resolve(s).normalize('NFC');
    return caseInsensitive ? r.toLowerCase() : r;
  };
  const dir = norm(opts.rendererDir);
  const file = norm(filePath);
  return file.startsWith(dir.endsWith(p.sep) ? dir : dir + p.sep);
}

/** 当前进程的信任策略（index.ts 启动期 configureTrustedRenderer 注入；未注入 = 不做来源校验，供单测/早期调用）。 */
let trustedRenderer: TrustedRendererOptions | null = null;

/** 注入渲染层信任策略：启用 registerIpcHandler 的来源校验。必须在注册任何 IPC handler 之前调用。 */
export function configureTrustedRenderer(opts: TrustedRendererOptions | null): void {
  trustedRenderer = opts;
}

/** 当前进程策略下 URL 是否为本应用页面（未注入策略 → false，调用方据此保守拒绝导航）。 */
export function isTrustedRendererUrl(rawUrl: string): boolean {
  return trustedRenderer ? isAppRendererUrl(rawUrl, trustedRenderer) : false;
}

/**
 * IPC 来源校验：发送方 frame 必须仍存活且 URL 属于本应用页面。frame 已销毁 / 读 url 抛错 → 不可信。
 * 未注入策略时放行（单测与 configure 之前的行为不变）。
 */
export function isTrustedIpcSender(event: Pick<IpcMainInvokeEvent, 'senderFrame'>): boolean {
  if (!trustedRenderer) return true;
  try {
    const frame = event.senderFrame;
    if (!frame) return false;
    return isAppRendererUrl(frame.url, trustedRenderer);
  } catch {
    return false;
  }
}

/** 渲染层可获批的权限（deny-by-default 白名单）：仅剪贴板「写」（复制按钮用 navigator.clipboard.writeText）。 */
const ALLOWED_PERMISSIONS = new Set(['clipboard-sanitized-write']);

/** 本机 sing-box 面板源（http://127.0.0.1:<port>，dashboard 窗口）。 */
function isLoopbackDashboardUrl(rawUrl: string): boolean {
  try {
    const u = new URL(rawUrl);
    return u.protocol === 'http:' && u.hostname === '127.0.0.1';
  } catch {
    return false;
  }
}

/**
 * 权限请求/检查统一判定（session.setPermissionRequestHandler / setPermissionCheckHandler 共用）：
 * 白名单外一律拒绝；白名单内仅本应用页面与本机面板（复制按钮）可用；其它来源（含被拖进窗口的页面）一律拒绝。
 */
export function isPermissionAllowed(permission: string, requestingUrl: string): boolean {
  if (!ALLOWED_PERMISSIONS.has(permission)) return false;
  return isTrustedRendererUrl(requestingUrl) || isLoopbackDashboardUrl(requestingUrl);
}

/** 拒绝日志限频：同一来源 URL 只记一次（防恶意页刷爆日志）。 */
const rejectedSenderUrls = new Set<string>();
function logRejectedSender(channel: string, event: Pick<IpcMainInvokeEvent, 'senderFrame'>): void {
  let frameUrl = '<destroyed>';
  try {
    frameUrl = event.senderFrame?.url ?? '<destroyed>';
  } catch {
    /* frame disposed */
  }
  // 只记 scheme + 截断，避免把潜在敏感 query 写进日志
  const key = frameUrl.slice(0, 120);
  if (rejectedSenderUrls.has(key) || rejectedSenderUrls.size > 50) return;
  rejectedSenderUrls.add(key);
  const msg = `Rejected IPC "${channel}" from an untrusted sender: ${key}`;
  console.warn(`[IPC] ${msg}`);
  ipcLogger?.addLog('warn', msg, 'IpcHandlerRegistry');
}

/**
 * 可选的 LogManager 实例（由 main/index.ts 在启动期经 setIpcLogger 注入）。
 * 用于生产期把「同名 channel 重复注册」这类异常记入应用日志（开发期直接抛错，无需此实例）。
 */
let ipcLogger: LogManager | null = null;

/**
 * 注入 LogManager 供 IPC 注册器在生产环境记录异常（如同名 channel 重复注册）。
 * 在 main/index.ts 创建 LogManager 之后、注册任何 IPC handler 之前调用一次。
 */
export function setIpcLogger(logManager: LogManager | null): void {
  ipcLogger = logManager;
}

export type IpcHandler<TArgs = any, TResult = any> = (
  event: IpcMainInvokeEvent,
  args: TArgs
) => Promise<TResult> | TResult;

export class IpcHandlerRegistry {
  private handlers: Map<IpcChannel, IpcHandler> = new Map();

  /** @param channel 收紧为 IpcChannel 联合类型，编译期根治孤儿字面量 */
  register<TArgs = any, TResult = any>(
    channel: IpcChannel,
    handler: IpcHandler<TArgs, TResult>
  ): void {
    if (this.handlers.has(channel)) {
      // 同名 channel 二次注册是 bug（后注册者静默覆盖前者，导致前者的 handler 失效且难排查）。
      // 开发期直接抛错及早暴露；生产期不能崩主进程，改为记入 LogManager 供事后排查。
      const msg = `IPC handler for channel "${channel}" is already registered. Overwriting.`;
      if (!app.isPackaged) {
        throw new Error(msg);
      }
      ipcLogger?.addLog('warn', msg, 'IpcHandlerRegistry');
    }

    const wrappedHandler = async (
      event: IpcMainInvokeEvent,
      args: TArgs
    ): Promise<ApiResponse<TResult>> => {
      // 来源校验：只服务本应用自己的页面（拖进窗口的本地 .html / 远端页即使拿到 preload 也调不动任何 handler）。
      if (!isTrustedIpcSender(event)) {
        logRejectedSender(channel, event);
        return { success: false, error: 'Untrusted IPC sender', code: 'IPC_FORBIDDEN' };
      }
      try {
        const result = await handler(event, args);

        return {
          success: true,
          data: result,
        };
      } catch (error) {
        console.error(`[IPC] Error handling channel "${channel}":`, error);

        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorCode = (error as any)?.code;
        const errorStack = error instanceof Error ? error.stack : undefined;

        // 记录详细错误堆栈：仅开发环境输出，生产环境不暴露堆栈
        if (isDevelopment && errorStack) {
          console.error(`[IPC] Stack trace:`, errorStack);
        }

        return {
          success: false,
          error: errorMessage,
          code: errorCode,
        };
      }
    };

    this.handlers.set(channel, wrappedHandler);
    // 覆盖注册前必须先摘除旧 handler：Electron 的 ipcMain.handle 对同名 channel 二次调用会直接
    // throw "Attempted to register a second handler"。生产分支已选择「不崩、记 warn 后覆盖」，若不先
    // removeHandler，紧随的 handle 仍会抛崩主进程，与「生产不崩」意图相悖。removeHandler 对未注册
    // channel 是安全 no-op（首次注册无副作用），与 unregister() 的用法一致。
    ipcMain.removeHandler(channel);
    ipcMain.handle(channel, wrappedHandler);
  }

  unregister(channel: IpcChannel): void {
    if (this.handlers.has(channel)) {
      ipcMain.removeHandler(channel);
      this.handlers.delete(channel);
    }
  }

  unregisterAll(): void {
    for (const channel of this.handlers.keys()) {
      ipcMain.removeHandler(channel);
    }
    this.handlers.clear();
  }

  getRegisteredChannels(): IpcChannel[] {
    return Array.from(this.handlers.keys());
  }

  isRegistered(channel: IpcChannel): boolean {
    return this.handlers.has(channel);
  }
}

export const ipcHandlerRegistry = new IpcHandlerRegistry();

export function registerIpcHandler<TArgs = any, TResult = any>(
  channel: IpcChannel,
  handler: IpcHandler<TArgs, TResult>
): void {
  ipcHandlerRegistry.register(channel, handler);
}
