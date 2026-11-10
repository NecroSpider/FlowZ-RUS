import { IpcMainInvokeEvent, app, shell } from 'electron';
import { release } from 'node:os';
import { IPC_CHANNELS } from '../../../shared/ipc-channels';
import { REPOSITORY_URL } from '../../../shared/repository';
import { LOGIN_ITEMS_SETTINGS_URL } from '../../../shared/constants';
import { registerIpcHandler } from '../ipc-handler';
// 内核版本以 core-manifest.json 为权威（构建时随内核打包的真相），非 package.json.singboxVersion（旧值易漂移）。
import coreManifest from '../../../shared/core-manifest.json';
// 构建时刻注入的真实构建日期（scripts/gen-build-info.js 生成），非运行时 new Date（B-1）。
import { BUILD_DATE } from '../../../shared/build-info';

const BUNDLED_CORE_VERSION = coreManifest.bundledCoreVersion || 'Unknown';

interface VersionInfo {
  appVersion: string;
  appName: string;
  buildDate: string;
  singBoxVersion: string;
  copyright: string;
  repositoryUrl: string;
  platform: string;
  arch: string;
  osVersion: string;
}

import { CoreUpdateService } from '../../services/CoreUpdateService';

/**
 * shell:openExternal 白名单：渲染端只允许打开 http(s) 网页 + macOS「登录项」设置深链（精确匹配常量）。
 * 其它 scheme（file:/smb:/javascript:/ms-msdt:/自定义协议处理器等）一律拒绝——openExternal 交 OS 协议处理器执行，
 * 放行任意 URL 等于让渲染端可触发本地文件/任意协议处理器。
 */
export function isAllowedExternalUrl(url: unknown): url is string {
  if (typeof url !== 'string' || url.length === 0 || url.length > 8192) return false;
  if (url === LOGIN_ITEMS_SETTINGS_URL) return true;
  try {
    const u = new URL(url);
    return (u.protocol === 'https:' || u.protocol === 'http:') && u.hostname.length > 0;
  } catch {
    return false;
  }
}

export function registerVersionHandlers(coreUpdateService?: CoreUpdateService): void {
  registerIpcHandler<void, VersionInfo>(
    IPC_CHANNELS.VERSION_GET_INFO,
    async (_event: IpcMainInvokeEvent) => {
      let currentSingBoxVersion = BUNDLED_CORE_VERSION;
      if (coreUpdateService) {
        try {
          // About 页显示：force=false 读缓存（启动已预热）→ 避免每次进入 spawn 内核子进程致加载转圈。
          const version = await coreUpdateService.getCurrentVersion(false);
          if (version && version !== 'unknown') {
            currentSingBoxVersion = version;
          }
        } catch (error) {
          console.error('Failed to get core version:', error);
        }
      }

      return {
        appVersion: app.getVersion(),
        appName: 'FlowZ',
        buildDate: BUILD_DATE,
        singBoxVersion: currentSingBoxVersion,
        copyright: `© 2025 FlowZ Project · © ${new Date().getFullYear()} NecroSpider`,
        repositoryUrl: REPOSITORY_URL,
        platform: process.platform,
        arch: process.arch,
        osVersion: release(),
      };
    }
  );

  registerIpcHandler<string, boolean>(
    IPC_CHANNELS.SHELL_OPEN_EXTERNAL,
    async (_event: IpcMainInvokeEvent, url: string) => {
      if (!isAllowedExternalUrl(url)) {
        throw Object.assign(new Error('Refusing to open a non-http(s) URL'), {
          code: 'URL_NOT_ALLOWED',
        });
      }
      await shell.openExternal(url);
      return true;
    }
  );
}
