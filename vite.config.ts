import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { createHash } from 'crypto';

const sha256 = (s: string): string =>
  `'sha256-${createHash('sha256').update(s, 'utf8').digest('base64')}'`;

/**
 * 生产构建给每个 HTML 入口（index.html / update-popup.html）注入 Content-Security-Policy meta（仅 build：dev server
 * 的 HMR 内联脚本 / ws 不受影响）。按最终 HTML 计算内联 <script> 的 sha256（如早期主题脚本），其余脚本只许 'self'。
 *  - img-src：data:（国旗 svg / vite 内联小图）、blob:、flowz-icon:（外部图标经主进程代理协议）。
 *  - connect-src 'self'：渲染层不直连网络（全部经 IPC / flowz-icon 协议）。
 * frame-ancestors 在 meta 中无效，故不写。
 */
function rendererCspPlugin(): Plugin {
  return {
    name: 'flowz-renderer-csp',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler(html) {
        const inlineHashes: string[] = [];
        const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
        let m: RegExpExecArray | null;
        while ((m = re.exec(html))) {
          if (/\bsrc\s*=/.test(m[1]) || m[2].trim() === '') continue;
          inlineHashes.push(sha256(m[2]));
        }
        const scriptSrc = ["'self'", ...inlineHashes];
        const csp = [
          "default-src 'self'",
          `script-src ${scriptSrc.join(' ')}`,
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: blob: flowz-icon:",
          "font-src 'self' data:",
          "connect-src 'self'",
          "object-src 'none'",
          "base-uri 'none'",
          "form-action 'none'",
        ].join('; ');
        const meta = `<meta http-equiv="Content-Security-Policy" content="${csp}" />`;
        // 紧跟 <meta charset> 之后插入（早于任何脚本/样式）；找不到 charset 则 head 开头。
        const charsetRe = /<meta\s+charset=[^>]*>/i;
        if (charsetRe.test(html)) return html.replace(charsetRe, (tag) => `${tag}\n    ${meta}`);
        return html.replace(/<head[^>]*>/i, (tag) => `${tag}\n    ${meta}`);
      },
    },
  };
}

export default defineConfig({
  plugins: [react(), rendererCspPlugin()],
  root: path.join(__dirname, 'src/renderer'),
  base: './',
  build: {
    outDir: path.join(__dirname, 'dist/renderer'),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: path.join(__dirname, 'src/renderer/index.html'),
        // 独立更新弹窗入口（Conduit mini 更新窗，UpdateService.createUpdatePopup 加载）——与主窗共享 index.css token/字体。
        updatePopup: path.join(__dirname, 'src/renderer/update-popup.html'),
      },
    },
  },
  resolve: {
    alias: {
      '@': path.join(__dirname, 'src/renderer'),
      '@shared': path.join(__dirname, 'src/shared'),
      '@renderer': path.join(__dirname, 'src/renderer'),
      '@components': path.join(__dirname, 'src/renderer/components'),
      '@lib': path.join(__dirname, 'src/renderer/lib'),
      '@hooks': path.join(__dirname, 'src/renderer/hooks'),
      '@store': path.join(__dirname, 'src/renderer/store'),
      '@pages': path.join(__dirname, 'src/renderer/pages'),
      '@bridge': path.join(__dirname, 'src/renderer/bridge'),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});
