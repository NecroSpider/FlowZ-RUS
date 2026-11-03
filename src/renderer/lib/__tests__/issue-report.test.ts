import {
  formatSystemInfo,
  formatProxyMode,
  buildBugReportBody,
  buildBugReportUrl,
} from '../issue-report';

describe('issue-report', () => {
  describe('formatSystemInfo', () => {
    it('maps platform to friendly name + arch + release', () => {
      expect(formatSystemInfo({ platform: 'darwin', arch: 'arm64', osVersion: '24.5.0' })).toBe(
        'macOS arm64 (24.5.0)'
      );
      expect(formatSystemInfo({ platform: 'win32', arch: 'x64', osVersion: '10.0.22631' })).toBe(
        'Windows x64 (10.0.22631)'
      );
    });

    it('omits missing parts and passes through unknown platform', () => {
      expect(formatSystemInfo({ platform: 'win32', arch: 'x64' })).toBe('Windows x64');
      expect(formatSystemInfo({ platform: 'freebsd', arch: 'x64' })).toBe('freebsd x64');
      expect(formatSystemInfo({})).toBe('');
    });
  });

  describe('formatProxyMode', () => {
    it('maps known modes to Chinese labels', () => {
      expect(formatProxyMode({ proxyModeType: 'systemProxy' })).toBe('System proxy');
      expect(formatProxyMode({ proxyModeType: 'tun' })).toBe('TUN');
    });
    it('returns empty for missing and passes through unknown', () => {
      expect(formatProxyMode({})).toBe('');
      expect(formatProxyMode({ proxyModeType: 'mixed' })).toBe('mixed');
    });
  });

  describe('buildBugReportBody', () => {
    it('fills env values and keeps the section scaffold', () => {
      const body = buildBugReportBody({
        appVersion: '4.0.1',
        platform: 'darwin',
        arch: 'arm64',
        osVersion: '24.5.0',
        singBoxVersion: '1.10.0',
        proxyModeType: 'tun',
      });
      expect(body).toContain('- FlowZ version: 4.0.1');
      expect(body).toContain('- OS + architecture: macOS arm64 (24.5.0)');
      expect(body).toContain('- sing-box core version: 1.10.0');
      expect(body).toContain('- Proxy mode: TUN');
      expect(body).toContain('## What happened');
      expect(body).toContain('## Raw logs (most important)');
      expect(body).toContain('## Extra context (optional, often decisive)');
    });

    it('tolerates fully missing env (manual-fill placeholders)', () => {
      const body = buildBugReportBody({});
      expect(body).toContain('- FlowZ version:');
      expect(body).toContain('- OS + architecture:');
      expect(body).toContain('- Proxy mode:');
    });
  });

  describe('buildBugReportUrl', () => {
    it('builds a new-issue URL with title/labels/body and trims trailing slashes', () => {
      const url = buildBugReportUrl('https://github.com/NecroSpider/FlowZ-RUS/', {
        appVersion: '4.0.1',
      });
      expect(url.startsWith('https://github.com/NecroSpider/FlowZ-RUS/issues/new?')).toBe(true);
      const qs = new URLSearchParams(url.split('?')[1]);
      expect(qs.get('title')).toBe('[Bug] ');
      expect(qs.get('labels')).toBe('bug');
      expect(qs.get('body')).toContain('- FlowZ version: 4.0.1');
    });
  });
});
