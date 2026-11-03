/**
 * 首页「Tailscale 出口名不副实」行内警示（§H）。挂在 ConnectionControlCard（原 ConnectionStatusCard）「出口节点」下拉正下方：选中 TS 当出口
 * 但出不了公网（未选出口设备 / 出口设备离线）时给一行 warning 注脚 +「选择出口设备」链接直达 TS 设置。
 * 判定单一真值 = deriveTsExitWarning。none → 渲染 null。纯 renderer 视图态、零 IPC/config-gen/重启。取代旧 §G nudge。
 */
import { AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useAppStore } from '@/store/app-store';
import { deriveTsExitWarning } from '@shared/tailscale-exit-warning';

export function TsExitWarning() {
  const { t } = useTranslation();
  const config = useAppStore((s) => s.config);
  const setCurrentView = useAppStore((s) => s.setCurrentView);
  const setServerPageAction = useAppStore((s) => s.setServerPageAction);
  const proxyRunning = useAppStore((s) => !!s.connectionStatus?.proxyCore?.running);

  const selectedServer = config?.servers.find((x) => x.id === config?.selectedServerId);
  const tsId =
    selectedServer?.protocol?.toLowerCase() === 'tailscale' ? selectedServer.id : undefined;
  const loggedIn = useAppStore((s) => (tsId ? !!s.tailscaleLoginStates[tsId] : false));
  const peers = useAppStore((s) => (tsId ? s.tailscalePeers[tsId] : undefined));

  const warning = deriveTsExitWarning({
    selectedServer,
    loggedIn,
    proxyModeDirect: (config?.proxyMode || 'smart').toLowerCase() === 'direct',
    proxyRunning,
    peers,
  });
  if (warning === 'none') return null;

  // 「选择出口设备」→ 打开组网卡的 TS 设置弹窗（内含出口设备选择）。TS=选中出口时 server-page 自动落 mesh tab。
  const goPickExitNode = () => {
    setServerPageAction('ts-settings');
    setCurrentView('server');
  };

  return (
    <div className="flex items-start gap-1.5 pt-1">
      <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0 text-warning" />
      <p className="min-w-0 text-xs text-muted-foreground">
        {warning === 'no-exit-device'
          ? t(
              'home.tsExitNoDeviceWarn',
              'Set as exit, but no exit node selected — internet traffic still goes direct.'
            )
          : warning === 'exit-device-not-advertised'
            ? t(
                'home.tsExitNotAdvertisedWarn',
                "The selected exit node isn't advertising as an exit; internet can't route through it — pick a device that advertises exit."
              )
            : t(
                'home.tsExitDeviceOfflineWarn',
                'The exit node is offline; internet may not route through Tailscale.'
              )}
        <button
          type="button"
          onClick={goPickExitNode}
          className="ms-1 text-warning underline underline-offset-2 hover:opacity-80"
        >
          {t('home.tsExitPickDevice', 'Pick exit node')}
        </button>
      </p>
    </div>
  );
}
