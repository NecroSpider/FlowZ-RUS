import {
  netstatDestinationToCidr,
  parseMacNetstatRoutes,
  parseScutilDictionaries,
  storeDnsEntries,
  parseScutilDnsResolvers,
  detectWorkVpn,
  mergeStickyWorkVpnDns,
  workVpnFingerprint,
  parseOpenVpnRemotes,
  applyWorkVpnToSingBoxConfig,
  dnsRulesUseLegacyAddressFilter,
  normalizeWorkDomain,
  parseWinNetSnapshot,
  WIN_VPN_CLIENT_PATH_REGEX,
} from '../work-vpn';

// 真机抓取（macOS 26，OpenVPN Connect 连在 FlowZ TUN 之后）：utun4 = FlowZ，utun5 = OpenVPN。
const NETSTAT = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            172.17.100.1       UGScg                 en8
default            172.17.20.1        UGScIg                en0
1                  172.19.0.1         UGSc                utun4
2/7                172.19.0.1         UGSc                utun4
8/5                172.19.0.1         UGSc                utun4
10.175/24          192.168.252.1      UGSc                utun5
95.143.180.69/32   172.19.0.1         UGSc                utun4
126                172.19.0.1         UGSc                utun4
127                127.0.0.1          UCS                   lo0
128.0/1            172.19.0.1         UGSc                utun4
169.254            link#23            UCS                   en8      !
172.17.10.2/32     192.168.252.1      UGSc                utun5
172.17.20/24       link#14            UCS                   en0      !
172.19.0.1         172.19.0.1         UH                  utun4
175.175            192.168.252.1      UGSc                utun5
192.168.252        192.168.252.13     UGSc                utun5
192.168.252.1      192.168.252.13     UH                  utun5
224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0
`;

// show Setup:/…/DNS（OpenVPN Connect 改写主服务）+ show State:/…/DNS（办公网 DHCP）
const STORE = `<dictionary> {
  OpenVPNConnectOrigServerAddresses : <array> {
    0 : 8.8.8.8
  }
  SearchOrder : 5000
  ServerAddresses : <array> {
    0 : 10.175.0.249
  }
}
<dictionary> {
  DomainName : itgroup.local
  ServerAddresses : <array> {
    0 : 172.17.10.2
    1 : 172.17.100.1
    2 : 8.8.8.8
  }
}
`;

const IFACES = {
  en0: ['172.17.20.27'],
  en8: ['172.17.100.152'],
  utun4: ['172.19.0.1'],
  utun5: ['192.168.252.13'],
  utun0: [],
};

function detectLive() {
  return detectWorkVpn({
    routes: parseMacNetstatRoutes(NETSTAT),
    ifaceAddrs: IFACES,
    ownTunAddrs: ['172.19.0.1'],
    ownMeshCidrs: [],
    ownTunExcludes: ['127.0.0.0/8'],
    dnsEntries: storeDnsEntries(parseScutilDictionaries(STORE)),
  });
}

describe('netstatDestinationToCidr', () => {
  it.each([
    ['default', 'UGSc', '0.0.0.0/0'],
    ['1', 'UGSc', '1.0.0.0/8'],
    ['2/7', 'UGSc', '2.0.0.0/7'],
    ['128.0/1', 'UGSc', '128.0.0.0/1'],
    ['10.175/24', 'UGSc', '10.175.0.0/24'],
    ['175.175', 'UGSc', '175.175.0.0/16'],
    ['192.168.252', 'UGSc', '192.168.252.0/24'],
    ['192.168.252.1', 'UH', '192.168.252.1/32'],
    ['172.17.10.2/32', 'UGSc', '172.17.10.2/32'],
  ])('%s → %s', (dest, flags, expected) => {
    expect(netstatDestinationToCidr(dest, flags)).toBe(expected);
  });

  it('IPv6 / 垃圾 → null', () => {
    expect(netstatDestinationToCidr('fe80::%utun0/64', 'UcI')).toBeNull();
    expect(netstatDestinationToCidr('300.1', 'U')).toBeNull();
  });
});

describe('detectWorkVpn（真机数据）', () => {
  it('认出 OpenVPN 接口、推送网段与 VPN DNS，排除 FlowZ 自家 TUN', () => {
    const s = detectLive();
    expect(s.interfaces).toHaveLength(1);
    const vpn = s.interfaces[0];
    expect(vpn.name).toBe('utun5');
    expect(vpn.cidrs).toEqual([
      '10.175.0.0/24',
      '172.17.10.2/32',
      '175.175.0.0/16',
      '192.168.252.0/24',
    ]);
    expect(vpn.dnsServers).toEqual(['10.175.0.249']);
    // 办公网 DHCP 条目混有非 VPN 服务器 → 其 itgroup.local 不算 VPN 域名
    expect(vpn.domains).toEqual([]);
    expect(vpn.fullTunnel).toBe(false);
  });

  it('经 FlowZ TUN 网关的 /32 识别为 VPN 服务器旁路路由', () => {
    expect(detectLive().serverIps).toEqual(['95.143.180.69']);
  });

  it('sing-tun 拆排除段产生的 /32 补集片不误判', () => {
    const s = detectWorkVpn({
      routes: parseMacNetstatRoutes(
        'Destination Gateway Flags Netif Expire\n1.2.3.5/32 172.19.0.1 UGSc utun4\n'
      ),
      ifaceAddrs: IFACES,
      ownTunAddrs: ['172.19.0.1'],
      ownMeshCidrs: [],
      ownTunExcludes: ['1.2.3.4/32'],
      dnsEntries: [],
    });
    expect(s.serverIps).toEqual([]);
  });

  it('全隧道（0/1 + 128/1）标记 fullTunnel 且不当作网段', () => {
    const s = detectWorkVpn({
      routes: parseMacNetstatRoutes(
        'Destination Gateway Flags Netif Expire\n0/1 10.8.0.1 UGSc utun7\n128.0/1 10.8.0.1 UGSc utun7\n10.8/24 10.8.0.2 UGSc utun7\n'
      ),
      ifaceAddrs: { utun7: ['10.8.0.2'] },
      ownTunAddrs: ['172.19.0.1'],
      ownMeshCidrs: [],
      ownTunExcludes: [],
      dnsEntries: [],
    });
    expect(s.interfaces[0].fullTunnel).toBe(true);
    expect(s.interfaces[0].cidrs).toEqual(['10.8.0.0/24']);
  });

  it('FlowZ 自家组网系统接口不算外部 VPN', () => {
    const s = detectWorkVpn({
      routes: parseMacNetstatRoutes(
        'Destination Gateway Flags Netif Expire\n100.64/10 link#30 UCS utun9\n'
      ),
      ifaceAddrs: { utun9: ['100.101.102.103'] },
      ownTunAddrs: [],
      ownMeshCidrs: ['100.64.0.0/10'],
      ownTunExcludes: [],
      dnsEntries: [],
    });
    expect(s.interfaces).toEqual([]);
  });

  it('补充解析器（per-domain）的域名归属 VPN', () => {
    const resolvers = parseScutilDnsResolvers(`DNS configuration

resolver #1
  nameserver[0] : 8.8.8.8

resolver #2
  domain   : corp.example
  nameserver[0] : 10.175.0.249
  nameserver[1] : 10.175.0.250

resolver #3
  domain   : local
  options  : mdns
`);
    const s = detectWorkVpn({
      routes: parseMacNetstatRoutes(NETSTAT),
      ifaceAddrs: IFACES,
      ownTunAddrs: ['172.19.0.1'],
      ownMeshCidrs: [],
      ownTunExcludes: [],
      dnsEntries: resolvers,
    });
    expect(s.interfaces[0].dnsServers).toEqual(['10.175.0.249', '10.175.0.250']);
    expect(s.interfaces[0].domains).toEqual(['corp.example']);
  });
});

describe('mergeStickyWorkVpnDns / workVpnFingerprint', () => {
  it('FlowZ 接管系统 DNS 后读不到 VPN DNS → 沿用上次，指纹不变（防重启循环）', () => {
    const before = detectLive();
    const afterTakeover = detectWorkVpn({
      routes: parseMacNetstatRoutes(NETSTAT),
      ifaceAddrs: IFACES,
      ownTunAddrs: ['172.19.0.1'],
      ownMeshCidrs: [],
      ownTunExcludes: [],
      dnsEntries: [],
    });
    expect(afterTakeover.interfaces[0].dnsServers).toEqual([]);
    const merged = mergeStickyWorkVpnDns(afterTakeover, before);
    expect(workVpnFingerprint(merged)).toBe(workVpnFingerprint(before));
  });

  it('VPN 接口换名（重连）→ 指纹变化', () => {
    const a = detectLive();
    const b = { ...a, interfaces: a.interfaces.map((it) => ({ ...it, name: 'utun6' })) };
    expect(workVpnFingerprint(a)).not.toBe(workVpnFingerprint(b));
  });

  it('无 VPN → 空指纹', () => {
    expect(workVpnFingerprint(null)).toBe('');
    expect(workVpnFingerprint({ interfaces: [], serverIps: ['1.1.1.1'] })).toBe('');
  });
});

describe('parseOpenVpnRemotes / normalizeWorkDomain', () => {
  it('取 remote 主机（含 <connection> 块），忽略注释与证书', () => {
    expect(
      parseOpenVpnRemotes(`client
remote 95.143.180.69 1195 udp
# remote commented.example 1194
<connection>
remote vpn.Example.ru 443 tcp-client
</connection>
remote vpn.example.ru 1194
<ca>
-----BEGIN CERTIFICATE-----
</ca>`)
    ).toEqual(['95.143.180.69', 'vpn.example.ru']);
  });

  it.each([
    ['Corp.Example.', 'corp.example'],
    ['*.corp.example', 'corp.example'],
    ['.corp.example', 'corp.example'],
    ['local', null],
    ['1.in-addr.arpa', null],
    ['10.0.0.1', null],
    ['bad domain', null],
  ])('%s → %s', (raw, expected) => {
    expect(normalizeWorkDomain(raw)).toBe(expected);
  });
});

function baseConfig() {
  return {
    dns: {
      servers: [{ tag: 'dns-bootstrap' }, { tag: 'fakeip' }],
      rules: [
        { inbound: ['probe-in-0'], server: 'dns-probe-exit-0' },
        { domain: ['node.example'], server: 'dns-node-race' },
        { domain: ['doh.pub'], server: 'dns-bootstrap' },
        { domain_suffix: ['.local'], server: 'dns-local' },
        { query_type: ['A', 'AAAA'], server: 'fakeip' },
      ] as Array<Record<string, unknown>>,
    },
    inbounds: [
      { type: 'mixed', tag: 'mixed-in' },
      { type: 'tun', tag: 'tun-in', route_exclude_address: ['127.0.0.0/8'] },
    ] as Array<Record<string, unknown>>,
    outbounds: [{ type: 'direct', tag: 'direct' }] as Array<Record<string, unknown>>,
    route: {
      rules: [
        { action: 'sniff' },
        { inbound: ['probe-in-0'], action: 'route', outbound: 'probe-selector-0' },
        { port: [53], action: 'hijack-dns' },
        { ip_cidr: ['10.0.0.0/8'], action: 'route', outbound: 'direct' },
      ] as Array<Record<string, unknown>>,
    },
  };
}

describe('applyWorkVpnToSingBoxConfig', () => {
  const input = (over: Partial<Parameters<typeof applyWorkVpnToSingBoxConfig>[1]> = {}) => ({
    snapshot: detectLive(),
    serverIps: ['95.143.180.69'],
    serverHosts: ['vpn.example.ru'],
    userDomains: ['Jira.Corp.Example'],
    autoDetectDomains: true,
    tunMode: true,
    realResolverTag: 'dns-node-race',
    ownLanCidrs: ['172.17.20.27/24', '172.17.100.152/24'],
    fakeipRanges: ['198.18.0.0/15'],
    ...over,
  });

  it('TUN：绑接口出站 + VPN DNS + evaluate 探测 + 路由直连 + TUN 排除', () => {
    const cfg = baseConfig();
    const res = applyWorkVpnToSingBoxConfig(cfg, input());

    expect(cfg.outbounds).toContainEqual({
      type: 'direct',
      tag: 'work-vpn-utun5',
      bind_interface: 'utun5',
      domain_resolver: 'work-vpn-dns-0',
    });
    expect(cfg.dns.servers).toContainEqual({
      tag: 'work-vpn-dns-0',
      type: 'udp',
      server: '10.175.0.249',
      bind_interface: 'utun5',
    });

    // DNS：bootstrap 之后、.local / fakeip 之前
    const dnsTags = cfg.dns.rules.map((r) => r.action ?? r.server);
    expect(dnsTags).toEqual([
      'dns-probe-exit-0',
      'dns-node-race',
      'dns-bootstrap',
      'dns-node-race', // VPN 服务器域名走真实解析
      'work-vpn-dns-0', // 用户内部域名
      'evaluate',
      'respond',
      'dns-local',
      'fakeip',
    ]);
    expect(cfg.dns.rules[4]).toMatchObject({
      domain: ['jira.corp.example'],
      domain_suffix: ['.jira.corp.example'],
    });
    expect(cfg.dns.rules[6]).toMatchObject({
      match_response: true,
      ip_cidr: ['10.175.0.0/24', '172.17.10.2/32', '175.175.0.0/16', '192.168.252.0/24'],
    });
    expect(res.usedEvaluate).toBe(true);

    // 路由：hijack-dns 之后、私网直连之前
    const outs = cfg.route.rules.map((r) => r.outbound ?? r.action);
    expect(outs).toEqual([
      'sniff',
      'probe-selector-0',
      'hijack-dns',
      'direct', // VPN 客户端进程
      'direct', // VPN 服务器 IP / 域名
      'work-vpn-utun5', // VPN 网段
      'work-vpn-utun5', // 内部域名
      'direct',
    ]);
    expect(cfg.route.rules[4]).toMatchObject({
      ip_cidr: ['95.143.180.69/32'],
      domain: ['vpn.example.ru'],
    });

    expect(cfg.inbounds[1].route_exclude_address).toEqual([
      '127.0.0.0/8',
      '10.175.0.0/24',
      '172.17.10.2/32',
      '175.175.0.0/16',
      '192.168.252.0/24',
      '95.143.180.69/32',
    ]);
  });

  it('非 TUN：不绑接口、直接用 direct 出站', () => {
    const cfg = baseConfig();
    cfg.inbounds = [{ type: 'mixed', tag: 'mixed-in' }];
    applyWorkVpnToSingBoxConfig(cfg, input({ tunMode: false }));
    expect(cfg.outbounds).toHaveLength(1);
    expect(cfg.dns.servers.find((s) => s.tag === 'work-vpn-dns-0')).toEqual({
      tag: 'work-vpn-dns-0',
      type: 'udp',
      server: '10.175.0.249',
    });
    // 进程 + 服务器 + VPN 网段 + 内部域名 + 原有私网直连
    expect(cfg.route.rules.filter((r) => r.outbound === 'direct')).toHaveLength(5);
  });

  it('与本机物理 LAN / fakeip 相交的段不排除出 TUN', () => {
    const cfg = baseConfig();
    const snap = detectLive();
    snap.interfaces[0].cidrs.push('172.17.20.0/24', '198.18.0.0/16');
    applyWorkVpnToSingBoxConfig(cfg, input({ snapshot: snap }));
    const ex = cfg.inbounds[1].route_exclude_address as string[];
    expect(ex).not.toContain('172.17.20.0/24');
    expect(ex).not.toContain('198.18.0.0/16');
  });

  it('关闭自动识别 → 不发 evaluate', () => {
    const cfg = baseConfig();
    const res = applyWorkVpnToSingBoxConfig(cfg, input({ autoDetectDomains: false }));
    expect(res.usedEvaluate).toBe(false);
    expect(cfg.dns.rules.some((r) => r.action === 'evaluate')).toBe(false);
  });

  it('DNS 规则含旧式地址过滤 → 跳过 evaluate 并告警', () => {
    const cfg = baseConfig();
    cfg.dns.rules.push({ rule_set: ['geoip-ru'], server: 'dns-local' });
    const res = applyWorkVpnToSingBoxConfig(cfg, input());
    expect(res.usedEvaluate).toBe(false);
    expect(res.logs.some((l) => l.level === 'warn')).toBe(true);
  });

  it('无 VPN 但有配置文件里的服务器 → 只加服务器直连与真实解析', () => {
    const cfg = baseConfig();
    applyWorkVpnToSingBoxConfig(cfg, input({ snapshot: null, serverIps: [] }));
    expect(cfg.outbounds).toHaveLength(1);
    expect(cfg.dns.rules[3]).toEqual({ domain: ['vpn.example.ru'], server: 'dns-node-race' });
    expect(cfg.inbounds[1].route_exclude_address).toEqual(['127.0.0.0/8']);
  });

  it('什么都没有 → 零改动', () => {
    const cfg = baseConfig();
    const before = JSON.stringify(cfg);
    applyWorkVpnToSingBoxConfig(cfg, input({ snapshot: null, serverIps: [], serverHosts: [] }));
    expect(JSON.stringify(cfg)).toBe(before);
  });
});

describe('dnsRulesUseLegacyAddressFilter', () => {
  it('match_response 下的 ip_cidr 不算旧式', () => {
    expect(dnsRulesUseLegacyAddressFilter([{ match_response: true, ip_cidr: ['1.0.0.0/8'] }])).toBe(
      false
    );
    expect(dnsRulesUseLegacyAddressFilter([{ ip_is_private: true, server: 'x' }])).toBe(true);
    expect(
      dnsRulesUseLegacyAddressFilter([{ type: 'logical', rules: [{ ip_cidr: ['1.0.0.0/8'] }] }])
    ).toBe(true);
  });
});

// Windows 快照（work-vpn-detector 的 PowerShell 脚本输出形状）：OpenVPN DCO + 系统自带 IKEv2（RAS，不在网卡列表）
// + 未连的 TAP + WSL 虚拟网卡 + FlowZ 自家 TUN。网卡名含西里尔字母（俄文系统）。
const WIN_SNAPSHOT = {
  adapters: [
    { n: 'Ethernet', d: 'Intel(R) Ethernet Connection (17) I219-V' },
    { n: 'Беспроводная сеть', d: 'Intel(R) Wi-Fi 6E AX211 160MHz' },
    { n: 'OpenVPN Data Channel Offload', d: 'OpenVPN Data Channel Offload' },
    { n: 'Подключение по локальной сети 2', d: 'TAP-Windows Adapter V9 for OpenVPN Connect' },
    { n: 'vEthernet (WSL)', d: 'Hyper-V Virtual Ethernet Adapter' },
    { n: 'flowz-tun0', d: 'FlowZ Tunnel' },
  ],
  addrs: [
    { n: 'Ethernet', a: '192.168.1.50' },
    { n: 'Беспроводная сеть', a: '169.254.10.10' },
    { n: 'OpenVPN Data Channel Offload', a: '10.8.0.6' },
    { n: 'vEthernet (WSL)', a: '172.29.80.1' },
    { n: 'flowz-tun0', a: '172.19.0.1' },
    { n: 'Loopback Pseudo-Interface 1', a: '127.0.0.1' },
    { n: 'Corp IKEv2', a: '10.200.0.15' },
  ],
  routes: [
    { n: 'Ethernet', p: '0.0.0.0/0', g: '192.168.1.1' },
    { n: 'Ethernet', p: 'garbage', g: '0.0.0.0' },
    { n: 'flowz-tun0', p: '0.0.0.0/1', g: '0.0.0.0' },
    { n: 'flowz-tun0', p: '128.0.0.0/1', g: '0.0.0.0' },
    { n: 'OpenVPN Data Channel Offload', p: '10.175.0.0/24', g: '10.8.0.1' },
    { n: 'OpenVPN Data Channel Offload', p: '175.175.0.0/16', g: '10.8.0.1' },
    { n: 'OpenVPN Data Channel Offload', p: '10.8.0.0/24', g: '0.0.0.0' },
    { n: 'OpenVPN Data Channel Offload', p: '10.8.0.6/32', g: '0.0.0.0' },
    { n: 'OpenVPN Data Channel Offload', p: '10.8.0.255/32', g: '0.0.0.0' },
    { n: 'OpenVPN Data Channel Offload', p: '224.0.0.0/4', g: '0.0.0.0' },
    { n: 'OpenVPN Data Channel Offload', p: '255.255.255.255/32', g: '0.0.0.0' },
    { n: 'vEthernet (WSL)', p: '172.29.80.0/20', g: '0.0.0.0' },
    { n: 'Corp IKEv2', p: '10.200.0.0/16', g: '0.0.0.0' },
  ],
  dns: [
    { n: 'Ethernet', s: ['192.168.1.1'] },
    { n: 'OpenVPN Data Channel Offload', s: ['10.175.0.249'] },
    { n: 'Corp IKEv2', s: ['10.200.0.1'] },
    { n: 'vEthernet (WSL)', s: [] },
  ],
  suffix: [
    { n: 'Ethernet', d: 'lan' },
    { n: 'OpenVPN Data Channel Offload', d: 'corp.example' },
  ],
  nrpt: [
    { ns: ['.intra.example'], s: ['10.175.0.249'] },
    { ns: ['.public.example'], s: ['8.8.8.8'] },
  ],
};

function detectWin(snapshot: unknown = WIN_SNAPSHOT) {
  const parsed = parseWinNetSnapshot(JSON.stringify(snapshot), 'flowz-tun0');
  if (!parsed) throw new Error('parse failed');
  return detectWorkVpn({
    ...parsed,
    ownTunAddrs: ['172.19.0.1'],
    ownMeshCidrs: [],
    ownTunExcludes: [],
  });
}

describe('Windows：parseWinNetSnapshot + detectWorkVpn', () => {
  it('按驱动描述认 VPN 网卡，RAS 连接按「不在网卡列表」认；物理网卡 / WSL / 自家 TUN 不算', () => {
    const parsed = parseWinNetSnapshot(JSON.stringify(WIN_SNAPSHOT), 'flowz-tun0');
    expect(parsed?.tunnelIfaces.sort()).toEqual([
      'Corp IKEv2',
      'OpenVPN Data Channel Offload',
      'Подключение по локальной сети 2',
    ]);
    expect(parsed?.ifaceAddrs['Беспроводная сеть']).toBeUndefined(); // 169.254 不算地址
    expect(parsed?.ifaceAddrs['Loopback Pseudo-Interface 1']).toBeUndefined();
    expect(parsed?.routes.some((r) => r.cidr === 'garbage')).toBe(false);
  });

  it('网段、VPN DNS、连接后缀与 NRPT 域名归到对应 VPN；不走 VPN 的 NRPT 服务器丢弃', () => {
    expect(detectWin()).toEqual({
      interfaces: [
        {
          name: 'Corp IKEv2',
          addresses: ['10.200.0.15'],
          cidrs: ['10.200.0.0/16'],
          dnsServers: ['10.200.0.1'],
          domains: [],
          fullTunnel: false,
        },
        {
          name: 'OpenVPN Data Channel Offload',
          addresses: ['10.8.0.6'],
          cidrs: ['10.175.0.0/24', '175.175.0.0/16', '10.8.0.0/24'],
          dnsServers: ['10.175.0.249'],
          domains: ['corp.example', 'intra.example'],
          fullTunnel: false,
        },
      ],
      serverIps: [],
    });
  });

  it('redirect-gateway（0/1 + 128/1 走 VPN 网卡）→ fullTunnel', () => {
    const snap = {
      ...WIN_SNAPSHOT,
      routes: [
        ...WIN_SNAPSHOT.routes,
        { n: 'OpenVPN Data Channel Offload', p: '0.0.0.0/1', g: '10.8.0.1' },
        { n: 'OpenVPN Data Channel Offload', p: '128.0.0.0/1', g: '10.8.0.1' },
      ],
    };
    const dco = detectWin(snap).interfaces.find((it) => it.name === 'OpenVPN Data Channel Offload');
    expect(dco?.fullTunnel).toBe(true);
    expect(dco?.cidrs).not.toContain('0.0.0.0/1');
  });

  it('PowerShell 把非 ASCII 转成 \\uXXXX：网卡名原样还原；单个对象（非数组）也收', () => {
    const raw =
      '{"adapters":{"n":"\\u0421\\u0435\\u0442\\u044c","d":"TAP-Windows Adapter V9"},' +
      '"addrs":[{"n":"\\u0421\\u0435\\u0442\\u044c","a":"10.9.0.2"}],' +
      '"routes":[{"n":"\\u0421\\u0435\\u0442\\u044c","p":"10.9.0.0/24","g":"0.0.0.0"}]}';
    const parsed = parseWinNetSnapshot(raw, 'flowz-tun0');
    expect(parsed?.tunnelIfaces).toEqual(['Сеть']);
    expect(parsed?.routes).toEqual([
      { cidr: '10.9.0.0/24', gateway: '0.0.0.0', flags: '', iface: 'Сеть' },
    ]);
  });

  it('网卡列表取不到（CIM 被拦）→ 不做 RAS 推断，不把所有接口当 VPN', () => {
    expect(detectWin({ ...WIN_SNAPSHOT, adapters: [] }).interfaces).toEqual([]);
  });

  it('坏 JSON → null', () => {
    expect(parseWinNetSnapshot('not json', 'flowz-tun0')).toBeNull();
    expect(parseWinNetSnapshot('null', 'flowz-tun0')).toBeNull();
  });

  it('Windows 起核：绑 VPN 网卡（别名含空格）+ 按安装目录认 VPN 客户端进程', () => {
    const cfg = baseConfig();
    applyWorkVpnToSingBoxConfig(cfg, {
      snapshot: detectWin(),
      serverIps: [],
      serverHosts: [],
      userDomains: [],
      autoDetectDomains: false,
      tunMode: true,
      realResolverTag: 'dns-node-race',
      ownLanCidrs: [],
      fakeipRanges: ['198.18.0.0/15'],
      platform: 'win32',
    });
    expect(cfg.outbounds).toContainEqual({
      type: 'direct',
      tag: 'work-vpn-OpenVPN_Data_Channel_Offload',
      bind_interface: 'OpenVPN Data Channel Offload',
      domain_resolver: 'work-vpn-dns-1',
    });
    expect(cfg.route.rules).toContainEqual({
      process_path_regex: WIN_VPN_CLIENT_PATH_REGEX,
      action: 'route',
      outbound: 'direct',
    });
    const tun = cfg.inbounds.find((ib) => ib.type === 'tun');
    expect(tun?.route_exclude_address).toEqual(
      expect.arrayContaining(['175.175.0.0/16', '10.175.0.0/24', '10.200.0.0/16'])
    );
  });

  it('macOS 不发 process_path_regex', () => {
    const cfg = baseConfig();
    applyWorkVpnToSingBoxConfig(cfg, {
      snapshot: detectLive(),
      serverIps: [],
      serverHosts: [],
      userDomains: [],
      autoDetectDomains: false,
      tunMode: true,
      realResolverTag: 'dns-node-race',
      ownLanCidrs: [],
      fakeipRanges: [],
      platform: 'darwin',
    });
    expect(cfg.route.rules.some((r) => 'process_path_regex' in r)).toBe(false);
  });

  it('安装目录正则（RE2 语法，这里按 JS 等价写法验）', () => {
    const res = WIN_VPN_CLIENT_PATH_REGEX.map((r) => new RegExp(r.replace('(?i)', ''), 'i'));
    const hit = (p: string): boolean => res.some((re) => re.test(p));
    expect(hit('C:\\Program Files\\OpenVPN Connect\\agent_ovpnconnect_1594367036109.exe')).toBe(
      true
    );
    expect(hit('C:\\Program Files\\OpenVPN\\bin\\openvpn.exe')).toBe(true);
    expect(hit('C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\vpnagent.exe')).toBe(true);
    expect(hit('C:\\Program Files\\WireGuard\\wireguard.exe')).toBe(true);
    expect(hit('C:\\Program Files\\FlowZ\\FlowZ.exe')).toBe(false);
    expect(hit('C:\\Program Files\\OpenVPN Connect\\resources\\app\\x.dll')).toBe(false);
  });
});
