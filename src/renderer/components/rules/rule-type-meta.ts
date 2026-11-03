/**
 * 路由规则类型的渲染端元数据（唯一来源）：分组、占位示例、中文默认名/说明（i18n 回退）。
 * 供 rule-dialog、rules-page 列表 Badge、delete-dialog 共用。
 */
import type { RuleType } from '../../../shared/types';
import type { RuleCategory } from '../../../shared/rules';
import { RULE_TYPE_CATEGORY, BYPASS_FAKEIP_TYPES } from '../../../shared/rules';
import { RULE_RESOURCE_CATALOG } from '../../../shared/rule-resource-catalog';
import { Globe, Network, AppWindow, Library, Router } from 'lucide-react';

// 单一来源：分组映射与 bypassFakeIP 适用类型复用 shared/rules，避免与之漂移
export const TYPE_TO_CATEGORY = RULE_TYPE_CATEGORY;
export { BYPASS_FAKEIP_TYPES };

export const RULE_CATEGORIES: RuleCategory[] = [
  'domain',
  'network',
  'device',
  'process',
  'ruleset',
];

export const CATEGORY_TYPES: Record<RuleCategory, RuleType[]> = {
  domain: ['domain', 'domainSuffix', 'domainKeyword', 'domainRegex'],
  network: ['ipCidr', 'sourceIpCidr', 'port', 'sourcePort'],
  device: ['sourceMac', 'sourceHostname'],
  process: ['processName', 'processPath'],
  ruleset: ['geosite', 'geoip', 'ruleSet'],
};

/** 分组的默认中文名（i18n key: rules.category.<cat>）。 */
export const CATEGORY_NAME: Record<RuleCategory, string> = {
  domain: 'Domain',
  network: 'IP / Port',
  device: 'LAN Device',
  process: 'Process',
  ruleset: 'Rule Set',
};

export const CATEGORY_ICON: Record<RuleCategory, typeof Globe> = {
  domain: Globe,
  network: Network,
  device: Router,
  process: AppWindow,
  ruleset: Library,
};

/** 分组 Badge 着色（域名蓝 / IP紫 / 设备绿 / 进程橙 / 规则集青）。 */
export const CATEGORY_BADGE_CLASS: Record<RuleCategory, string> = {
  domain: 'border-transparent bg-badge-blue/15 text-badge-blue',
  network: 'border-transparent bg-badge-purple/15 text-badge-purple',
  device: 'border-transparent bg-badge-green/15 text-badge-green',
  process: 'border-transparent bg-badge-orange/15 text-badge-orange',
  ruleset: 'border-transparent bg-badge-cyan/15 text-badge-cyan',
};

/** 类型默认中文名（i18n key: rules.types.<type>.name）。 */
export const RULE_TYPE_NAME: Record<RuleType, string> = {
  domain: 'Domain',
  domainSuffix: 'Domain Suffix',
  domainKeyword: 'Domain Keyword',
  domainRegex: 'Domain Regex',
  ipCidr: 'Dest IP/CIDR',
  sourceIpCidr: 'Source IP/CIDR',
  port: 'Dest Port',
  sourcePort: 'Source Port',
  sourceMac: 'Source MAC',
  sourceHostname: 'Source Hostname',
  processName: 'Process Name',
  processPath: 'Process Path',
  geosite: 'Geosite',
  geoip: 'GeoIP',
  ruleSet: 'Rule Set',
};

/** 类型默认中文说明（i18n key: rules.types.<type>.desc）。 */
export const RULE_TYPE_DESC: Record<RuleType, string> = {
  domain: 'Match the exact full domain, no subdomains',
  domainSuffix: 'Match the domain and all its subdomains (recommended)',
  domainKeyword: 'Match if the domain contains the keyword',
  domainRegex: 'Match domain by Golang RE2 regex (advanced)',
  ipCidr: 'Destination IP/CIDR (IPv4/IPv6)',
  sourceIpCidr: 'Source IP/CIDR (route by source device)',
  port: 'Destination port, single or range (e.g. 1000-2000)',
  sourcePort: 'Source port (advanced, rarely used)',
  sourceMac: 'Route by source device MAC (LAN gateway scenario; Linux/macOS only)',
  sourceHostname: 'Route by source device hostname (DHCP lease name; Linux/macOS only)',
  processName: 'Executable file name (Windows incl. .exe); local connections only',
  processPath: 'Full executable path (distinguishes same-named programs)',
  geosite: 'sing-geosite domain category tag (e.g. youtube)',
  geoip: 'sing-geoip country/region IP tag (e.g. cn)',
  ruleSet: 'A downloaded local rule resource',
};

/** 每行一条输入的占位示例（i18n key: rules.types.<type>.placeholder）。 */
export const RULE_TYPE_PLACEHOLDER: Record<RuleType, string> = {
  domain: 'www.google.com',
  domainSuffix: 'google.com',
  domainKeyword: 'youtube',
  domainRegex: '^stun\\..+',
  ipCidr: '8.8.8.8/32',
  sourceIpCidr: '192.168.1.100/32',
  port: '443\n1000-2000',
  sourcePort: '5060',
  sourceMac: '00:11:22:33:44:55',
  sourceHostname: 'my-laptop',
  processName: 'Telegram',
  processPath: '/Applications/Telegram.app/Contents/MacOS/Telegram',
  geosite: 'youtube',
  geoip: 'cn',
  ruleSet: '',
};

export const PROCESS_TYPES: RuleType[] = ['processName', 'processPath'];

/** 按类型的输入格式 hint（i18n key: rules.types.<type>.hint）。ruleSet 用 ResourcePicker，不取此值。 */
export const RULE_TYPE_HINT: Record<RuleType, string> = {
  domain: 'One full domain per line',
  domainSuffix: 'One domain per line (matches it and all subdomains)',
  domainKeyword: 'One keyword per line; matches if the domain contains it',
  domainRegex: 'Golang RE2 regex; no lookahead / backreferences',
  ipCidr: 'One per line; a bare IP means a single host; IPv4/IPv6 both OK',
  sourceIpCidr: 'One source IP/CIDR per line',
  port: 'One port or range per line (e.g. 443 or 1000-2000)',
  sourcePort: 'One source port or range per line',
  sourceMac: 'One MAC per line (00:11:22:33:44:55 / 00-11-22-33-44-55 / 0011.2233.4455)',
  sourceHostname: 'One device hostname per line (from DHCP leases)',
  processName: 'One process name per line (Windows includes .exe)',
  processPath: 'One full process path per line',
  geosite: 'One tag per line (e.g. youtube), or pick from common tags below',
  geoip: 'One tag per line (e.g. cn), or pick from common tags below',
  ruleSet: '',
};

/** 这些类型典型只 1-3 条 → 输入框用较矮高度。 */
export const SHORT_VALUE_TYPES: RuleType[] = [
  'domainRegex',
  'port',
  'sourcePort',
  'sourceMac',
  'sourceHostname',
  'geosite',
  'geoip',
];

/** geosite/geoip 的「常用标签」建议（来自内置精选清单，渲染端直接 import，零 IPC）。 */
export const GEO_SUGGEST: Partial<Record<RuleType, string[]>> = {
  geosite: RULE_RESOURCE_CATALOG.filter((i) => i.category === 'geosite').map((i) => i.name),
  geoip: RULE_RESOURCE_CATALOG.filter((i) => i.category === 'geoip').map((i) => i.name),
};
