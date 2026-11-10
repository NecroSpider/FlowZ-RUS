import type { ServerConfig } from '../../shared/types';
import type { SingBoxOutbound } from './singbox-config-types';

const MEMBER_PROTOCOLS = new Set(['vless', 'vmess', 'trojan', 'hysteria2', 'shadowsocks']);

export function isImportedGroupMember(server: ServerConfig): boolean {
  return MEMBER_PROTOCOLS.has(server.protocol);
}

export function importedGroupMembers(server: ServerConfig): string[] | undefined {
  if (
    server.protocol !== 'custom' ||
    server.customSettings?.outbound?.type !== 'urltest' ||
    !Array.isArray(server.urltestMemberIds)
  )
    return undefined;
  return server.urltestMemberIds.filter((id) => typeof id === 'string' && id !== server.id);
}

export function buildImportedGroup(
  memberIds: string[],
  tag: string,
  tagsById: ReadonlyMap<string, string>
): SingBoxOutbound | undefined {
  const members = [
    ...new Set(memberIds.map((id) => tagsById.get(id)).filter((tag): tag is string => !!tag)),
  ];
  if (members.length === 0) return undefined;
  return {
    type: 'urltest',
    tag,
    outbounds: members,
    url: 'https://www.gstatic.com/generate_204',
    interval: '30s',
  };
}
