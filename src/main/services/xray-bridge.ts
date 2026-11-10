import { spawn, type ChildProcess } from 'child_process';
import { randomBytes } from 'crypto';
import { createServer, Socket, type Server } from 'net';
import { setTimeout as delay } from 'timers/promises';
import type { ServerConfig } from '../../shared/types';
import {
  canUseXray,
  isXrayVlessEncryption,
  normalizeXrayTcpFragment,
} from '../../shared/xray-node';
import type {
  SingBoxDomainResolver,
  SingBoxInbound,
  SingBoxOutbound,
  SingBoxRouteRule,
} from './singbox-config-types';

const HOST = '127.0.0.1';
const USER = 'flowz';
const DIRECT_TAG = 'flowz-xray-direct';
export const XRAY_EGRESS_TAG = 'flowz-xray-egress';

function makeXrayOutbound(node: ServerConfig, tag: string) {
  const network = node.network ?? 'tcp';
  const security = node.security ?? 'none';
  const tls = node.tlsSettings;
  const reality = node.realitySettings;
  const streamSettings: Record<string, unknown> = {
    network,
    security,
    sockopt: { dialerProxy: DIRECT_TAG },
  };
  const fragment = normalizeXrayTcpFragment(node.xrayTcpFragment);
  if (fragment) streamSettings.finalmask = { tcp: [{ type: 'fragment', settings: fragment }] };
  if (security === 'reality' && reality) {
    streamSettings.realitySettings = {
      serverName: tls?.serverName || node.address,
      fingerprint: tls?.fingerprint || 'chrome',
      password: reality.publicKey,
      shortId: reality.shortId,
      spiderX: reality.spiderX,
      mldsa65Verify: reality.mldsa65Verify,
    };
  } else if (security === 'tls') {
    streamSettings.tlsSettings = {
      serverName: tls?.serverName || node.address,
      fingerprint: tls?.fingerprint,
      alpn: tls?.alpn,
    };
  }
  if (network === 'grpc') {
    const { serviceName, multiMode, authority } = node.grpcSettings ?? {};
    streamSettings.grpcSettings = { serviceName, multiMode, authority };
  } else if (network === 'xhttp') {
    const { path, host, mode } = node.xhttpSettings ?? {};
    streamSettings.xhttpSettings = { path, host, mode };
  } else if (network === 'ws' || network === 'httpupgrade') {
    const { path, headers } = node.wsSettings ?? {};
    const { Host, host, ...otherHeaders } = headers ?? {};
    streamSettings[network === 'ws' ? 'wsSettings' : 'httpupgradeSettings'] = {
      path,
      host: Host ?? host,
      headers: otherHeaders,
    };
  }
  return {
    tag,
    protocol: 'vless',
    settings: {
      address: node.address,
      port: node.port,
      id: node.uuid,
      encryption: isXrayVlessEncryption(node.encryption) ? node.encryption : 'none',
      flow: node.flow,
    },
    streamSettings,
  };
}

function reservePort(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, HOST, () => {
      const address = server.address();
      if (address && typeof address !== 'string') resolve(address.port);
      else reject(new Error('Could not allocate a local Xray port'));
    });
  });
}

function canAuthenticate(port: number, password: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new Socket();
    const finish = (ready: boolean) => {
      socket.destroy();
      resolve(ready);
    };
    socket.once('connect', () => socket.write(Buffer.from([5, 1, 2])));
    let reply = Buffer.alloc(0);
    let authenticating = false;
    socket.on('data', (chunk: Buffer) => {
      reply = Buffer.concat([reply, chunk]);
      if (reply.length < 2) return;
      if (authenticating) {
        finish(reply[0] === 1 && reply[1] === 0);
      } else if (reply[0] === 5 && reply[1] === 2) {
        authenticating = true;
        reply = Buffer.alloc(0);
        socket.write(
          Buffer.concat([
            Buffer.from([1, USER.length]),
            Buffer.from(USER),
            Buffer.from([password.length]),
            Buffer.from(password),
          ])
        );
      } else {
        finish(false);
      }
    });
    socket.once('close', () => resolve(false));
    socket.once('error', () => finish(false));
    socket.setTimeout(200, () => finish(false));
    socket.connect(port, HOST);
  });
}

class XrayConfigError extends Error {}

function launchXray(binary: string, config: object, test = false): ChildProcess {
  const args = ['run', '-format', 'json', '-c', 'stdin:'];
  if (test) args.push('-test');
  const child = spawn(binary, args, { windowsHide: true, stdio: ['pipe', 'ignore', 'ignore'] });
  child.stdin?.on('error', () => {});
  child.stdin?.end(JSON.stringify(config));
  return child;
}

function checkXrayConfig(binary: string, nodes: ServerConfig[]): Promise<boolean> {
  return new Promise((resolve) => {
    const outbounds = nodes.map((node, i) => makeXrayOutbound(node, `test-${i}`));
    const child = launchXray(binary, { outbounds }, true);
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve(false);
    }, 1500);
    child.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      resolve(code === 0);
    });
  });
}

async function validXrayNodes(
  binary: string,
  nodes: ServerConfig[],
  deadline: number
): Promise<ServerConfig[]> {
  if (Date.now() >= deadline) return [];
  if (await checkXrayConfig(binary, nodes)) return nodes;
  if (nodes.length === 1) return [];
  const middle = Math.floor(nodes.length / 2);
  const first = await validXrayNodes(binary, nodes.slice(0, middle), deadline);
  const last = await validXrayNodes(binary, nodes.slice(middle), deadline);
  return [...first, ...last];
}

/** Xray handles the VLESS transport; sing-box owns both ingress and physical egress. */
export class XrayBridge {
  private constructor(
    private readonly child: ChildProcess,
    private readonly ports: Map<string, number>,
    private readonly directPort: number,
    private readonly password: string
  ) {}

  static async start(binary: string, nodes: ServerConfig[]): Promise<XrayBridge | undefined> {
    const supported = nodes.filter(canUseXray);
    if (!supported.length) return undefined;
    try {
      return await XrayBridge.launch(binary, supported);
    } catch (error) {
      if (!(error instanceof XrayConfigError) || supported.length === 1) throw error;
      // A malformed profile should not prevent healthy nodes in the same subscription from starting.
      const valid = await validXrayNodes(binary, supported, Date.now() + 3500);
      if (!valid.length || valid.length === supported.length) throw error;
      return XrayBridge.launch(binary, valid);
    }
  }

  private static async launch(binary: string, supported: ServerConfig[]): Promise<XrayBridge> {
    const reservations = supported.map(() => createServer());
    reservations.push(createServer());
    let allocated: number[];
    try {
      // Wait for all attempts to settle before releasing reservations, even on failure.
      const results = await Promise.allSettled(reservations.map(reservePort));
      allocated = results.map((result) => {
        if (result.status === 'rejected') throw result.reason;
        return result.value;
      });
    } finally {
      for (const server of reservations) server.close();
    }

    const directPort = allocated[supported.length];
    const password = randomBytes(32).toString('hex');
    const outbounds = supported.map((node, i) => makeXrayOutbound(node, `vless-${i}`));
    const config = {
      log: { loglevel: 'none' },
      inbounds: supported.map((_, i) => ({
        tag: `socks-${i}`,
        protocol: 'socks',
        listen: HOST,
        port: allocated[i],
        settings: {
          auth: 'password',
          accounts: [{ user: USER, pass: password }],
          udp: true,
          ip: HOST,
        },
      })),
      outbounds: [
        { tag: 'blocked', protocol: 'blackhole' },
        ...outbounds,
        {
          tag: DIRECT_TAG,
          protocol: 'socks',
          settings: {
            servers: [{ address: HOST, port: directPort, users: [{ user: USER, pass: password }] }],
          },
        },
      ],
      routing: {
        rules: outbounds.map(({ tag }, i) => ({
          type: 'field',
          inboundTag: [`socks-${i}`],
          outboundTag: tag,
        })),
      },
    };
    const child = launchXray(binary, config);
    const bridge = new XrayBridge(
      child,
      new Map(supported.map((node, i) => [node.id, allocated[i]])),
      directPort,
      password
    );
    let failed = false;
    child.once('error', () => {
      failed = true;
    });
    child.once('exit', () => {
      failed = true;
    });
    try {
      const deadline = Date.now() + 5000;
      // Xray starts its listeners in inbound order. Verify the last one after spawn.
      while (!failed && Date.now() < deadline) {
        if ((await canAuthenticate(allocated[supported.length - 1], password)) && !failed)
          return bridge;
        await delay(40);
      }
      if (child.exitCode === 23) throw new XrayConfigError('Xray rejected the VLESS configuration');
      throw new Error('Xray core did not start');
    } catch (error) {
      bridge.stop();
      throw error;
    }
  }

  outbound(serverId: string, tag: string): SingBoxOutbound | undefined {
    const port = this.ports.get(serverId);
    if (!port) return undefined;
    return {
      type: 'socks',
      tag,
      server: HOST,
      server_port: port,
      inet4_bind_address: HOST,
      username: USER,
      password: this.password,
    };
  }

  hasNode(serverId: string): boolean {
    return this.ports.has(serverId);
  }

  onExit(listener: () => void): void {
    this.child.once('exit', listener);
  }

  directInbound(): SingBoxInbound {
    return {
      type: 'socks',
      tag: DIRECT_TAG,
      listen: HOST,
      listen_port: this.directPort,
      users: [{ username: USER, password: this.password }],
    };
  }

  directRule(): SingBoxRouteRule {
    return { inbound: [DIRECT_TAG], action: 'route', outbound: XRAY_EGRESS_TAG };
  }

  directOutbound(resolver: SingBoxDomainResolver): SingBoxOutbound {
    return { type: 'direct', tag: XRAY_EGRESS_TAG, domain_resolver: resolver };
  }

  stop(): void {
    if (this.child.exitCode !== null || this.child.signalCode !== null || this.child.killed) return;
    if (!this.child.kill()) return;
    const timer = setTimeout(() => this.child.kill('SIGKILL'), 1000);
    timer.unref();
    this.child.once('exit', () => clearTimeout(timer));
  }
}
