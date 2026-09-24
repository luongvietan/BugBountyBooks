export interface RuntimeListener {
  readonly address: string;
  readonly port: number;
}

export interface RuntimeMcpServer {
  listen(): Promise<{ host: string; port: number }>;
  close(): Promise<void>;
}

export interface BrokerLifecycleOptions {
  readonly proxy: { start(): Promise<RuntimeListener>; close(): Promise<void> };
  readonly verifyEgress: () => boolean | Promise<boolean>;
  readonly createMcp: () => RuntimeMcpServer | Promise<RuntimeMcpServer>;
  readonly recheckIntervalMs?: number;
}

export function createBrokerLifecycle(options: BrokerLifecycleOptions): {
  start(): Promise<void>;
  refreshEgress(): Promise<boolean>;
  isEgressVerified(): boolean;
  isStarted(): boolean;
  close(): Promise<void>;
} {
  const intervalMs = options.recheckIntervalMs ?? 30_000;
  if (!Number.isInteger(intervalMs) || intervalMs < 1000 || intervalMs > 300_000) throw new Error('Egress recheck interval is invalid');
  let verified = false;
  let started = false;
  let closing = false;
  let checking = false;
  let mcp: RuntimeMcpServer | undefined;
  let timer: NodeJS.Timeout | undefined;
  let startOperation: Promise<void> | undefined;

  async function start(): Promise<void> {
    if (started) return;
    if (startOperation) return startOperation;
    if (closing) throw new Error('Broker runtime is closed');
    startOperation = startOnce();
    try { await startOperation; } finally { startOperation = undefined; }
  }

  async function startOnce(): Promise<void> {
    try {
      const proxy = await options.proxy.start();
      if (!proxy || proxy.address !== '127.0.0.1' || proxy.port !== 8766) throw new Error('Broker proxy listener is not exact loopback');
      if (!(await safeVerify())) throw new Error('Egress protection is not verified');
      verified = true;
      mcp = await options.createMcp();
      const listener = await mcp.listen();
      if (!listener || listener.host !== '127.0.0.1' || !Number.isInteger(listener.port) || listener.port < 1 || listener.port > 65535) {
        throw new Error('MCP listener is not exact loopback');
      }
      started = true;
      timer = setInterval(() => { void refreshEgress(); }, intervalMs);
      timer.unref();
    } catch (error) {
      verified = false;
      started = false;
      try { await mcp?.close(); } catch { /* listener cleanup continues */ }
      mcp = undefined;
      try { await options.proxy.close(); } catch { /* preserve fail-closed startup */ }
      if (error instanceof Error && ['Broker proxy listener is not exact loopback', 'Egress protection is not verified', 'MCP listener is not exact loopback'].includes(error.message)) {
        throw error;
      }
      throw new Error('Broker runtime could not start safely');
    }
  }

  async function refreshEgress(): Promise<boolean> {
    if (!started || closing || checking) return verified;
    checking = true;
    try { verified = await safeVerify(); } catch { verified = false; }
    finally { checking = false; }
    return verified;
  }

  function isEgressVerified(): boolean { return verified && started && !closing; }
  function isStarted(): boolean { return started && !closing; }

  async function close(): Promise<void> {
    if (closing) return;
    closing = true;
    verified = false;
    started = false;
    if (timer) clearInterval(timer);
    timer = undefined;
    let failed = false;
    try { await mcp?.close(); } catch { failed = true; }
    mcp = undefined;
    try { await options.proxy.close(); } catch { failed = true; }
    if (failed) throw new Error('Broker runtime could not close safely');
  }

  async function safeVerify(): Promise<boolean> {
    try { return await options.verifyEgress() === true; } catch { return false; }
  }

  return { start, refreshEgress, isEgressVerified, isStarted, close };
}
