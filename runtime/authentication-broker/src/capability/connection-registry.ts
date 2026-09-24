import { randomUUID } from 'node:crypto';

/** Opaque server-created identity used by researcher controls, never a worker argument. */
export type ConnectionId = string & { readonly __connectionId: unique symbol };

export type ConnectionIdentityMode = 'stateful' | 'single-worker';

export interface ConnectionRecord {
  readonly connectionId: ConnectionId;
  readonly openedAtUtc: string;
}

export interface ConnectionIdResolver {
  resolve(sessionId?: string): ConnectionId | undefined;
}

interface RegistryOptions {
  identityMode: ConnectionIdentityMode;
  now?: () => Date;
  newId?: () => string;
}

/**
 * Adapts SDK lifecycle callbacks to broker-owned identities. The SDK session ID
 * stays private to this map and is never returned to the researcher surface.
 */
export class ConnectionRegistry implements ConnectionIdResolver {
  readonly identityMode: ConnectionIdentityMode;
  private readonly now: () => Date;
  private readonly newId: () => string;
  private readonly sessions = new Map<string, ConnectionId>();
  private readonly records = new Map<ConnectionId, ConnectionRecord>();
  private readonly listeners = new Set<(connectionId: ConnectionId) => void>();
  private singleWorkerConnectionId: ConnectionId | undefined;

  constructor(options: RegistryOptions) {
    this.identityMode = options.identityMode;
    this.now = options.now ?? (() => new Date());
    this.newId = options.newId ?? randomUUID;
  }

  registerSession(sessionId: string): ConnectionId {
    if (this.identityMode !== 'stateful') throw new Error('Registry requires stateful identity mode');
    if (!sessionId || this.sessions.has(sessionId)) throw new Error('MCP session is missing or already registered');
    const connectionId = this.createRecord();
    this.sessions.set(sessionId, connectionId);
    return connectionId;
  }

  registerSingleWorkerConnection(): ConnectionId {
    if (this.identityMode !== 'single-worker') throw new Error('Registry requires single-worker identity mode');
    if (this.singleWorkerConnectionId) throw new Error('Only one single worker connection may be active');
    this.singleWorkerConnectionId = this.createRecord();
    return this.singleWorkerConnectionId;
  }

  resolve(sessionId?: string): ConnectionId | undefined {
    if (this.identityMode === 'stateful') {
      if (!sessionId) return undefined;
      return this.sessions.get(sessionId);
    }
    // In fallback mode the sole accepted worker is established by the server's
    // connection event. An arbitrary request/session value cannot select it.
    return this.singleWorkerConnectionId;
  }

  closeSession(sessionId: string): boolean {
    if (this.identityMode !== 'stateful') return false;
    const connectionId = this.sessions.get(sessionId);
    if (!connectionId) return false;
    this.sessions.delete(sessionId);
    this.removeRecord(connectionId);
    return true;
  }

  closeSingleWorkerConnection(): boolean {
    if (this.identityMode !== 'single-worker' || !this.singleWorkerConnectionId) return false;
    const connectionId = this.singleWorkerConnectionId;
    this.singleWorkerConnectionId = undefined;
    this.removeRecord(connectionId);
    return true;
  }

  closeConnection(connectionId: string): boolean {
    const record = this.records.get(connectionId as ConnectionId);
    if (!record) return false;
    if (this.identityMode === 'single-worker') return this.closeSingleWorkerConnection();
    for (const [sessionId, mappedId] of this.sessions) {
      if (mappedId === record.connectionId) return this.closeSession(sessionId);
    }
    return false;
  }

  onClosed(listener: (connectionId: ConnectionId) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  list(): readonly ConnectionRecord[] {
    return Object.freeze([...this.records.values()].map((record) => Object.freeze({ ...record })));
  }

  private createRecord(): ConnectionId {
    const connectionId = this.newId() as ConnectionId;
    if (this.records.has(connectionId)) throw new Error('Connection identity collision');
    const openedAtUtc = this.now().toISOString();
    this.records.set(connectionId, Object.freeze({ connectionId, openedAtUtc }));
    return connectionId;
  }

  private removeRecord(connectionId: ConnectionId): void {
    if (!this.records.delete(connectionId)) return;
    for (const listener of this.listeners) {
      try {
        listener(connectionId);
      } catch {
        // Cleanup must continue for remaining listeners; callers observe only
        // opaque connection IDs and failure never restores the closed session.
      }
    }
  }
}
