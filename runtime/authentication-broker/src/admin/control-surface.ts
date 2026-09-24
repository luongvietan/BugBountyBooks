import type { ConnectionRegistry, ConnectionRecord } from '../capability/connection-registry.js';
import type { CapabilityManager, CapabilityRole, WorkerToolName, HttpMethod } from '../capability/grants.js';

export interface ResearcherConnectionView {
  readonly connectionId: string;
  readonly openedAtUtc: string;
  readonly accountAlias?: string;
}

export interface ResearcherCapabilityGrant {
  connectionId: string;
  accountAlias: string;
  role: CapabilityRole;
  tools: WorkerToolName[];
  technique: string;
  policyReference: string;
  methods: HttpMethod[];
  origins: string[];
}

interface ControlSurfaceOptions {
  registry: Pick<ConnectionRegistry, 'list'>;
  capabilities: Pick<CapabilityManager, 'grant' | 'revoke' | 'accountAliasFor'>;
  closeSession: (connectionId: string) => boolean | Promise<boolean>;
}

/**
 * Researcher-only in-process actions. The worker MCP tool registry never
 * receives this object. Task 6 wires these actions to an attended terminal.
 */
export class ResearcherControlSurface {
  private readonly registry: ControlSurfaceOptions['registry'];
  private readonly capabilities: ControlSurfaceOptions['capabilities'];
  private readonly closeSessionAction: ControlSurfaceOptions['closeSession'];

  constructor(options: ControlSurfaceOptions) {
    this.registry = options.registry;
    this.capabilities = options.capabilities;
    this.closeSessionAction = options.closeSession;
  }

  listConnections(): readonly ResearcherConnectionView[] {
    return Object.freeze(this.registry.list().map((record: ConnectionRecord) => {
      const accountAlias = this.capabilities.accountAliasFor(record.connectionId);
      return Object.freeze({
        connectionId: record.connectionId,
        openedAtUtc: record.openedAtUtc,
        ...(accountAlias ? { accountAlias } : {})
      });
    }));
  }

  grant(input: ResearcherCapabilityGrant): unknown {
    return this.capabilities.grant(input);
  }

  revoke(connectionId: string): boolean {
    return this.capabilities.revoke(connectionId);
  }

  async closeSession(connectionId: string, confirmed: boolean): Promise<boolean> {
    if (confirmed !== true) return false;
    return this.closeSessionAction(connectionId);
  }
}
