/**
 * Backend Response Normalization Layer.
 * Shields SDK consumers from backend response shape inconsistencies, legacy property keys, and raw string formats.
 */

import {
  Agent,
  Connection,
  Message,
  Cluster,
  FloorTool,
  FloorAccessRequestStatus,
  WatchtowerActivity,
} from './types.js';
import { AamarvaError } from './errors.js';

export function extractMasterId(obj: Record<string, unknown>): string | undefined {
  const fields = ['masterId', 'master_id', 'masterAgentId', 'master_agent_id', 'ownerAgentId', 'owner_agent_id'];
  const candidates: Array<{ field: string; value: string }> = [];

  for (const f of fields) {
    const val = obj[f];
    if (typeof val === 'string' && val.trim()) {
      candidates.push({ field: f, value: val.trim() });
    }
  }

  if (candidates.length === 0) {
    return undefined;
  }

  const primary = candidates[0].value;
  for (let i = 1; i < candidates.length; i++) {
    if (candidates[i].value !== primary) {
      throw new AamarvaError(
        `Conflicting master/owner identity fields detected: ${candidates[0].field}=${candidates[0].value} vs ${candidates[i].field}=${candidates[i].value}.`,
        { code: 'MASTER_RESOLUTION_FAILED' }
      );
    }
  }

  return primary;
}

export function normalizeAgent(raw: unknown): Agent {
  if (!raw || typeof raw !== 'object') {
    return {
      agentId: '',
      name: '',
    };
  }

  const obj = raw as Record<string, unknown>;
  const masterId = extractMasterId(obj);

  return {
    agentId: String(obj.agentId || obj.id || ''),
    name: String(obj.name || obj.displayName || obj.display_name || ''),
    bio: typeof obj.bio === 'string' ? obj.bio : undefined,
    email: typeof obj.email === 'string' ? obj.email : undefined,
    status: typeof obj.status === 'string' ? obj.status : 'active',
    avatar: typeof obj.avatar === 'string' ? obj.avatar : undefined,
    avatarUrl: typeof obj.avatarUrl === 'string' ? obj.avatarUrl : typeof obj.avatar_url === 'string' ? obj.avatar_url : undefined,
    masterId,
    masterAgentId: masterId,
    ownerAgentId: masterId,
    slaveIds: Array.isArray(obj.slaveIds) ? obj.slaveIds.map(String) : Array.isArray(obj.slave_ids) ? obj.slave_ids.map(String) : undefined,
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : undefined,
    updatedAt: typeof obj.updatedAt === 'string' ? obj.updatedAt : undefined,
  };
}

export function normalizeConnection(raw: unknown, currentAgentId?: string): Connection {
  if (!raw || typeof raw !== 'object') {
    return {
      connectionId: '',
      agentId: '',
      status: 'active',
      createdAt: new Date().toISOString(),
    };
  }

  const obj = raw as Record<string, unknown>;
  
  let peerAgentId = '';
  if (typeof obj.peerAgentId === 'string' && obj.peerAgentId) {
    peerAgentId = obj.peerAgentId;
  } else if (typeof obj.agentId === 'string' && obj.agentId && obj.agentId !== currentAgentId) {
    peerAgentId = obj.agentId;
  } else if (typeof obj.targetAgentId === 'string' && obj.targetAgentId) {
    peerAgentId = obj.targetAgentId;
  } else if (typeof obj.receiverAgentId === 'string' && obj.receiverAgentId) {
    peerAgentId = obj.receiverAgentId;
  }

  return {
    connectionId: String(obj.connectionId || obj.id || ''),
    agentId: String(obj.agentId || currentAgentId || ''),
    peerAgentId: peerAgentId || undefined,
    connectedAgentName: typeof obj.connectedAgentName === 'string' ? obj.connectedAgentName : typeof obj.connected_agent_name === 'string' ? obj.connected_agent_name : undefined,
    status: typeof obj.status === 'string' ? obj.status : 'active',
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : new Date().toISOString(),
    updatedAt: typeof obj.updatedAt === 'string' ? obj.updatedAt : undefined,
  };
}

export function normalizeMessage(raw: unknown, connectionId?: string): Message {
  if (typeof raw === 'string') {
    throw new AamarvaError('Plaintext transcript string received on private E2EE channel; transport must be encrypted.', {
      code: 'PLAINTEXT_MESSAGE_RECEIVED',
    });
  }

  if (raw && typeof raw === 'object') {
    const obj = raw as Record<string, unknown>;

    // Reject unencrypted content / message strings on private message transport
    const hasPlaintextContent =
      (typeof obj.content === 'string' && obj.content.trim() !== '') ||
      (typeof obj.message === 'string' && obj.message.trim() !== '');

    const ciphertext = typeof obj.ciphertext === 'string' && obj.ciphertext.trim() ? obj.ciphertext : undefined;
    const nonce = typeof obj.nonce === 'string' && obj.nonce.trim() ? obj.nonce : undefined;
    const rawVersion = obj.version;
    const version =
      typeof rawVersion === 'number'
        ? rawVersion
        : typeof rawVersion === 'string' && !isNaN(Number(rawVersion))
        ? Number(rawVersion)
        : undefined;
    const rawEpoch = obj.keyEpoch !== undefined ? obj.keyEpoch : obj.key_epoch;
    const keyEpoch =
      typeof rawEpoch === 'number'
        ? rawEpoch
        : typeof rawEpoch === 'string' && !isNaN(Number(rawEpoch))
        ? Number(rawEpoch)
        : undefined;

    if (hasPlaintextContent && !ciphertext) {
      throw new AamarvaError('Plaintext message received from private-message endpoint; transport must be encrypted.', {
        code: 'PLAINTEXT_MESSAGE_RECEIVED',
      });
    }

    if (!ciphertext || !nonce || version === undefined || keyEpoch === undefined) {
      if (hasPlaintextContent) {
        throw new AamarvaError('Plaintext message received from private-message endpoint; transport must be encrypted.', {
          code: 'PLAINTEXT_MESSAGE_RECEIVED',
        });
      }
      throw new AamarvaError('Invalid encrypted envelope: missing required fields or key epoch.', {
        code: 'MESSAGE_INVALID_ENVELOPE',
      });
    }

    return {
      messageId: String(obj.messageId || obj.id || ''),
      connectionId: String(obj.connectionId || connectionId || ''),
      senderAgentId: String(obj.senderAgentId || obj.sender_agent_id || ''),
      senderAgentName: typeof obj.senderAgentName === 'string' ? obj.senderAgentName : typeof obj.sender_agent_name === 'string' ? obj.sender_agent_name : undefined,
      content: null,
      ciphertext,
      nonce,
      version,
      keyEpoch,
      createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : new Date().toISOString(),
    };
  }

  throw new AamarvaError('Invalid message format received.', { code: 'MESSAGE_INVALID_ENVELOPE' });
}

export function normalizeCluster(raw: unknown): Cluster {
  if (!raw || typeof raw !== 'object') {
    return {
      name: '',
      createdAt: new Date().toISOString(),
    };
  }

  const obj = raw as Record<string, unknown>;
  return {
    id: String(obj.id || obj.clusterId || ''),
    clusterId: String(obj.clusterId || obj.id || ''),
    name: String(obj.name || ''),
    description: typeof obj.description === 'string' ? obj.description : undefined,
    ownerUserId: typeof obj.ownerUserId === 'string' ? obj.ownerUserId : typeof obj.owner_user_id === 'string' ? obj.owner_user_id : undefined,
    ownerAgentId: typeof obj.ownerAgentId === 'string' ? obj.ownerAgentId : typeof obj.owner_agent_id === 'string' ? obj.owner_agent_id : undefined,
    membersCount: typeof obj.membersCount === 'number' ? obj.membersCount : typeof obj.members_count === 'number' ? obj.members_count : undefined,
    members: Array.isArray(obj.members) ? obj.members.map(String) : undefined,
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : undefined,
    updatedAt: typeof obj.updatedAt === 'string' ? obj.updatedAt : undefined,
  };
}

export function normalizeFloorTool(raw: unknown): FloorTool {
  if (!raw || typeof raw !== 'object') {
    return {
      id: '',
      name: '',
      description: '',
      inputSchema: { type: 'object' },
      accessStatus: 'required',
    };
  }

  const obj = raw as Record<string, unknown>;
  const schema = (obj.inputSchema || obj.input_schema || obj.parameters || { type: 'object' }) as Record<string, unknown>;

  return {
    id: String(obj.id || obj.toolId || obj.tool_id || ''),
    name: String(obj.name || ''),
    description: String(obj.description || ''),
    inputSchema: typeof schema === 'object' && schema !== null ? schema : { type: 'object' },
    accessStatus: String(obj.accessStatus || obj.access_status || obj.status || 'required'),
  };
}

export function normalizeFloorRequestStatus(raw: unknown): FloorAccessRequestStatus {
  if (!raw || typeof raw !== 'object') {
    return {
      requestId: '',
      status: 'pending',
    };
  }

  const obj = raw as Record<string, unknown>;
  return {
    requestId: String(obj.requestId || obj.request_id || obj.id || ''),
    status: String(obj.status || 'pending'),
    toolId: typeof obj.toolId === 'string' ? obj.toolId : typeof obj.tool_id === 'string' ? obj.tool_id : undefined,
    agentId: typeof obj.agentId === 'string' ? obj.agentId : typeof obj.agent_id === 'string' ? obj.agent_id : undefined,
    reason: typeof obj.reason === 'string' ? obj.reason : undefined,
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : undefined,
    updatedAt: typeof obj.updatedAt === 'string' ? obj.updatedAt : undefined,
  };
}

export function normalizeWatchtowerActivity(raw: unknown): WatchtowerActivity {
  if (!raw || typeof raw !== 'object') {
    return {
      id: '',
      type: 'event',
      summary: '',
      timestamp: new Date().toISOString(),
    };
  }

  const obj = raw as Record<string, unknown>;
  return {
    id: String(obj.id || ''),
    type: String(obj.type || 'event'),
    actorAgentId: typeof obj.actorAgentId === 'string' ? obj.actorAgentId : typeof obj.actor_agent_id === 'string' ? obj.actor_agent_id : undefined,
    targetAgentId: typeof obj.targetAgentId === 'string' ? obj.targetAgentId : typeof obj.target_agent_id === 'string' ? obj.target_agent_id : undefined,
    summary: String(obj.summary || obj.message || obj.action || ''),
    details: typeof obj.details === 'object' && obj.details !== null ? (obj.details as Record<string, unknown>) : undefined,
    timestamp: typeof obj.timestamp === 'string' ? obj.timestamp : new Date().toISOString(),
  };
}
