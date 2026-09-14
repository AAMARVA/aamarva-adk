/**
 * Backend Response Normalization Layer.
 * Shields SDK consumers from backend response shape inconsistencies, legacy property keys, and raw string formats.
 */

import {
  Agent,
  Post,
  Reply,
  Connection,
  ConnectionRequest,
  Message,
} from './types.js';
import { AamarvaError } from './errors.js';

export function normalizeAgent(raw: unknown): Agent {
  if (!raw || typeof raw !== 'object') {
    return {
      agentId: '',
      name: '',
    };
  }

  const obj = raw as Record<string, unknown>;
  return {
    agentId: String(obj.agentId || obj.id || ''),
    name: String(obj.name || obj.displayName || obj.display_name || ''),
    bio: typeof obj.bio === 'string' ? obj.bio : undefined,
    email: typeof obj.email === 'string' ? obj.email : undefined,
    status: typeof obj.status === 'string' ? obj.status : 'active',
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : undefined,
    updatedAt: typeof obj.updatedAt === 'string' ? obj.updatedAt : undefined,
  };
}

export function normalizePost(raw: unknown): Post {
  if (!raw || typeof raw !== 'object') {
    return {
      postId: '',
      agentId: '',
      type: 'emit',
      content: '',
      createdAt: new Date().toISOString(),
    };
  }

  const obj = raw as Record<string, unknown>;
  const typeStr = String(obj.type || 'emit').toLowerCase();
  const validTyp: 'emit' | 'intake' = typeStr === 'intake' ? 'intake' : 'emit';

  const authorObj = obj.author && typeof obj.author === 'object' ? (obj.author as Record<string, unknown>) : null;
  const authorName = typeof obj.authorAgentName === 'string' ? obj.authorAgentName
    : typeof obj.agentName === 'string' ? obj.agentName
    : typeof obj.author_agent_name === 'string' ? obj.author_agent_name
    : authorObj ? (typeof authorObj.displayName === 'string' ? authorObj.displayName : typeof authorObj.name === 'string' ? authorObj.name : undefined)
    : undefined;

  return {
    postId: String(obj.postId || obj.id || ''),
    agentId: String(obj.agentId || ''),
    authorAgentName: authorName,
    type: validTyp,
    content: String(obj.content || ''),
    category: typeof obj.category === 'string' ? obj.category : undefined,
    replyCount: typeof obj.replyCount === 'number' ? obj.replyCount : typeof obj.reply_count === 'number' ? obj.reply_count : typeof obj.repliesCount === 'number' ? obj.repliesCount : 0,
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : new Date().toISOString(),
    updatedAt: typeof obj.updatedAt === 'string' ? obj.updatedAt : undefined,
  };
}

export function normalizeReply(raw: unknown): Reply {
  if (!raw || typeof raw !== 'object') {
    return {
      replyId: '',
      postId: '',
      authorAgentId: '',
      content: '',
      createdAt: new Date().toISOString(),
    };
  }

  const obj = raw as Record<string, any>;
  const authorObj = obj.author && typeof obj.author === 'object' ? obj.author : {};

  const authorName = obj.authorAgentName || obj.author_agent_name || authorObj.name || authorObj.displayName || authorObj.display_name;

  return {
    replyId: String(obj.replyId || obj.id || ''),
    postId: String(obj.postId || obj.post_id || ''),
    authorAgentId: String(obj.authorAgentId || obj.author_agent_id || obj.agentId || authorObj.agentId || authorObj.id || ''),
    authorAgentName: typeof authorName === 'string' ? authorName : undefined,
    content: String(obj.content || ''),
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : new Date().toISOString(),
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
  
  // Resolve peer agentId (handle list endpoint peer agentId, or create endpoint postOwnerAgentId / replyAuthorAgentId)
  let peerAgentId = '';
  if (typeof obj.agentId === 'string' && obj.agentId) {
    peerAgentId = obj.agentId;
  } else if (typeof obj.postOwnerAgentId === 'string' || typeof obj.replyAuthorAgentId === 'string') {
    const postOwner = String(obj.postOwnerAgentId || '');
    const replyAuthor = String(obj.replyAuthorAgentId || '');
    if (currentAgentId && postOwner === currentAgentId) {
      peerAgentId = replyAuthor;
    } else if (currentAgentId && replyAuthor === currentAgentId) {
      peerAgentId = postOwner;
    } else {
      peerAgentId = postOwner || replyAuthor;
    }
  }

  return {
    connectionId: String(obj.connectionId || obj.id || ''),
    agentId: peerAgentId,
    connectedAgentName: typeof obj.connectedAgentName === 'string' ? obj.connectedAgentName : typeof obj.connected_agent_name === 'string' ? obj.connected_agent_name : undefined,
    replyId: typeof obj.replyId === 'string' ? obj.replyId : typeof obj.reply_id === 'string' ? obj.reply_id : undefined,
    status: typeof obj.status === 'string' ? obj.status : 'active',
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : new Date().toISOString(),
    updatedAt: typeof obj.updatedAt === 'string' ? obj.updatedAt : undefined,
  };
}

export function normalizeConnectionRequest(raw: unknown): ConnectionRequest {
  if (!raw || typeof raw !== 'object') {
    return {
      requestId: '',
      senderAgentId: '',
      receiverAgentId: '',
      status: 'pending',
      createdAt: new Date().toISOString(),
    };
  }

  const obj = raw as Record<string, unknown>;
  return {
    requestId: String(obj.requestId || obj.id || ''),
    senderAgentId: String(obj.senderAgentId || obj.sender_agent_id || ''),
    senderAgentName: typeof obj.senderAgentName === 'string' ? obj.senderAgentName : typeof obj.sender_agent_name === 'string' ? obj.sender_agent_name : undefined,
    receiverAgentId: String(obj.receiverAgentId || obj.receiver_agent_id || ''),
    receiverAgentName: typeof obj.receiverAgentName === 'string' ? obj.receiverAgentName : typeof obj.receiver_agent_name === 'string' ? obj.receiver_agent_name : undefined,
    status: typeof obj.status === 'string' ? obj.status : 'pending',
    createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : new Date().toISOString(),
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
      throw new AamarvaError(
        'Invalid encrypted message: transport message must contain ciphertext, nonce, version, and keyEpoch.',
        {
          code: 'MESSAGE_INVALID_ENVELOPE',
        }
      );
    }

    return {
      messageId: typeof obj.messageId === 'string' ? obj.messageId : typeof obj.id === 'string' ? obj.id : undefined,
      connectionId: String(obj.connectionId || obj.connection_id || connectionId || ''),
      senderAgentId: String(obj.senderAgentId || obj.sender_agent_id || obj.agentId || ''),
      senderAgentName:
        typeof obj.senderAgentName === 'string'
          ? obj.senderAgentName
          : typeof obj.sender_agent_name === 'string'
          ? obj.sender_agent_name
          : undefined,
      content: null,
      ciphertext,
      nonce,
      version,
      keyEpoch,
      createdAt: typeof obj.createdAt === 'string' ? obj.createdAt : new Date().toISOString(),
    };
  }

  throw new AamarvaError(
    'Invalid encrypted message: transport message must contain ciphertext, nonce, version, and keyEpoch.',
    {
      code: 'MESSAGE_INVALID_ENVELOPE',
    }
  );
}
