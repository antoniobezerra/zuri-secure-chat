import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import {
  acceptInviteInputSchema,
  assertNoPlaintextFields,
  claimInviteInputSchema,
  createReportInputSchema,
  deliveredMessageInputSchema,
  enqueueMessageInputSchema,
  pullMessagesQuerySchema,
  RELAY_PRODUCT,
  type RelayConnectionBundle,
  type QueuedMessage,
  type WsServerEvent,
  wsClientEventSchema,
  wsOpenInputSchema,
} from '@zuri-secure-chat/protocol';
import Fastify from 'fastify';
import { z } from 'zod';
import type { RawData, WebSocket } from 'ws';
import { serverConfig } from './config.js';
import { Database } from './db.js';
import { incrementMetric } from './metrics.js';
import {
  bucketHour,
  capabilityToken,
  ciphertextHash,
  decryptJsonWithSecret,
  encryptJsonWithSecret,
  relayId,
  tokenHash,
} from './security.js';

type QueueRow = {
  id: string;
  send_token_hash: string;
  receive_token_hash: string;
  status: string;
  created_at: Date | string;
};

type MessageRow = {
  id: string;
  queue_id: string;
  client_message_id: string | null;
  envelope_version: number;
  ciphertext: string;
  nonce: string | null;
  byte_size: number;
  created_at: Date | string;
  expires_at: Date | string;
};

type InviteRow = {
  id: string;
  secret_hash: string;
  creator_token_hash: string | null;
  status: 'pending' | 'consumed' | 'expired' | 'revoked';
  attempt_count: number;
  bundle_ciphertext: string | null;
  bundle_nonce: string | null;
  creator_bundle_ciphertext: string | null;
  creator_bundle_nonce: string | null;
  created_at: Date | string;
  expires_at: Date | string;
  consumed_at: Date | string | null;
  creator_claimed_at: Date | string | null;
  revoked_at: Date | string | null;
};

type AdminQueueRow = {
  queue_id: string;
  status: string;
  created_at: Date | string;
  pending_count: string | number;
  pending_bytes: string | number | null;
  oldest_pending_at: Date | string | null;
  newest_pending_at: Date | string | null;
  expires_next_at: Date | string | null;
};

type AdminMessageRow = {
  id: string;
  queue_id: string;
  client_message_id: string | null;
  envelope_version: number;
  ciphertext: string;
  byte_size: number;
  created_at: Date | string;
  expires_at: Date | string;
};

type MetricRow = {
  bucket_at: Date | string;
  metric_hash: string;
  enqueued_count: number;
  delivered_count: number;
  expired_count: number;
};

const db = new Database();
const app = Fastify({
  logger: {
    serializers: {
      req(request) {
        const url = serverConfig.logQueryString ? request.url : request.url.split('?')[0];
        return {
          method: request.method,
          url,
          hostname: request.hostname,
          remoteAddress: serverConfig.ipLogRetentionHours > 0 ? request.ip : undefined,
        };
      },
    },
  },
});
const adminToken = serverConfig.adminToken;
const subscribers = new Map<string, Set<WebSocket>>();
const deliveryWatchers = new Map<string, Set<WebSocket>>();
const rateLimits = new Map<string, { resetAt: number; count: number }>();

await app.register(websocket, {
  options: {
    maxPayload: serverConfig.maxWebsocketPayloadBytes,
  },
});
await app.register(cors, {
  origin: true,
});

app.get('/health', async () => ({
  status: 'ok',
  product: RELAY_PRODUCT.publicName,
  database: await db.health(),
  time: new Date().toISOString(),
}));

app.post('/invites', async (request, reply) => {
  if (!checkRateLimit(`invite:create:${request.ip}`)) return reply.code(429).send({ error: 'Rate limit exceeded.' });

  const invite = await createInvite();
  return {
    data: invite,
  };
});

app.post('/invites/:id/accept', async (request, reply) => {
  const params = z.object({ id: z.string().min(8).max(160) }).parse(request.params);
  const input = acceptInviteInputSchema.parse(request.body);
  if (!checkRateLimit(`invite:accept:${request.ip}:${params.id}`)) {
    return reply.code(429).send({ error: 'Rate limit exceeded.' });
  }

  const accepted = await acceptInvite(params.id, input.inviteSecret);
  if (accepted.kind === 'ok') {
    return {
      data: accepted.data,
    };
  }

  return reply.code(accepted.statusCode).send({ error: accepted.message });
});

app.post('/invites/:id/claim', async (request, reply) => {
  const params = z.object({ id: z.string().min(8).max(160) }).parse(request.params);
  const input = claimInviteInputSchema.parse(request.body);
  if (!checkRateLimit(`invite:claim:${request.ip}:${params.id}`)) {
    return reply.code(429).send({ error: 'Rate limit exceeded.' });
  }

  const claimed = await claimInvite(params.id, input.creatorClaimToken);
  if (claimed.kind === 'ok') {
    return {
      data: claimed.data,
    };
  }

  return reply.code(claimed.statusCode).send({ error: claimed.message });
});

app.post('/invites/:id/revoke', async (request, reply) => {
  if (!authorizeAdmin(request.headers['x-admin-token'])) {
    return reply.code(401).send({ error: 'Invalid admin token.' });
  }
  const params = z.object({ id: z.string().min(8).max(160) }).parse(request.params);
  const result = await db.query<InviteRow>(
    `UPDATE chat_invites
     SET status = 'revoked', revoked_at = now(), bundle_ciphertext = NULL, bundle_nonce = NULL,
       creator_bundle_ciphertext = NULL, creator_bundle_nonce = NULL
     WHERE id = $1 AND status = 'pending'
     RETURNING id, secret_hash, creator_token_hash, status, attempt_count, bundle_ciphertext, bundle_nonce,
       creator_bundle_ciphertext, creator_bundle_nonce, created_at, expires_at, consumed_at, creator_claimed_at, revoked_at`,
    [params.id],
  );
  const row = result.rows[0];
  if (!row) return reply.code(404).send({ error: 'Invite not found or not pending.' });
  return {
    data: {
      inviteId: row.id,
      status: row.status,
      revokedAt: iso(row.revoked_at ?? new Date().toISOString()),
    },
  };
});

app.post('/queues', async (request, reply) => {
  if (!checkRateLimit(`queue:create:${request.ip}`)) return reply.code(429).send({ error: 'Rate limit exceeded.' });
  const queue = await createQueue();
  return {
    data: queue,
  };
});

app.post('/messages/enqueue', async (request, reply) => {
  const raw = request.body as Record<string, unknown>;
  assertNoPlaintextFields(raw);
  const input = enqueueMessageInputSchema.parse(raw);
  if (!checkRateLimit(`message:send:${request.ip}:${input.queueId}`)) {
    return reply.code(429).send({ error: 'Rate limit exceeded.' });
  }
  const message = await enqueueMessage(input);
  if (!message) return reply.code(403).send({ error: 'Invalid queue capability.' });
  notifyQueue(message.queueId, message);

  return {
    data: message,
    integrity: {
      ciphertextHash: ciphertextHash(input.ciphertext),
    },
  };
});

app.get('/messages/pull', async (request, reply) => {
  const query = pullMessagesQuerySchema.parse(request.query);
  const messages = await pullMessages(query.queueId, query.receiveToken, query.limit);
  if (!messages) return reply.code(403).send({ error: 'Invalid queue capability.' });

  return {
    data: messages,
    page: {
      limit: query.limit,
      nextCursor: null,
    },
  };
});

app.post('/messages/:id/delivered', async (request, reply) => {
  const params = z.object({ id: z.string().min(1) }).parse(request.params);
  const input = deliveredMessageInputSchema.parse(request.body);
  const delivered = await markDelivered(params.id, input.queueId, input.receiveToken);
  if (delivered === 'forbidden') return reply.code(403).send({ error: 'Invalid queue capability.' });
  if (!delivered) return reply.code(404).send({ error: 'Message not found.' });
  notifyDelivered(delivered);

  return {
    data: {
      id: delivered.message.id,
      deleted: true,
      deliveredAt: delivered.deliveredAt,
    },
  };
});

app.get('/ws', { websocket: true }, (socket, request) => {
  const open = wsOpenInputSchema.safeParse(request.query);
  if (!open.success) {
    sendWs(socket, { type: 'error', message: 'Invalid websocket query.' });
    socket.close(1008, 'Invalid websocket query');
    return;
  }

  let opened = false;
  const subscription = authorizeWs(open.data.queueId, open.data.receiveToken)
    .then(async (authorized) => {
      if (!authorized) {
        sendWs(socket, { type: 'error', message: 'Invalid queue capability.' });
        socket.close(1008, 'Invalid queue capability');
        return;
      }

      opened = true;
      addSubscriber(open.data.queueId, socket);
      const pending = await pullMessages(open.data.queueId, open.data.receiveToken, 100);
      sendWs(socket, { type: 'ready', queueId: open.data.queueId, pending: pending?.length ?? 0 });
      for (const message of pending ?? []) {
        sendWs(socket, { type: 'message.deliver', message });
      }
    })
    .catch((error) => {
      app.log.error({ error }, 'websocket open failed');
      sendWs(socket, { type: 'error', message: 'Could not open websocket.' });
      socket.close(1011, 'Could not open websocket');
    });

  socket.on('message', (raw) => {
    void handleWsMessage(socket, raw, subscription);
  });
  socket.on('close', () => {
    if (opened) removeSubscriber(open.data.queueId, socket);
    removeSocketWatchers(socket);
  });
});

app.post('/reports', async (request) => {
  const input = createReportInputSchema.parse(request.body);
  const id = relayId('report');
  const result = await db.query(
    `INSERT INTO reports (
       id, queue_id, reason, public_context_ref, approximate_event_at, evidence_ciphertext_hash
     )
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, queue_id, reason, public_context_ref, approximate_event_at, evidence_ciphertext_hash, created_at`,
    [
      id,
      input.queueId ?? null,
      input.reason,
      input.publicContextRef ?? null,
      input.approximateEventAt ?? null,
      input.evidenceCiphertextHash ?? null,
    ],
  );

  return {
    data: result.rows[0],
    plaintextIncluded: false,
  };
});

app.get('/metrics/hourly', async () => {
  const result = await db.query<MetricRow>(
    `SELECT bucket_at, metric_hash, enqueued_count, delivered_count, expired_count
     FROM hourly_metrics
     ORDER BY bucket_at DESC
     LIMIT 200`,
  );

  return {
    data: result.rows.map((row) => ({
      bucketAt: iso(row.bucket_at),
      metricHash: row.metric_hash,
      enqueuedCount: row.enqueued_count,
      deliveredCount: row.delivered_count,
      expiredCount: row.expired_count,
    })),
  };
});

app.get('/admin/overview', async (request, reply) => {
  if (!authorizeAdmin(request.headers['x-admin-token'])) {
    return reply.code(401).send({ error: 'Invalid admin token.' });
  }

  const queueResult = await db.query<AdminQueueRow>(
    `SELECT
       q.id AS queue_id,
       q.status,
       q.created_at,
       count(m.id) AS pending_count,
       coalesce(sum(m.byte_size), 0) AS pending_bytes,
       min(m.created_at) AS oldest_pending_at,
       max(m.created_at) AS newest_pending_at,
       min(m.expires_at) AS expires_next_at
     FROM queues q
     LEFT JOIN queued_messages m ON m.queue_id = q.id AND m.expires_at > now()
     GROUP BY q.id, q.status, q.created_at
     ORDER BY pending_count DESC, q.created_at DESC
     LIMIT 200`,
  );
  const recentResult = await db.query<AdminMessageRow>(
    `SELECT id, queue_id, client_message_id, envelope_version, ciphertext, byte_size, created_at, expires_at
     FROM queued_messages
     WHERE expires_at > now()
     ORDER BY created_at DESC
     LIMIT 80`,
  );
  const metricResult = await db.query<MetricRow>(
    `SELECT bucket_at, metric_hash, enqueued_count, delivered_count, expired_count
     FROM hourly_metrics
     ORDER BY bucket_at DESC
     LIMIT 48`,
  );

  const queues = queueResult.rows.map(mapAdminQueue);
  const pendingMessages = recentResult.rows.map(mapAdminMessage);
  const totals = queues.reduce(
    (acc, queue) => ({
      queues: acc.queues + 1,
      activeQueues: acc.activeQueues + (queue.status === 'active' ? 1 : 0),
      pendingMessages: acc.pendingMessages + queue.pendingCount,
      pendingBytes: acc.pendingBytes + queue.pendingBytes,
    }),
    { queues: 0, activeQueues: 0, pendingMessages: 0, pendingBytes: 0 },
  );

  return {
    data: {
      generatedAt: new Date().toISOString(),
      relayStoresPlaintext: false,
      totals,
      queues,
      pendingMessages,
      hourlyMetrics: metricResult.rows.map((row) => ({
        bucketAt: iso(row.bucket_at),
        metricHash: row.metric_hash,
        enqueuedCount: row.enqueued_count,
        deliveredCount: row.delivered_count,
        expiredCount: row.expired_count,
      })),
    },
  };
});

process.once('SIGTERM', async () => {
  await db.close();
  process.exit(0);
});

const port = Number(process.env.CHAT_RELAY_PORT ?? 4088);
await app.listen({ port, host: '0.0.0.0' });

async function createQueue() {
  const id = relayId('queue');
  const sendToken = capabilityToken(serverConfig.tokenBytes);
  const receiveToken = capabilityToken(serverConfig.tokenBytes);
  const result = await db.query<QueueRow>(
    `INSERT INTO queues (id, send_token_hash, receive_token_hash)
     VALUES ($1, $2, $3)
     RETURNING id, status, created_at, send_token_hash, receive_token_hash`,
    [id, tokenHash(sendToken, serverConfig.hashPepper), tokenHash(receiveToken, serverConfig.hashPepper)],
  );
  const row = result.rows[0];

  return {
    queueId: id,
    sendToken,
    receiveToken,
    createdAt: iso(row?.created_at),
  };
}

async function createInvite() {
  const inviteId = relayId('invite');
  const inviteSecret = capabilityToken(serverConfig.tokenBytes);
  const creatorClaimToken = capabilityToken(serverConfig.tokenBytes);
  const bundle: RelayConnectionBundle = {
    aToB: await createQueue(),
    bToA: await createQueue(),
  };
  const encryptedBundle = encryptJsonWithSecret(bundle, inviteSecret, serverConfig.hashPepper);
  const encryptedCreatorBundle = encryptJsonWithSecret(bundle, creatorClaimToken, serverConfig.hashPepper);
  const expiresAt = new Date(Date.now() + serverConfig.inviteTtlSeconds * 1000);
  const result = await db.query<InviteRow>(
    `INSERT INTO chat_invites (
       id, secret_hash, creator_token_hash, status, attempt_count, bundle_ciphertext, bundle_nonce,
       creator_bundle_ciphertext, creator_bundle_nonce, expires_at
     )
     VALUES ($1, $2, $3, 'pending', 0, $4, $5, $6, $7, $8)
     RETURNING id, secret_hash, creator_token_hash, status, attempt_count, bundle_ciphertext, bundle_nonce,
       creator_bundle_ciphertext, creator_bundle_nonce, created_at, expires_at, consumed_at, creator_claimed_at, revoked_at`,
    [
      inviteId,
      tokenHash(inviteSecret, serverConfig.hashPepper),
      tokenHash(creatorClaimToken, serverConfig.hashPepper),
      encryptedBundle.ciphertext,
      encryptedBundle.nonce,
      encryptedCreatorBundle.ciphertext,
      encryptedCreatorBundle.nonce,
      expiresAt.toISOString(),
    ],
  );
  const row = result.rows[0];

  return {
    inviteId,
    inviteSecret,
    creatorClaimToken,
    status: row?.status ?? 'pending',
    createdAt: iso(row?.created_at),
    expiresAt: iso(row?.expires_at),
  };
}

async function acceptInvite(inviteId: string, inviteSecret: string) {
  const currentResult = await db.query<InviteRow>(
    `SELECT id, secret_hash, creator_token_hash, status, attempt_count, bundle_ciphertext, bundle_nonce,
       creator_bundle_ciphertext, creator_bundle_nonce, created_at, expires_at, consumed_at, creator_claimed_at, revoked_at
     FROM chat_invites
     WHERE id = $1`,
    [inviteId],
  );
  const invite = currentResult.rows[0];
  if (!invite) return inviteError(404, 'Invite not found.');

  if (invite.status === 'consumed') return inviteError(409, 'Invite already used.');
  if (invite.status === 'revoked') return inviteError(410, 'Invite revoked.');
  if (invite.status === 'expired' || new Date(invite.expires_at).getTime() <= Date.now()) {
    await expireInvite(invite.id);
    return inviteError(410, 'Invite expired.');
  }
  if (invite.attempt_count >= serverConfig.inviteMaxAttempts) return inviteError(429, 'Invite attempt limit exceeded.');

  if (invite.secret_hash !== tokenHash(inviteSecret, serverConfig.hashPepper)) {
    await db.query(`UPDATE chat_invites SET attempt_count = attempt_count + 1 WHERE id = $1`, [invite.id]);
    return inviteError(403, 'Invalid invite secret.');
  }
  const consumeResult = await db.query<InviteRow>(
    `UPDATE chat_invites
     SET status = $3, consumed_at = now(),
       bundle_ciphertext = CASE WHEN $4::boolean THEN NULL ELSE bundle_ciphertext END,
       bundle_nonce = CASE WHEN $4::boolean THEN NULL ELSE bundle_nonce END
     WHERE id = $1
       AND secret_hash = $2
       AND status = 'pending'
       AND expires_at > now()
       AND attempt_count < $5
       AND bundle_ciphertext IS NOT NULL
       AND bundle_nonce IS NOT NULL
     RETURNING id, secret_hash, creator_token_hash, status, attempt_count, bundle_ciphertext, bundle_nonce,
       creator_bundle_ciphertext, creator_bundle_nonce, created_at, expires_at, consumed_at, creator_claimed_at, revoked_at`,
    [
      invite.id,
      tokenHash(inviteSecret, serverConfig.hashPepper),
      serverConfig.inviteOneTime ? 'consumed' : 'pending',
      serverConfig.inviteOneTime,
      serverConfig.inviteMaxAttempts,
    ],
  );
  const consumed = consumeResult.rows[0];
  if (!consumed) return inviteError(409, 'Invite already used.');
  const bundleCiphertext = consumed.bundle_ciphertext ?? invite.bundle_ciphertext;
  const bundleNonce = consumed.bundle_nonce ?? invite.bundle_nonce;
  if (!bundleCiphertext || !bundleNonce) return inviteError(410, 'Invite bundle unavailable.');

  const bundle = decryptJsonWithSecret<RelayConnectionBundle>(
    bundleCiphertext,
    bundleNonce,
    inviteSecret,
    serverConfig.hashPepper,
  );

  return {
    kind: 'ok' as const,
    data: {
      inviteId: invite.id,
      status: 'consumed' as const,
      consumedAt: iso(consumed.consumed_at ?? new Date().toISOString()),
      bundle,
    },
  };
}

async function claimInvite(inviteId: string, creatorClaimToken: string) {
  const currentResult = await db.query<InviteRow>(
    `SELECT id, secret_hash, creator_token_hash, status, attempt_count, bundle_ciphertext, bundle_nonce,
       creator_bundle_ciphertext, creator_bundle_nonce, created_at, expires_at, consumed_at, creator_claimed_at, revoked_at
     FROM chat_invites
     WHERE id = $1`,
    [inviteId],
  );
  const invite = currentResult.rows[0];
  if (!invite) return inviteError(404, 'Invite not found.');
  if (invite.status === 'pending') return inviteError(409, 'Invite not accepted yet.');
  if (invite.status === 'expired') return inviteError(410, 'Invite expired.');
  if (invite.status === 'revoked') return inviteError(410, 'Invite revoked.');
  if (invite.creator_claimed_at) return inviteError(409, 'Invite bundle already claimed.');
  if (!invite.creator_token_hash || invite.creator_token_hash !== tokenHash(creatorClaimToken, serverConfig.hashPepper)) {
    return inviteError(403, 'Invalid creator claim token.');
  }
  if (!invite.creator_bundle_ciphertext || !invite.creator_bundle_nonce) {
    return inviteError(410, 'Invite bundle unavailable.');
  }

  const claimResult = await db.query<InviteRow>(
    `UPDATE chat_invites
     SET creator_claimed_at = now(), creator_bundle_ciphertext = NULL, creator_bundle_nonce = NULL
     WHERE id = $1
       AND status = 'consumed'
       AND creator_token_hash = $2
       AND creator_claimed_at IS NULL
       AND creator_bundle_ciphertext IS NOT NULL
       AND creator_bundle_nonce IS NOT NULL
     RETURNING id, secret_hash, creator_token_hash, status, attempt_count, bundle_ciphertext, bundle_nonce,
       creator_bundle_ciphertext, creator_bundle_nonce, created_at, expires_at, consumed_at, creator_claimed_at, revoked_at`,
    [invite.id, tokenHash(creatorClaimToken, serverConfig.hashPepper)],
  );
  const claimed = claimResult.rows[0];
  if (!claimed) return inviteError(409, 'Invite bundle already claimed.');
  const bundle = decryptJsonWithSecret<RelayConnectionBundle>(
    invite.creator_bundle_ciphertext,
    invite.creator_bundle_nonce,
    creatorClaimToken,
    serverConfig.hashPepper,
  );

  return {
    kind: 'ok' as const,
    data: {
      inviteId: invite.id,
      status: 'consumed' as const,
      claimedAt: iso(claimed.creator_claimed_at ?? new Date().toISOString()),
      bundle,
    },
  };
}

function inviteError(statusCode: number, message: string) {
  return {
    kind: 'error' as const,
    statusCode,
    message,
  };
}

async function expireInvite(inviteId: string) {
  await db.query(
    `UPDATE chat_invites
     SET status = 'expired', bundle_ciphertext = NULL, bundle_nonce = NULL,
       creator_bundle_ciphertext = NULL, creator_bundle_nonce = NULL
     WHERE id = $1 AND status = 'pending'`,
    [inviteId],
  );
}

async function enqueueMessage(input: z.infer<typeof enqueueMessageInputSchema>) {
  const queue = await getQueueBySendToken(input.queueId, input.sendToken);
  if (!queue) return null;

  const byteSize = Buffer.byteLength(input.ciphertext, 'utf8');
  if (byteSize > serverConfig.maxMessageBytes) return null;
  if (!(await canQueueMoreMessages(input.queueId))) return null;

  const id = relayId('message');
  const expiresAt = new Date(Date.now() + serverConfig.messageTtlDays * 24 * 60 * 60 * 1000);
  const bucketAt = bucketHour();
  const result = await db.query<MessageRow>(
    `INSERT INTO queued_messages (
       id, queue_id, client_message_id, envelope_version, ciphertext, nonce, byte_size, expires_at
     )
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, queue_id, client_message_id, envelope_version, ciphertext, nonce, byte_size, created_at, expires_at`,
    [
      id,
      input.queueId,
      input.clientMessageId ?? null,
      input.envelopeVersion,
      input.ciphertext,
      input.nonce ?? null,
      byteSize,
      expiresAt.toISOString(),
    ],
  );

  await incrementMetric(db, input.queueId, bucketAt, 'enqueued_count');
  return mapMessage(result.rows[0]);
}

async function pullMessages(queueId: string, receiveToken: string, limit: number) {
  const queue = await getQueueByReceiveToken(queueId, receiveToken);
  if (!queue) return null;

  const result = await db.query<MessageRow>(
    `SELECT id, queue_id, client_message_id, envelope_version, ciphertext, nonce, byte_size, created_at, expires_at
     FROM queued_messages
     WHERE queue_id = $1 AND expires_at > now()
     ORDER BY created_at ASC
     LIMIT $2`,
    [queueId, limit],
  );

  return result.rows.map(mapMessage).filter((message): message is QueuedMessage => Boolean(message));
}

async function canQueueMoreMessages(queueId: string) {
  const result = await db.query<{ pending_count: string | number }>(
    `SELECT count(*) AS pending_count
     FROM queued_messages
     WHERE queue_id = $1 AND expires_at > now()`,
    [queueId],
  );
  return Number(result.rows[0]?.pending_count ?? 0) < serverConfig.maxPendingMessagesPerQueue;
}

async function markDelivered(messageId: string, queueId: string, receiveToken: string) {
  const queue = await getQueueByReceiveToken(queueId, receiveToken);
  if (!queue) return 'forbidden' as const;

  const result = await db.query<MessageRow>(
    `DELETE FROM queued_messages
     WHERE id = $1 AND queue_id = $2
     RETURNING id, queue_id, client_message_id, envelope_version, ciphertext, nonce, byte_size, created_at, expires_at`,
    [messageId, queueId],
  );
  const deleted = result.rows[0];
  if (!deleted) return null;

  await incrementMetric(db, queueId, bucketHour(new Date(deleted.created_at)), 'delivered_count');
  const message = mapMessage(deleted);
  if (!message) return null;
  return {
    message,
    deliveredAt: new Date().toISOString(),
  };
}

async function authorizeWs(queueId: string, receiveToken: string) {
  return Boolean(await getQueueByReceiveToken(queueId, receiveToken));
}

async function handleWsMessage(socket: WebSocket, raw: RawData, subscription: Promise<void>) {
  await subscription;
  if (socket.readyState !== socket.OPEN) return;

  try {
    const parsed = JSON.parse(raw.toString()) as Record<string, unknown>;
    if (parsed.type === 'message.send') assertNoPlaintextFields(parsed);
    const event = wsClientEventSchema.parse(parsed);

    if (event.type === 'ping') {
      sendWs(socket, { type: 'pong', at: new Date().toISOString() });
      return;
    }

    if (event.type === 'message.send') {
      if (!checkRateLimit(`ws:send:${event.queueId}`)) {
        sendWs(socket, { type: 'error', message: 'Rate limit exceeded.' });
        return;
      }
      const message = await enqueueMessage(event);
      if (!message) {
        sendWs(socket, { type: 'error', message: 'Invalid queue capability.' });
        return;
      }
      watchDelivery(message.id, socket);
      sendWs(socket, {
        type: 'message.stored',
        clientMessageId: event.clientMessageId,
        messageId: message.id,
        queueId: message.queueId,
        createdAt: message.createdAt,
      });
      notifyQueue(message.queueId, message);
      return;
    }

    const delivered = await markDelivered(event.messageId, event.queueId, event.receiveToken);
    if (delivered === 'forbidden') {
      sendWs(socket, { type: 'error', message: 'Invalid queue capability.' });
      return;
    }
    if (!delivered) {
      sendWs(socket, { type: 'error', message: 'Message not found.' });
      return;
    }
    sendWs(socket, {
      type: 'message.deleted',
      messageId: delivered.message.id,
      queueId: delivered.message.queueId,
      deliveredAt: delivered.deliveredAt,
    });
    notifyDelivered(delivered);
  } catch (error) {
    app.log.warn({ error }, 'invalid websocket event');
    sendWs(socket, { type: 'error', message: 'Invalid websocket event.' });
  }
}

async function getQueueBySendToken(queueId: string, sendToken: string) {
  const result = await db.query<QueueRow>(
    `SELECT id, send_token_hash, receive_token_hash, status, created_at
     FROM queues
     WHERE id = $1 AND send_token_hash = $2 AND status = 'active'`,
    [queueId, tokenHash(sendToken, serverConfig.hashPepper)],
  );

  return result.rows[0];
}

function addSubscriber(queueId: string, socket: WebSocket) {
  const current = subscribers.get(queueId) ?? new Set<WebSocket>();
  current.add(socket);
  subscribers.set(queueId, current);
}

function removeSubscriber(queueId: string, socket: WebSocket) {
  const current = subscribers.get(queueId);
  if (!current) return;
  current.delete(socket);
  if (!current.size) subscribers.delete(queueId);
}

function watchDelivery(messageId: string, socket: WebSocket) {
  const current = deliveryWatchers.get(messageId) ?? new Set<WebSocket>();
  current.add(socket);
  deliveryWatchers.set(messageId, current);
}

function removeSocketWatchers(socket: WebSocket) {
  for (const [messageId, sockets] of deliveryWatchers) {
    sockets.delete(socket);
    if (!sockets.size) deliveryWatchers.delete(messageId);
  }
}

function notifyQueue(queueId: string, message: QueuedMessage | undefined) {
  if (!message) return;
  for (const socket of subscribers.get(queueId) ?? []) {
    sendWs(socket, { type: 'message.deliver', message });
  }
}

function notifyDelivered(delivered: { message: QueuedMessage; deliveredAt: string }) {
  const sockets = deliveryWatchers.get(delivered.message.id);
  if (!sockets) return;
  for (const socket of sockets) {
    sendWs(socket, {
      type: 'message.delivered',
      clientMessageId: delivered.message.clientMessageId,
      messageId: delivered.message.id,
      queueId: delivered.message.queueId,
      deliveredAt: delivered.deliveredAt,
    });
  }
  deliveryWatchers.delete(delivered.message.id);
}

function sendWs(socket: WebSocket, event: WsServerEvent) {
  if (socket.readyState !== socket.OPEN) return;
  socket.send(JSON.stringify(event));
}

async function getQueueByReceiveToken(queueId: string, receiveToken: string) {
  const result = await db.query<QueueRow>(
    `SELECT id, send_token_hash, receive_token_hash, status, created_at
     FROM queues
     WHERE id = $1 AND receive_token_hash = $2 AND status = 'active'`,
    [queueId, tokenHash(receiveToken, serverConfig.hashPepper)],
  );

  return result.rows[0];
}

function mapMessage(row: MessageRow | undefined): QueuedMessage | undefined {
  if (!row) return undefined;

  return {
    id: row.id,
    queueId: row.queue_id,
    clientMessageId: row.client_message_id ?? undefined,
    envelopeVersion: row.envelope_version,
    ciphertext: row.ciphertext,
    nonce: row.nonce ?? undefined,
    byteSize: row.byte_size,
    createdAt: iso(row.created_at),
    expiresAt: iso(row.expires_at),
  };
}

function mapAdminQueue(row: AdminQueueRow) {
  return {
    queueId: row.queue_id,
    status: row.status,
    createdAt: iso(row.created_at),
    pendingCount: Number(row.pending_count),
    pendingBytes: Number(row.pending_bytes ?? 0),
    oldestPendingAt: isoOrNull(row.oldest_pending_at),
    newestPendingAt: isoOrNull(row.newest_pending_at),
    expiresNextAt: isoOrNull(row.expires_next_at),
  };
}

function mapAdminMessage(row: AdminMessageRow) {
  return {
    id: row.id,
    queueId: row.queue_id,
    clientMessageId: row.client_message_id ?? undefined,
    envelopeVersion: row.envelope_version,
    ciphertextHash: ciphertextHash(row.ciphertext),
    byteSize: row.byte_size,
    createdAt: iso(row.created_at),
    expiresAt: iso(row.expires_at),
  };
}

function authorizeAdmin(input: string | string[] | undefined) {
  if (!adminToken) return process.env.NODE_ENV !== 'production';
  const token = Array.isArray(input) ? input[0] : input;
  return token === adminToken;
}

function checkRateLimit(key: string) {
  const now = Date.now();
  const current = rateLimits.get(key);
  if (!current || current.resetAt <= now) {
    rateLimits.set(key, {
      count: 1,
      resetAt: now + serverConfig.rateLimitWindowSeconds * 1000,
    });
    return true;
  }
  current.count += 1;
  return current.count <= serverConfig.rateLimitMaxEvents;
}

function iso(value: Date | string | undefined) {
  if (!value) return new Date().toISOString();
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function isoOrNull(value: Date | string | null | undefined) {
  if (!value) return null;
  return iso(value);
}
