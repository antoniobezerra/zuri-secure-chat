import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import {
  assertNoPlaintextFields,
  createReportInputSchema,
  deliveredMessageInputSchema,
  enqueueMessageInputSchema,
  pullMessagesQuerySchema,
  RELAY_PRODUCT,
  type QueuedMessage,
  type WsServerEvent,
  wsClientEventSchema,
  wsOpenInputSchema,
} from '@zuri-secure-chat/protocol';
import Fastify from 'fastify';
import { z } from 'zod';
import type { RawData, WebSocket } from 'ws';
import { Database } from './db.js';
import { incrementMetric } from './metrics.js';
import { bucketHour, capabilityToken, ciphertextHash, relayId, tokenHash } from './security.js';

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
const app = Fastify({ logger: true });
const ttlDays = Number(process.env.MESSAGE_TTL_DAYS ?? 30);
const adminToken = process.env.ADMIN_TOKEN;
const subscribers = new Map<string, Set<WebSocket>>();
const deliveryWatchers = new Map<string, Set<WebSocket>>();

await app.register(websocket, {
  options: {
    maxPayload: 512 * 1024,
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

app.post('/queues', async () => {
  const id = relayId('queue');
  const sendToken = capabilityToken();
  const receiveToken = capabilityToken();
  const result = await db.query<QueueRow>(
    `INSERT INTO queues (id, send_token_hash, receive_token_hash)
     VALUES ($1, $2, $3)
     RETURNING id, status, created_at, send_token_hash, receive_token_hash`,
    [id, tokenHash(sendToken), tokenHash(receiveToken)],
  );
  const row = result.rows[0];

  return {
    data: {
      queueId: id,
      sendToken,
      receiveToken,
      createdAt: iso(row?.created_at),
    },
  };
});

app.post('/messages/enqueue', async (request, reply) => {
  const raw = request.body as Record<string, unknown>;
  assertNoPlaintextFields(raw);
  const input = enqueueMessageInputSchema.parse(raw);
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

async function enqueueMessage(input: z.infer<typeof enqueueMessageInputSchema>) {
  const queue = await getQueueBySendToken(input.queueId, input.sendToken);
  if (!queue) return null;

  const id = relayId('message');
  const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000);
  const bucketAt = bucketHour();
  const byteSize = Buffer.byteLength(input.ciphertext, 'utf8');
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
    [queueId, tokenHash(sendToken)],
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
    [queueId, tokenHash(receiveToken)],
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

function iso(value: Date | string | undefined) {
  if (!value) return new Date().toISOString();
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function isoOrNull(value: Date | string | null | undefined) {
  if (!value) return null;
  return iso(value);
}
