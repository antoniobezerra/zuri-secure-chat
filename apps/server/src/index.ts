import cors from '@fastify/cors';
import {
  assertNoPlaintextFields,
  createReportInputSchema,
  deliveredMessageInputSchema,
  enqueueMessageInputSchema,
  pullMessagesQuerySchema,
  RELAY_PRODUCT,
  type QueuedMessage,
} from '@zuri-secure-chat/protocol';
import Fastify from 'fastify';
import { z } from 'zod';
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
  const queue = await getQueueBySendToken(input.queueId, input.sendToken);

  if (!queue) {
    return reply.code(403).send({ error: 'Invalid queue capability.' });
  }

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

  return {
    data: mapMessage(result.rows[0]),
    integrity: {
      ciphertextHash: ciphertextHash(input.ciphertext),
    },
  };
});

app.get('/messages/pull', async (request, reply) => {
  const query = pullMessagesQuerySchema.parse(request.query);
  const queue = await getQueueByReceiveToken(query.queueId, query.receiveToken);

  if (!queue) {
    return reply.code(403).send({ error: 'Invalid queue capability.' });
  }

  const result = await db.query<MessageRow>(
    `SELECT id, queue_id, client_message_id, envelope_version, ciphertext, nonce, byte_size, created_at, expires_at
     FROM queued_messages
     WHERE queue_id = $1 AND expires_at > now()
     ORDER BY created_at ASC
     LIMIT $2`,
    [query.queueId, query.limit],
  );

  return {
    data: result.rows.map(mapMessage),
    page: {
      limit: query.limit,
      nextCursor: null,
    },
  };
});

app.post('/messages/:id/delivered', async (request, reply) => {
  const params = z.object({ id: z.string().min(1) }).parse(request.params);
  const input = deliveredMessageInputSchema.parse(request.body);
  const queue = await getQueueByReceiveToken(input.queueId, input.receiveToken);

  if (!queue) {
    return reply.code(403).send({ error: 'Invalid queue capability.' });
  }

  const result = await db.query<MessageRow>(
    `DELETE FROM queued_messages
     WHERE id = $1 AND queue_id = $2
     RETURNING id, queue_id, client_message_id, envelope_version, ciphertext, nonce, byte_size, created_at, expires_at`,
    [params.id, input.queueId],
  );
  const deleted = result.rows[0];

  if (!deleted) {
    return reply.code(404).send({ error: 'Message not found.' });
  }

  await incrementMetric(db, input.queueId, bucketHour(new Date(deleted.created_at)), 'delivered_count');

  return {
    data: {
      id: deleted.id,
      deleted: true,
      deliveredAt: new Date().toISOString(),
    },
  };
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

process.once('SIGTERM', async () => {
  await db.close();
  process.exit(0);
});

const port = Number(process.env.CHAT_RELAY_PORT ?? 4088);
await app.listen({ port, host: '0.0.0.0' });

async function getQueueBySendToken(queueId: string, sendToken: string) {
  const result = await db.query<QueueRow>(
    `SELECT id, send_token_hash, receive_token_hash, status, created_at
     FROM queues
     WHERE id = $1 AND send_token_hash = $2 AND status = 'active'`,
    [queueId, tokenHash(sendToken)],
  );

  return result.rows[0];
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

function iso(value: Date | string | undefined) {
  if (!value) return new Date().toISOString();
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

