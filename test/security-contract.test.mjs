import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  assertNoPlaintextFields,
  enqueueMessageInputSchema,
  wsClientEventSchema,
} from '../packages/protocol/dist/index.js';

const rootDir = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const validEnvelope = {
  queueId: 'queue_demo_123456789',
  sendToken: 's'.repeat(32),
  clientMessageId: 'client_message_1',
  envelopeVersion: 1,
  ciphertext: 'ciphertext'.repeat(4),
  nonce: 'nonce'.repeat(3),
};

test('relay enqueue contract accepts only opaque encrypted payloads', () => {
  assert.equal(enqueueMessageInputSchema.safeParse(validEnvelope).success, true);

  for (const forbidden of ['text', 'plaintext', 'body', 'message', 'uid1', 'uid2', 'memberUid', 'advertiserUid', 'phone']) {
    assert.throws(() => assertNoPlaintextFields({ ...validEnvelope, [forbidden]: 'leak' }), /forbidden relay field/);
    assert.equal(enqueueMessageInputSchema.safeParse({ ...validEnvelope, [forbidden]: 'leak' }).success, false);
  }
});

test('websocket send contract accepts only opaque encrypted payloads', () => {
  const validWsEnvelope = {
    type: 'message.send',
    ...validEnvelope,
  };

  assert.equal(wsClientEventSchema.safeParse(validWsEnvelope).success, true);

  for (const forbidden of ['text', 'plaintext', 'body', 'message', 'uid1', 'uid2', 'memberUid', 'advertiserUid', 'phone']) {
    assert.throws(() => assertNoPlaintextFields({ ...validWsEnvelope, [forbidden]: 'leak' }), /forbidden relay field/);
    assert.equal(wsClientEventSchema.safeParse({ ...validWsEnvelope, [forbidden]: 'leak' }).success, false);
  }
});

test('relay database schema stores ciphertext, not chat plaintext or direct identities', async () => {
  const schema = (await readFile(join(rootDir, 'infra/schema.sql'), 'utf8')).toLowerCase();

  assert.match(schema, /create table if not exists queued_messages/);
  assert.match(schema, /ciphertext text not null/);
  assert.match(schema, /expires_at timestamptz not null/);
  assert.doesNotMatch(schema, /messages\.text/);
  assert.doesNotMatch(schema, /plaintext/);
  assert.doesNotMatch(schema, /member_uid|advertiser_uid|uid1|uid2|phone/);
});

test('delivered messages are deleted from the relay queue', async () => {
  const server = await readFile(join(rootDir, 'apps/server/src/index.ts'), 'utf8');

  assert.match(server, /DELETE FROM queued_messages/);
  assert.match(server, /deliveredAt/);
});

test('retention worker expires undelivered ciphertext by timestamp', async () => {
  const worker = await readFile(join(rootDir, 'apps/retention-worker/src/index.ts'), 'utf8');

  assert.match(worker, /WHERE expires_at <= now\(\)/);
  assert.match(worker, /expired_count/);
});
