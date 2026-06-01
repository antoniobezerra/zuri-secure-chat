# Zuri Secure Chat

**A segurança é nossa. A conversa é sua.**

Zuri Secure Chat is an open source ephemeral relay for encrypted chat envelopes. It is inspired by SimpleX-style unidirectional queues and Signal-style end-to-end encryption goals, without importing a full Matrix, SimpleX, or Signal server.

The relay does not store accounts, profiles, phone numbers, message plaintext, private keys, or conversation history. It stores only anonymous queues, hashed capability tokens, pending ciphertext, expiration timestamps, delivery state, and aggregate metrics.

## Architecture

- `apps/server`: Fastify relay API.
- `apps/retention-worker`: expires undelivered ciphertext after the configured TTL.
- `apps/demo-web`: PWA demo for local encrypted history and relay flow.
- `packages/protocol`: Zod schemas and shared contracts.
- `packages/web-sdk`: WebCrypto and IndexedDB helpers for PWA clients.
- `infra`: schema and Docker Compose.

## Local Start

```bash
pnpm install
docker compose -f infra/docker-compose.yml up -d postgres redis
pnpm db:migrate
pnpm dev
```

Relay: `http://localhost:4088`

Demo PWA: `http://localhost:5177`

## Privacy Rules

- The relay never receives `uid1`, `uid2`, display name, profile name, phone number, or plaintext.
- The relay deletes pending ciphertext immediately after the receiver confirms delivery.
- Undelivered ciphertext expires after 30 days by default.
- Local chat history lives only on the user device and is encrypted before it is written to IndexedDB.
- Reports do not include plaintext unless a client explicitly reveals a local excerpt.

