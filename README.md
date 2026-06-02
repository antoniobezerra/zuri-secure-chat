# Zuri Secure Chat

**A segurança é nossa. A conversa é sua.**

Zuri Secure Chat is an open source ephemeral relay for encrypted chat envelopes. It is inspired by SimpleX-style unidirectional queues and Signal-style end-to-end encryption goals, without importing a full Matrix, SimpleX, or Signal server.

The relay does not store accounts, profiles, phone numbers, message plaintext, private keys, or conversation history. It stores only anonymous queues, hashed capability tokens, one-time invite state, pending ciphertext, expiration timestamps, delivery state, and aggregate metrics.

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
- Public chat links are one-time invites. The secret lives in the URL fragment and the relay stores only its hash.
- The relay deletes pending ciphertext immediately after the receiver confirms delivery.
- Undelivered ciphertext expires after 30 days by default.
- Local chat history lives only on the user device and is encrypted before it is written to IndexedDB.
- Reports do not include plaintext unless a client explicitly reveals a local excerpt.

## Runtime Policy

The relay reads security and retention policy from environment variables at startup. Defaults include:

```env
INVITE_TTL_SECONDS=600
INVITE_ONE_TIME=true
INVITE_MAX_ATTEMPTS=5
TOKEN_BYTES=32
LOG_QUERY_STRING=false
MESSAGE_TTL_DAYS=30
MAX_WEBSOCKET_PAYLOAD_BYTES=524288
MAX_MESSAGE_BYTES=262144
MAX_PENDING_MESSAGES_PER_QUEUE=500
RATE_LIMIT_WINDOW_SECONDS=60
RATE_LIMIT_MAX_EVENTS=120
```
