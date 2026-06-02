# Security Model

## Goals

- No conversation plaintext on Zuri servers.
- No private keys on Zuri servers.
- No direct user identifiers in the relay.
- Delete ciphertext after delivery.
- Expire undelivered ciphertext.
- Keep only aggregate metrics.

## Non-Goals For V1

- Full Signal compatibility.
- MLS/group messaging.
- Encrypted binary attachments.
- Server-side message search.
- Server-side conversation recovery.

## V1 Cryptography

The SDK uses WebCrypto for local vault encryption and demo envelope encryption. Production clients should evolve the session layer toward X3DH + Double Ratchet before broad launch.

Passkeys authenticate or unlock device-local state; they do not replace message encryption.

## One-Time Invites

An invite is not a conversation session. It is a temporary entry ticket used to bootstrap the anonymous queues. The create response returns no queue tokens. The server stores only `secret_hash`, `creator_token_hash`, status, attempt count, timestamps, and encrypted temporary bundles while the invite is pending or waiting for creator claim.

Default production policy:

- Invite TTL: `INVITE_TTL_SECONDS=600`.
- Invite usage: `INVITE_ONE_TIME=true`.
- Attempt cap: `INVITE_MAX_ATTEMPTS=5`.
- Public link secret: URL fragment only.
- After acceptance: status becomes `consumed`, the acceptor bundle is cleared, and the creator can claim their encrypted bundle once.

If a copied link is used after acceptance, the relay refuses it. The fragment secret should not appear in logs, admin views, metrics, or query strings.

## Runtime Policy

Operational policy is configured at server startup rather than hardcoded. Important defaults include `MESSAGE_TTL_DAYS=30`, `MAX_WEBSOCKET_PAYLOAD_BYTES=524288`, `MAX_MESSAGE_BYTES=262144`, `MAX_PENDING_MESSAGES_PER_QUEUE=500`, `RATE_LIMIT_WINDOW_SECONDS=60`, and `RATE_LIMIT_MAX_EVENTS=120`.
