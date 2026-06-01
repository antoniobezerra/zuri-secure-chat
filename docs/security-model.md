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

