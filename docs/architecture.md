# Architecture

Zuri Secure Chat is a relay, not a social or account system.

The Zuri Core product authorizes a chat intent between a member and an advertiser. The relay receives only opaque queues and capability tokens. A relay operator should not be able to infer the Zuri account pair from relay tables alone.

## Runtime Boundaries

- Zuri Core knows product identity and permission.
- Zuri Secure Chat knows anonymous queue state.
- PWA clients hold keys, decrypt content, and store local history.

## Server Storage

The relay may store pending ciphertext only until delivery or expiration. It must not persist plaintext, user IDs, phone numbers, profile names, private keys, or decrypted reports.

## PWA Storage

The PWA stores encrypted local history in IndexedDB. Unwrapped keys live only in memory while the chat vault is unlocked. `.zuri-key` backups are encrypted locally before export.

