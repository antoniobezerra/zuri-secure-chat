# API

## Queues

`POST /queues`

Creates one anonymous unidirectional queue and returns `queueId`, `sendToken`, and `receiveToken`. The relay stores only token hashes.

This endpoint remains available for demos and operational testing. The production chat bootstrap should prefer one-time invites.

## Invites

`POST /invites`

Creates a one-time invite. The response includes `inviteId`, `inviteSecret`, `creatorClaimToken`, and `expiresAt`, but no queue tokens. The public share link should put the invite secret in the URL fragment, for example `/i/:inviteId#zuri=...`, so browsers do not send it automatically as part of a normal HTTP request.

`POST /invites/:id/accept`

Accepts a pending invite by sending only `inviteSecret`. If the invite is pending, unexpired, under the attempt limit, and the secret hash matches, the relay marks it consumed and returns the connection bundle once. Later attempts return used, expired, revoked, or invalid-secret errors.

`POST /invites/:id/claim`

Lets the creator claim their connection bundle after the invite has been accepted. It requires only `creatorClaimToken`, returns the bundle once, then clears the creator-side encrypted bundle.

`POST /invites/:id/revoke`

Admin-only endpoint that marks a pending invite as revoked and clears its temporary encrypted bundle.

The relay stores `secret_hash`, not the secret. Any temporary bundle-at-rest is encrypted with the invite secret and cleared after one-time acceptance.

## Messages

`POST /messages/enqueue`

Receives ciphertext for a queue. The payload must not contain plaintext, UIDs, profile names, phone numbers, or decrypted content.

`GET /messages/pull?queueId=...`

Returns pending ciphertext for a receiver capability.

`POST /messages/:id/delivered`

Confirms delivery and immediately deletes the ciphertext row.

## Reports

`POST /reports`

Creates a report without plaintext by default. The report can reference a public profile/ad context using an opaque external reference.

## Metrics

`GET /metrics/hourly`

Returns aggregate hourly counts for enqueued, delivered, and expired messages.
