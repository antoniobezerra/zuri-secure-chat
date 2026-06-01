# API

## Queues

`POST /queues`

Creates one anonymous unidirectional queue and returns `queueId`, `sendToken`, and `receiveToken`. The relay stores only token hashes.

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

