# Zuri Core Integration

Zuri Core should expose `POST /chat/intents` to validate whether a member can start a chat with an advertiser. The response should include an opaque connection bundle with two relay queues:

- member to advertiser
- advertiser to member

The Chat Relay must not receive member IDs, advertiser IDs, profile handles, phone numbers, or names. Any mapping between Zuri accounts and relay queues stays in Zuri Core, and should be minimized or rotated.

