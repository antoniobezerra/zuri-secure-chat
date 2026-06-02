# Zuri Core Integration

Zuri Core should expose `POST /chat/intents` to validate whether a member can start a chat with an advertiser. The product should then create a one-time relay invite instead of exposing long-lived queue tokens in a public link.

The invite response gives the creator a `creatorClaimToken`, but no queue tokens. The shared link contains only an opaque invite id and a fragment secret. The accepting client calls the relay with the invite secret; if the invite is pending and unexpired, the relay returns the two anonymous queues:

- member to advertiser
- advertiser to member

The Chat Relay must not receive member IDs, advertiser IDs, profile handles, phone numbers, or names. Any mapping between Zuri accounts and relay queues stays in Zuri Core, and should be minimized or rotated.

The relay invite is one-time by default. After acceptance, later attempts fail, the acceptor temporary encrypted bundle is cleared, and the creator can claim their encrypted bundle once using the private claim token. Zuri Core can revoke a chat by disabling the associated relay queues without giving the relay public profile identity.
