# Low: JWT anti-replay salts held in memory only → signed RPC commands replayable across restart

**Target:** Zano (`hyle-team/zano/src/wallet/wallet_rpc_server.cpp`)
**Severity:** Low
**Slug:** `zano-jwt-salt-not-persisted-rpc-replay`

## Impact

The wallet RPC server authenticates requests with JWTs that carry a `salt` to prevent token
reuse. Used salts are tracked **only in memory** (`m_jwt_used_salts`). On server restart the salt
history is lost, so a previously-seen, still-unexpired JWT (valid up to ~1 hour) — together with
its exact request body — can be **replayed**, re-executing sensitive authenticated RPC actions
such as `transfer`, `sweep_below`, or `contracts_release` without re-authentication.

## Root cause

```cpp
if (m_jwt_used_salts.get_set().find(salt) != m_jwt_used_salts.get_set().end()) {
    throw std::runtime_error("Salt reused");
}
// ...
m_jwt_used_salts.add(salt, ticks_now + JWT_TOKEN_EXPIRATION_MAXIMUM);
```

`m_jwt_used_salts` is in-memory state. Nothing persists consumed salts across process lifetime,
so the replay guard resets to empty on restart.

## Proof of Concept

Sign one `transfer` JWT (with `body_hash` over the request), submit it, restart the wallet RPC
with the same secret, and replay the identical token + body — it is accepted a second time. Full
steps in [`ISSUE-1.md`](./ISSUE-1.md).

## Files in this folder

- [`REPORT.md`](./REPORT.md) — full technical write-up
- [`ISSUE-1.md`](./ISSUE-1.md) — finding submission
- [`POC__jwt_replay_after_restart.sh`](./POC__jwt_replay_after_restart.sh) — reproduction steps
