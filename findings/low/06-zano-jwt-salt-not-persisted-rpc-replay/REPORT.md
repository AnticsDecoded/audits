# Zano — JWT anti-replay salts are not persisted, enabling RPC command replay across restart

| | |
|---|---|
| **Program** | Zano (Immunefi Bug Bounty) |
| **Submission** | #49383 |
| **Target** | `hyle-team/zano/src/wallet/wallet_rpc_server.cpp` @ `master` |
| **Class** | Authentication / replay (broken nonce durability) |
| **Submitted severity** | Critical |
| **Final severity** | Low (project downgrade) |
| **Outcome** | **Confirmed & Rewarded — 1000 USDC** |

## 1. Summary

The wallet RPC server authenticates each request with a JWT that carries a per-request `salt`,
intended to make each token single-use. The set of consumed salts (`m_jwt_used_salts`) lives
**only in process memory**. When the RPC server restarts, that set is empty again, so any JWT
that has not yet hit its `exp` (up to ~1 hour) can be replayed verbatim — along with the exact
request body it authorises — and the underlying authenticated action executes a second time
without fresh authentication.

## 2. Affected code

`wallet_rpc_server::auth_http_request`:

```cpp
if (m_jwt_used_salts.get_set().find(salt) != m_jwt_used_salts.get_set().end()) {
    throw std::runtime_error("Salt reused");
}
// ...
m_jwt_used_salts.add(salt, ticks_now + JWT_TOKEN_EXPIRATION_MAXIMUM);
```

`m_jwt_used_salts` is an in-memory structure with an expiry keyed on `JWT_TOKEN_EXPIRATION_MAXIMUM`.
There is no on-disk / persistent record of consumed salts, so the anti-replay invariant ("a salt
is accepted at most once") only holds within a single process lifetime.

## 3. Why it matters

A JWT in this scheme binds:

- `salt` — meant to guarantee one-time use,
- `body_hash` — a hash of the JSON-RPC body, binding the token to a specific action,
- `exp` — expiry, up to roughly one hour out.

Because the salt guard resets on restart, a captured `(token, body)` pair is replayable inside
the token's validity window across any restart boundary. The authenticated methods this protects
are exactly the sensitive ones:

- `transfer` — move funds,
- `sweep_below` — sweep/drain,
- `contracts_release` — change escrow/contract state.

An attacker who has observed one valid request (see scope note below) can re-issue it after a
restart, and the wallet will treat it as a fresh, authorised command.

## 4. Proof of Concept

[`POC__jwt_replay_after_restart.sh`](./POC__jwt_replay_after_restart.sh):

1. Builds a `transfer` request body and computes its `sha256` `body_hash`.
2. Mints an HS256 JWT `{exp, salt:"replay-001", body_hash}` signed with the shared secret.
3. Sends the request once (executes).
4. Restarts the wallet RPC with the same secret.
5. Replays the identical token + body.

Expected result: step 5 is accepted, re-executing the `transfer` — demonstrating that the
salt-reuse protection does not survive a restart.

## 5. Remediation

- **Persist consumed salts** (or a monotonic per-client nonce high-water mark) to durable storage,
  scoped by the token validity window, so the replay guard survives restarts.
- **Bound `exp`** to a small maximum (the project committed to this) to shrink the replay window.
- Optionally, bind tokens to a server-side session/epoch value that rotates on restart, so tokens
  minted before a restart are rejected afterwards regardless of salt state.

## 6. Disclosure outcome

Zano scoped the JWT layer to localhost traffic between the browser extension and the desktop
wallet, so a real-world exploit presupposes local malware already able to intercept that traffic
— which they treat as out of scope for full impact. They confirmed the issue as technically
valid, downgraded Critical→Low, paid **1000 USDC** (tx `0x6f53...5f04`), and committed to adding
a maximum-`exp` constraint.
