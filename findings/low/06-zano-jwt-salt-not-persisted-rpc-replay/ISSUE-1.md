# Lack of Persistent Salt Tracking in JWT Authentication Enables Replay of Critical Wallet RPC Commands

**Program:** Zano (Immunefi Bug Bounty) · **Submission #49383**
**Target:** https://github.com/hyle-team/zano/blob/master/src/wallet/wallet_rpc_server.cpp — Websites & Apps
**Impact:** Taking/modifying authenticated actions on behalf of other users without their interaction (withdrawals, trades, etc.)
**Status:** Confirmed (severity Critical → Low) — Paid 1000 USDC

## Brief / Intro

Zano Wallet RPC server implements JWT-based authentication for access control. However, salts
used to prevent token reuse are only stored in memory and are not persisted across server
restarts. This enables an attacker to replay previously valid, signed JWT tokens and execute
critical authenticated actions like fund transfers, contract releases, and sweep operations. If
exploited in production, this could lead to unauthorized transactions and total loss of user
funds without their interaction.

## Vulnerability Details

JWT authentication is used in Zano's `wallet_rpc_server` to validate incoming RPC requests. Each
token includes a salt to prevent reuse, which is stored temporarily in memory via
`m_jwt_used_salts`.

Relevant code from `wallet_rpc_server::auth_http_request`:

```cpp
if (m_jwt_used_salts.get_set().find(salt) != m_jwt_used_salts.get_set().end()) {
    throw std::runtime_error("Salt reused");
}
// ...
m_jwt_used_salts.add(salt, ticks_now + JWT_TOKEN_EXPIRATION_MAXIMUM);
```

Key problems:

- The used salts are stored in-memory only.
- Upon restarting the server, all salt history is lost.
- JWTs that are not yet expired (valid for up to 1 hour) can be replayed.
- Replay of RPC requests such as `transfer`, `sweep_below`, `contracts_release`, etc., results in
  wallet state being modified without re-authentication.

The token's salt-reuse logic is insufficient without a persistent or nonce-bound implementation.

## Impact Details

This vulnerability allows an attacker to:

- Replay previously valid authenticated RPC requests without needing new credentials.
- Execute sensitive wallet functions:
  - `transfer`: move funds from the victim's wallet again.
  - `sweep_below`: drain funds using sweeping.
  - `contracts_release`: trigger contract state changes.
- Perform these actions without the user's awareness or any interaction.
- Exploit the replay after a server restart, making the attack stealthy and persistent.

This results in unauthorized fund transfers, potential theft of user assets, and irreversible
blockchain state changes.

## References

- Zano Wallet RPC source: https://github.com/hyle-team/zano/blob/master/src/wallet/wallet_rpc_server.cpp

## Proof of Concept

Full runnable steps are in [`POC__jwt_replay_after_restart.sh`](./POC__jwt_replay_after_restart.sh).

Setup — run the Zano Wallet RPC server on localhost:

```
./simplewallet --wallet-file mywallet --password testpass \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 8080 --jwt-secret mysupersecret
```

1. Create the request body (`transfer.json`) with a `transfer` params object.
2. Hash the request body: `cat transfer.json | tr -d '\n' | sha256sum`.
3. Create a JWT with header `{"alg":"HS256","typ":"JWT"}` and payload
   `{"exp":<far future>,"salt":"replay-001","body_hash":"<sha256 of body>"}`, signed with the
   shared secret.
4. Send the original authenticated request with the `Zano-Access-Token` header and `--data @transfer.json`.
5. Restart the wallet RPC (`pkill simplewallet`, then relaunch with the **same** `--jwt-secret`).
6. Replay the exact same request with the exact same token and body.

**Result:** after the restart, the replayed request is accepted a second time — the salt-reuse
guard no longer remembers the consumed salt, so the previously-executed authenticated command
runs again.

## Project response (timeline excerpt)

> Since JWT is used exclusively on localhost to facilitate communication between the browser
> extension and the local Zano desktop application, the described scenario would only be possible
> if malicious software is already present on the user's machine … we acknowledge that the
> reported issue is technically valid. Given the limited real-world impact … we are confirming
> the report but assigning it a Low severity rating. … we will also introduce a constraint on the
> maximum allowed expiration (exp) claim in access tokens.

Confirmed → Paid: 1000 USDC (tx `0x6f53...5f04`).
