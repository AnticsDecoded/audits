## Jupiter Lend
Audit competition (Code4rena) · Target: [code-423n4/2026-02-jupiter-lend](https://github.com/code-423n4/2026-02-jupiter-lend)

Jupiter Lend is a Solana (Anchor/Rust) lending protocol. The finding below is in the liquidity
layer's flashloan borrow/payback accounting.

- **Contest:** [Code4rena — 2026-02 Jupiter Lend](https://code4rena.com/audits/2026-02-jupiter-lend) · Submission `S-423`
- **Validated severity:** Low (submitted with a Medium rationale; see below)
- **PoC:** [`poc/jupiter-lend-flashloan-dust.rs`](./poc/jupiter-lend-flashloan-dust.rs)

---

### [Low-01] Flashloan deactivation lacks a zero-debt invariant — asymmetric raw rounding accumulates residual debt into a `BorrowLimitReached` DoS

**Target:** `programs/liquidity/src/state/user_borrow_position.rs` (raw conversion, lines ~237 and ~246), flashloan `payback` deactivation path

**Weakness:** CWE-682 (incorrect calculation) / CWE-841 (improper enforcement of behavioral workflow)

**Finding description and impact**

`flashloan_borrow` / `flashloan_payback` are nominal-amount APIs, but the underlying liquidity debt is
tracked in raw amounts with **asymmetric rounding**:

- Borrow conversion rounds **up** (`safe_div_ceil`) — `user_borrow_position.rs:237`
- Payback conversion rounds **down** (`safe_div`) — `user_borrow_position.rs:246`

For a nominal amount `A` and borrow exchange price `P`:

```text
raw borrow added   = ceil (A * 1e12 / P)
raw payback removed = floor(A * 1e12 / P)
```

When `A * 1e12 / P` is non-integer, each exact nominal borrow/payback cycle leaves positive residual
raw debt (typically **+1 raw unit**).

`flashloan_payback` only checks `amount == active_flashloan_amount`, pays back nominally, and then
**always** calls `set_flashloan_as_inactive()`. No invariant ensures residual raw debt is zero before
the flashloan state is closed. This produces a state-machine mismatch:

- Flashloan state says closed (`is_flashloan_active = false`, `active_flashloan_amount = 0`)
- The liquidity borrow position still holds non-zero raw debt

Because the flashloan uses a **shared** protocol borrow position per mint, repeated permissionless
cycles accumulate residual debt monotonically and eventually trip the liquidity `BorrowLimitReached`
guard, blocking all further flashloan borrows for that mint until privileged intervention / config
change.

This is distinct from the prior "max fee rounding → `TransferAmountOutOfBounds`" issue: it reproduces
with `flashloan_fee = 0` and fails via residual-debt accumulation into borrow-limit exhaustion.

**Impact** — A non-admin, permissionless attacker can grief the protocol with repeated *valid*
flashloan cycles. The deterministic end state is loss of liveness on the flashloan borrow path
(`BorrowLimitReached`) for the affected mint's shared flashloan borrow position — a systemic
liveness failure, not a one-off accounting cosmetic. No funds are lost, which is consistent with the
validated **Low** severity; the submission argued Medium on the basis of the systemic, permissionless,
deterministic liveness break.

**Proof of Concept**

See [`poc/jupiter-lend-flashloan-dust.rs`](./poc/jupiter-lend-flashloan-dust.rs) — three tests against
the contest harness:

```bash
cargo test -p tests i2_flashloan_exact_payback_can_leave_nonzero_raw_borrow_dust      -- --nocapture --test-threads=1
cargo test -p tests i2_flashloan_residual_raw_borrow_compounds_across_roundtrips      -- --nocapture --test-threads=1
cargo test -p tests i2_flashloan_residual_accumulation_eventually_blocks_flashloan_liveness -- --nocapture --test-threads=1
```

Observed evidence:

```text
PoC1: flashloan_active=false active_amount=0 residual_raw_borrow=1
      (exact borrow+payback of 12_345_679 leaves 1 raw unit of debt after deactivation)
PoC2: i2_compound cycles=8 growth_events=8 final_raw_borrow=8
      (residual grows by ~1 raw unit every cycle — monotonic accumulation)
PoC3: succeeds for several cycles, then fails with
      BorrowLimitReached / Custom(6029) / 0x178d
      (dust accumulation deterministically exhausts the borrow limit)
```

**Recommended mitigation steps**

Preferred fix — enforce the invariant: in `flashloan_payback`, after the liquidity
`operate_with_signer` call and **before** `set_flashloan_as_inactive`, read the flashloan protocol
borrow position and `require!(raw_borrow == 0)`, reverting otherwise.

Alternate fix — forced dust settlement: compute the remaining raw debt, convert it to the required
nominal payback with protocol-favorable rounding, settle the residual in the same transaction, then
deactivate.

Additional hardening: use a symmetric close-path rounding policy that guarantees debt clearance when a
nominal borrow/payback pair is intended to be an exact-close operation.

Regression tests to add:

- Exact borrow + payback must end with `raw_borrow == 0`.
- Repeated cycles must not monotonically increase residual raw borrow.
- Deactivation must fail if residual raw debt is non-zero.
- Repeated cycles must not be able to force `BorrowLimitReached` via dust accumulation.
