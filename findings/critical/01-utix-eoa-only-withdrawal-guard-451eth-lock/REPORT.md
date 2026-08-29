# Utix — EOA-only withdrawal guard permanently locks 451 ETH on a live mainnet crowdsale

| | |
|---|---|
| **Program** | Utix (Immunefi Bug Bounty) |
| **Submission** | #56107 |
| **Target** | `MintedTokenCappedCrowdsaleExtv1` @ `0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03` (mainnet) |
| **Class** | Permanent freezing of funds (unlocking stuck funds) |
| **Severity** | Critical |
| **Outcome** | Closed — Immunefi-verified **duplicate of Report #22566** (same root cause) |

## 1. Summary

The deployed Utix crowdsale holds **451.32137 ETH** that can never be withdrawn. Its internal
withdrawal helper insists the payout destination is an **externally-owned account** by checking
`extcodesize(multisigWallet) == 0`. The configured payout wallet
(`0xF9C3c1A10787761269274d34AC9C1D7bD06Ed11A`) is a **Gnosis Safe** — a smart contract with
non-zero code. Every withdrawal therefore fails the `require`, and the ETH is stuck. A second
bug (a discarded `investorCount.plus(1)` return value) keeps `investorCount` permanently above
the five-investor threshold, disabling `setMultisig` and removing the only intended way to
repoint the contract at an EOA.

## 2. Affected code

Withdrawal helper (`CrowdsaleExt.sol`):

```solidity
uint32 size;
address walletAddress = multisigWallet;
assembly { size := extcodesize(walletAddress) }
require(size == 0, "Multi Sig Wallet not contract address");   // (A) any contract wallet reverts

(bool success, ) = payable(multisigWallet).call{value: withdrawAmount}("");
require(success, "Transfer failed to Multisig Wallet");
```

Investor counter:

```solidity
if (investedAmountOf[receiver] == 0) {
    investorCount.plus(1);       // (B) return value discarded — investorCount never changes
}
```

- **(A)** On-chain, `eth_getCode(0xF9C3…d11A)` returns bytecode, so `extcodesize > 0` and the
  guard reverts unconditionally.
- **(B)** `plus` returns a new value rather than mutating in place; without assignment the count
  is stuck. With it stuck above the threshold, `setMultisig` (gated on the investor count) can't
  be used to switch to an EOA payout wallet.

Together, (A) blocks withdrawal and (B) blocks the reconfiguration that would work around (A).

## 3. Impact

All **451.32137 ETH** held by the contract is permanently frozen. There is no code path — not
`withdrawContractFund`, not `setMultisig` — that releases it on the deployed bytecode.

## 4. Proof of Concept

Reproduced on a Hardhat **mainnet fork**:

- [`POC__TestSafe.sol`](./POC__TestSafe.sol) — a `TestSafe` contract receiver (non-zero
  `extcodesize`, standing in for the real Safe) plus dummy Pricing/Token/Finalize/Vesting
  contracts to satisfy the crowdsale constructor.
- [`POC__run-patched-withdraw.js`](./POC__run-patched-withdraw.js) — deploys a **patched**
  crowdsale (counter fixed, `extcodesize` guard replaced with `_transferETH`, plus
  `emergencyWithdraw` / `forceSetMultisig` escape hatches), funds it with ETH, and calls
  `emergencyWithdraw` to move ETH **to a contract wallet**.

Observed: the patched path transfers ETH to the contract receiver successfully. The only
difference from the deployed contract is the removal of the `extcodesize == 0` guard and the
counter fix — which pins the freeze on exactly those two defects. Against the unpatched
bytecode, the equivalent withdrawal to any contract multisig reverts with
`"Multi Sig Wallet not contract address"`.

## 5. Remediation

- Remove the EOA-only `extcodesize == 0` guard; contract wallets (Safes) are a normal, intended
  payout destination. Use a plain checked `call{value:...}` transfer (`_transferETH`) instead.
- Fix the counter: `investorCount = investorCount.plus(1);`.
- For the already-deployed, stuck instance, ship an owner-gated escape hatch
  (`emergencyWithdraw` / `forceSetMultisig`) via upgrade/migration so the trapped 451 ETH can be
  recovered to the Safe.

## 6. Disclosure outcome

Utix closed the report as an already-known bug. On mediation, Immunefi's technical team confirmed
it is the **same root cause and vulnerability type as the earlier Report #22566** and advised the
program to publicly document the known issue. The vulnerability is real and unpatched on the
deployed contract; the earlier report simply claimed the reward first — hence this entry is
catalogued as a duplicate/known finding rather than a paid one.
