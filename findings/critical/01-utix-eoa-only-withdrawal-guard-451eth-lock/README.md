# Critical: `extcodesize==0` withdrawal guard rejects the Gnosis-Safe multisig → 451 ETH permanently locked

**Target:** Utix — `MintedTokenCappedCrowdsaleExtv1` @ [`0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03`](https://etherscan.io/address/0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03) (Ethereum mainnet)
**Severity:** Critical
**Slug:** `utix-eoa-only-withdrawal-guard-451eth-lock`

## Impact

The production crowdsale contract holds **451.32137 ETH** and cannot release it. Its withdrawal
helper requires the destination `multisigWallet` to be an **EOA** via an `extcodesize == 0`
check, but the configured payout wallet
([`0xF9C3c1A10787761269274d34AC9C1D7bD06Ed11A`](https://etherscan.io/address/0xF9C3c1A10787761269274d34AC9C1D7bD06Ed11A))
is a Gnosis Safe — a contract with non-zero code. Every withdrawal therefore reverts, and the
entire balance is permanently trapped.

## Root cause

```solidity
uint32 size;
address walletAddress = multisigWallet;
assembly { size := extcodesize(walletAddress) }
require(size == 0, "Multi Sig Wallet not contract address");   // Safe has code → always reverts

(bool success, ) = payable(multisigWallet).call{value: withdrawAmount}("");
require(success, "Transfer failed to Multisig Wallet");
```

Compounding it, `investorCount.plus(1)` is called without assigning the result
(`investorCount = investorCount.plus(1)` was intended), so the inherited `investorCount` never
updates — it stays above the five-investor threshold and blocks `setMultisig`, removing the only
path to repoint the contract at an EOA.

## Proof of Concept

Reproduced on a Hardhat mainnet fork: the `extcodesize==0` guard reverts to a Safe, and a patched
build (fixed counter, `_transferETH` in place of the guard, plus `emergencyWithdraw` /
`forceSetMultisig` escape hatches) successfully frees the ETH. Full write-up and Hardhat
script/contracts in [`REPORT.md`](./REPORT.md) and [`ISSUE-1.md`](./ISSUE-1.md).

## Files in this folder

- [`REPORT.md`](./REPORT.md) — full technical write-up
- [`ISSUE-1.md`](./ISSUE-1.md) — finding submission
- [`POC__run-patched-withdraw.js`](./POC__run-patched-withdraw.js) — Hardhat PoC script
- [`POC__TestSafe.sol`](./POC__TestSafe.sol) — helper contracts (Safe receiver + constructor dummies)
