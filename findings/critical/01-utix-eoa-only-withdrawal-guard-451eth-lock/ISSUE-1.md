# EOA-only withdrawal guard permanently locks 451 ETH in `MintedTokenCappedCrowdsaleExtv1`

**Program:** Utix (Immunefi Bug Bounty) · **Submission #56107**
**Target:** https://etherscan.io/address/0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03 — Smart Contract
**Impact:** Unlocking stuck funds
**Status:** Closed — duplicate of Report #22566 (Immunefi-verified same root cause)

## Brief / Intro

While looking for a way to unlock stuck funds, I discovered that the production crowdsaleExt at
`0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03` will not send ETH to its configured multisig because
the code insists the destination be an EOA. Since the team chose a Gnosis Safe, every withdrawal
reverts and the entire 451 ETH balance is still trapped.

## Vulnerability Details

The withdrawal helper contains an `extcodesize` gate:

```solidity
uint32 size;
address walletAddress = multisigWallet;
assembly {
    size := extcodesize(walletAddress)
}
require(size == 0, "Multi Sig Wallet not contract address");

// Pocket the money
(bool success, ) = payable(multisigWallet).call{value: withdrawAmount}("");
require(success, "Transfer failed to Multisig Wallet");
```

I fetched `multisigWallet` on mainnet — `0xF9C3c1A10787761269274d34AC9C1D7bD06Ed11A` — and
confirmed via `eth_getCode` that it has bytecode. With non-zero code size, the
`require(size == 0…)` check always fails, so no ETH is ever sent.

Additionally, `investorCount.plus(1);` never updates state (the return value is discarded), so
the inherited `investorCount` stays above the five-investor threshold and blocks `setMultisig`,
shutting down any attempt to point the contract at an EOA payout wallet.

## Impact Details

Because every withdrawal path is gated by that EOA-only check while `investorCount` remains
permanently high, the **451.32137 ETH cannot leave the contract**.

## References

- Mainnet contract: https://etherscan.io/address/0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03
- Payout multisig: https://etherscan.io/address/0xF9C3c1A10787761269274d34AC9C1D7bD06Ed11A

## Proof of Concept

I tested a remediation locally by making certain changes to the code — incrementing
`investorCount` correctly, replacing the `extcodesize` block with `_transferETH`, adding
`emergencyWithdraw`, and allowing `forceSetMultisig` — and confirmed it frees the funds.

Changes to `CrowdsaleExt.sol`:

1. Fixed the investor counter:

   ```solidity
   // before
   if (investedAmountOf[receiver] == 0) {
       investorCount.plus(1);
   }
   // after
   if (investedAmountOf[receiver] == 0) {
       investorCount = investorCount.plus(1);
   }
   ```

2. Replaced the `extcodesize == 0` guard with a safe transfer:

   ```solidity
   function withdrawContractFund(uint256 withdrawAmount) internal {
       _transferETH(payable(multisigWallet), withdrawAmount);
   }

   function _transferETH(address payable wallet, uint256 amount) internal {
       require(wallet != address(0), "Destination cannot be Null Address");
       (bool success, ) = wallet.call{value: amount}("");
       require(success, "ETH transfer failed");
       emit FundWithdrawnToMultiSigWallet(amount, block.timestamp);
   }
   ```

3. Added an owner escape hatch:

   ```solidity
   function emergencyWithdraw(address payable receiver, uint256 amount) external onlyOwner {
       require(receiver != address(0), "Receiver Address set to 0 address");
       uint256 available = weiRaised.minus(currentRaisedFundWithdrawn);
       require(amount <= available, "Amount exceeds available balance");
       currentRaisedFundWithdrawn = currentRaisedFundWithdrawn.plus(amount);
       _transferETH(receiver, amount);
   }
   ```

4. Added `forceSetMultisig(address)` to override the wallet even after five investors.

I reproduced this using a Hardhat mainnet fork. See
[`POC__run-patched-withdraw.js`](./POC__run-patched-withdraw.js) and
[`POC__TestSafe.sol`](./POC__TestSafe.sol). After deploying the patched crowdsale with a
contract (Safe) receiver, funding it, and calling `emergencyWithdraw`, ETH is successfully moved
to the contract wallet — proving the original EOA-only guard is what traps the funds.

## Project / Immunefi response (timeline excerpt)

- Utix: "This issue has already been reported by everyone. It is literally the bug we aim to fix …
  this report will not receive a reward."
- Immunefi (after mediation): "This report showcases the same vulnerability as Report #22566,
  previously submitted to the project via Immunefi. Both reports share the same root cause and
  vulnerability type. @Utix — We strongly recommend updating your Bug Bounty Program to publicly
  acknowledge this known vulnerability to prevent further submissions."
