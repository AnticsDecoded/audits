## Utix
[Program on Immunefi](https://bugs.immunefi.com/) · Target: [`MintedTokenCappedCrowdsaleExtv1`](https://etherscan.io/address/0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03) (Ethereum mainnet)

Utix's token crowdsale is a deployed Solidity contract that custodies raised ETH and pays it out
to a configured multisig. The finding below concerns a withdrawal guard that is incompatible with
the multisig actually configured on mainnet.

---

### [Critical-01] EOA-only withdrawal guard permanently locks 451 ETH

**Target:** `MintedTokenCappedCrowdsaleExtv1` @ `0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03`

**Finding description and impact**

The production crowdsale holds **451.32137 ETH** and cannot release any of it. Its withdrawal
helper requires the destination `multisigWallet` to be an externally-owned account via an
`extcodesize == 0` check, but the configured payout wallet
([`0xF9C3c1A10787761269274d34AC9C1D7bD06Ed11A`](https://etherscan.io/address/0xF9C3c1A10787761269274d34AC9C1D7bD06Ed11A))
is a Gnosis Safe — a contract with non-zero code — so every withdrawal reverts.

```solidity
uint32 size;
address walletAddress = multisigWallet;
assembly { size := extcodesize(walletAddress) }
require(size == 0, "Multi Sig Wallet not contract address");   // Safe has code -> always reverts

(bool success, ) = payable(multisigWallet).call{value: withdrawAmount}("");
require(success, "Transfer failed to Multisig Wallet");
```

A second defect removes the only intended workaround: `investorCount.plus(1)` is called without
assigning the result (`investorCount = investorCount.plus(1)` was intended), so the inherited
`investorCount` never updates. It stays above the five-investor threshold and blocks `setMultisig`,
so the contract cannot be repointed at an EOA payout wallet. Together, the guard blocks withdrawal
and the counter bug blocks the reconfiguration that would work around it — the full 451 ETH is
permanently frozen.

**Proof of Concept**

Reproduced on a Hardhat mainnet fork. A `TestSafe` contract receiver (non-zero `extcodesize`,
standing in for the real Safe) plus constructor dummies let a patched crowdsale deploy; funding it
and calling `emergencyWithdraw` moves ETH to a **contract** wallet successfully — the only
difference from the deployed bytecode being the removed `extcodesize == 0` guard and the counter
fix, which pins the freeze on exactly those two defects. Against the unpatched contract, the
equivalent withdrawal to any contract multisig reverts with `"Multi Sig Wallet not contract address"`.

- Helper contracts: [`poc/utix-TestSafe.sol`](./poc/utix-TestSafe.sol)
- Hardhat script: [`poc/utix-run-patched-withdraw.js`](./poc/utix-run-patched-withdraw.js)

**Recommended mitigation steps**

Remove the EOA-only `extcodesize == 0` guard — contract wallets (Safes) are a normal, intended
payout destination — and use a plain checked transfer instead:

```solidity
function _transferETH(address payable wallet, uint256 amount) internal {
    require(wallet != address(0), "Destination cannot be Null Address");
    (bool success, ) = wallet.call{value: amount}("");
    require(success, "ETH transfer failed");
    emit FundWithdrawnToMultiSigWallet(amount, block.timestamp);
}
```

Fix the counter (`investorCount = investorCount.plus(1);`), and for the already-deployed stuck
instance ship an owner-gated escape hatch (`emergencyWithdraw` / `forceSetMultisig`) via
upgrade/migration so the trapped 451 ETH can be recovered to the Safe.
