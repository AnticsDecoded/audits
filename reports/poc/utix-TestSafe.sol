// SPDX-License-Identifier: MIT
// PoC helper contracts for Utix MintedTokenCappedCrowdsaleExtv1 451-ETH lock (Immunefi #56107).
//
// TestSafe is a contract (non-zero extcodesize) receiver standing in for the real Gnosis Safe.
// The Dummy* contracts satisfy the crowdsale constructor's dependencies so the patched
// crowdsale can be deployed on a Hardhat mainnet fork for the withdrawal test.
pragma solidity 0.7.6;

import "MintedTokenCappedCrowdsaleExt.sol";
import "FinalizeAgent.sol";
import "PricingStrategy.sol";
import "FractionalERC20Ext.sol";
import "TokenVesting.sol";

contract TestSafe {
    event Received(address from, uint256 value);
    receive() external payable { emit Received(msg.sender, msg.value); }
    function balance() external view returns (uint256) { return address(this).balance; }
}

contract DummyPricing is PricingStrategy {
    function updateRate(uint) external override {}
    function calculatePrice(uint value, uint, uint) external pure override returns (uint) { return value; }
    function oneTokenInWei(uint, uint) external pure override returns (uint) { return 1; }
}

contract DummyToken is FractionalERC20Ext {
    constructor() { decimals = 18; minCap = 0; }
    function balanceOf(address) external pure override returns (uint256) { return 0; }
    function transfer(address, uint256) external pure override returns (bool) { return true; }
    function transferFrom(address, address, uint256) external pure override returns (bool) { return true; }
    function approve(address, uint256) external pure override returns (bool) { return true; }
    function allowance(address, address) external pure override returns (uint256) { return 0; }
}

contract DummyFinalize is FinalizeAgent {
    function isSane() public pure override returns (bool) { return true; }
    function distributeReservedTokens(uint256) public override {}
    function finalizeCrowdsale() public override {}
    function setCrowdsaleTokenExtv1(address) public override {}
}

contract DummyVesting is TokenVesting(address(0)) {
    constructor() TokenVesting(address(0)) {}
}
