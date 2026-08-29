// Hardhat PoC for Utix MintedTokenCappedCrowdsaleExtv1 451-ETH lock (Immunefi #56107).
//
// Deploys a contract (Safe-like) receiver + the PATCHED crowdsale, funds it, and shows
// emergencyWithdraw moving ETH to a *contract* wallet — the exact transfer the original
// extcodesize==0 guard forbids. On the unpatched contract, withdrawContractFund reverts
// against any contract multisig, trapping the balance.
//
//   npx hardhat compile
//   npx hardhat run POC__run-patched-withdraw.js   # against a mainnet-fork network
const { ethers } = require("hardhat");

async function main() {
  const [owner] = await ethers.getSigners();
  console.log("Using owner:", owner.address);

  const Safe = await ethers.getContractFactory("TestSafe");
  const safe = await Safe.deploy();
  await safe.deployed();
  console.log("TestSafe (contract receiver) deployed at:", safe.address);

  const Pricing = await ethers.getContractFactory("DummyPricing");
  const pricing = await Pricing.deploy();
  await pricing.deployed();

  const Token = await ethers.getContractFactory("DummyToken");
  const token = await Token.deploy();
  await token.deployed();

  const Finalize = await ethers.getContractFactory("DummyFinalize");
  const finalize = await Finalize.deploy();
  await finalize.deployed();

  const Vesting = await ethers.getContractFactory("DummyVesting");
  const vesting = await Vesting.deploy();
  await vesting.deployed();

  const Crowdsale = await ethers.getContractFactory("MintedTokenCappedCrowdsaleExtv1");
  const crowdsale = await Crowdsale.deploy(
    "PatchedCrowdsale",
    token.address,
    pricing.address,
    safe.address, // contract wallet — reverts under the original extcodesize==0 guard
    Math.floor(Date.now() / 1000),
    Math.floor(Date.now() / 1000) + 86400,
    0,
    ethers.utils.parseEther("1000000"),
    true,
    true,
    vesting.address,
    ethers.constants.AddressZero
  );
  await crowdsale.deployed();
  console.log("Patched crowdsale deployed at:", crowdsale.address);

  await crowdsale.setFinalizeAgent(finalize.address);

  await owner.sendTransaction({ to: crowdsale.address, value: ethers.utils.parseEther("5") });
  console.log(
    "Crowdsale balance before =",
    ethers.utils.formatEther(await ethers.provider.getBalance(crowdsale.address)),
    "ETH"
  );

  // On the PATCHED contract this succeeds to a contract receiver.
  // On the DEPLOYED contract, the equivalent withdrawal reverts ("Multi Sig Wallet not contract address").
  const tx = await crowdsale.emergencyWithdraw(safe.address, ethers.utils.parseEther("3"));
  await tx.wait();

  console.log(
    "Crowdsale balance after  =",
    ethers.utils.formatEther(await ethers.provider.getBalance(crowdsale.address)),
    "ETH"
  );
  console.log("Safe balance after       =", ethers.utils.formatEther(await safe.balance()), "ETH");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
