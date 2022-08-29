// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// You can also run a script with `npx hardhat run <script>`. If you do that, Hardhat
// will compile your contracts, add the Hardhat Runtime Environment's members to the
// global scope, and execute the script.
const hre = require("hardhat");
const artifacts = require("./abi.json");
const { initialize } = require("zokrates-js");

async function main() {
  let proof,keypair;
  const Lock = await hre.ethers.getContractFactory("Verifier");
  const lock = await Lock.deploy();

  await lock.deployed();

  // console.log(lock.address);
  // console.log(artifacts.abi)

  initialize().then(async(zokratesProvider) => {
    const { witness, output } = zokratesProvider.computeWitness(artifacts, [
      "2",
    ]);
    console.log(witness, output);
     keypair = zokratesProvider.setup(artifacts.program);

    //   // generate proof
     proof = zokratesProvider.generateProof(
      artifacts.program,
      witness,
      keypair.pk
    );
    // console.log(proof)

    //   // export solidity verifier
    //   const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk);

    //   // or verify off-chain
    const isVerified = zokratesProvider.verify(keypair.vk, proof);
    console.log(isVerified);
    let proofabi=[proof.proof.a,proof.proof.b,proof.proof.c]
    console.log((proofabi))
      const bit=await lock.verifyTx(proofabi,proof.inputs)
  // console.log(bit)

  });
// console.log(proof)
}
// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
