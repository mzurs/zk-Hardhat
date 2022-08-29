const hre = require("hardhat");
const artifacts = require("./abi.json");
const { initialize } = require("zokrates-js");
const pk = require("./keypair.json");

async function main() {
  const Lock = await hre.ethers.getContractFactory("Verifier");
  const lock = await Lock.deploy();

  await lock.deployed();

  initialize().then(async (zokratesProvider) => {
    const { witness, output } = zokratesProvider.computeWitness(artifacts, [
      "16",
    ]);

    // generate proof
   const proof = zokratesProvider.generateProof(artifacts.program, witness, pk.pk);

    const proofabi = [proof.proof.a, proof.proof.b, proof.proof.c];

    const bit = await lock.verifyTx(proofabi, proof.inputs);
    console.log(bit);
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
