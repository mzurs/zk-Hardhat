const hre = require("hardhat");
const { initialize } = require("zokrates-js");
const path = require("path");
const keyPair = require("../scripts/zokrates/generated/zk_setup.json");
const fs = require("fs");

async function main() {
  const ZKP = await hre.ethers.getContractFactory("Verifier");
  const zkpverifier = await ZKP.deploy();

  await zkpverifier.deployed();

  // console.log(zkpverifier.address)
  const zokratesProvider = await initialize();

  const program = fs.readFileSync(
    path.join(__dirname, "zokrates", "generated", "out")
  ); //artifacts.program;
  const abi = JSON.parse(
    fs.readFileSync(
      path.join(__dirname, "zokrates", "generated", "zk_abi.json")
    )
  ); //artifacts.abi;
  const program_abi = {
    program,
    abi,
  };
  // console.log(program_abi)

  const { witness, output } = zokratesProvider.computeWitness(program_abi, [
    "4210177777773",
    "249697928511749064481934707482023822598",
    "127222874392670729104785390335824196170",
    "0",
    "0",
    "0",
    "164345617366728272006170673450623848882",
    "281430901492732617543158812730993744472",
    false,
  ]);

  const proof = zokratesProvider.generateProof(program, witness, keyPair.pk);

  // console.log(proof)

  const result = await zkpverifier.verifyTx(proof.proof, proof.inputs);
  console.log(`Result: ${result}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
