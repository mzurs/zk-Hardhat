const hre = require("hardhat");
const { initialize } = require("zokrates-js");
const keyPair=require("../scripts/zokrates/generated/zk_setup.json")
const fs =require('fs')
async function main() {
  const ZKP = await hre.ethers.getContractFactory("Verifier");
  const zkpverifier = await ZKP.deploy();

  await zkpverifier.deployed();



// console.log(zkpverifier.address)
const zokratesProvider= await initialize();

const program = fs.readFileSync("/home/abc/Documents/Project/zk-hardhat/scripts/zokrates/generated/out")//artifacts.program;
  const abi =  JSON.parse(fs.readFileSync("/home/abc/Documents/Project/zk-hardhat/scripts/zokrates/generated/zk_abi.json"))//artifacts.abi;
  const program_abi = {
    program,
    abi,
  };
// console.log(program_abi)

const { witness, output } = zokratesProvider.computeWitness(program_abi, [
  "0","0","0","97","45324487246557938747332883189457400843","84478852209878349000735790184433475398"
]);

const proof = zokratesProvider.generateProof(program, witness, keyPair.pk);

// console.log(proof)

const result= await zkpverifier.verifyTx(proof.proof,proof.inputs)
console.log(`Result: ${result}`)

}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
