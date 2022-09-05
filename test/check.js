const { initialize } = require("zokrates-js");
const fs = require("fs");
const main = async () => {
  const zokratesProvider = await initialize();
  const source = "def main(private field a) -> field { return a * a; }";

  const artifacts = zokratesProvider.compile(source);

  fs.writeFileSync("./out", artifacts.program);
  fs.writeFileSync("scripts/zk_abi.json", JSON.stringify(artifacts.abi));


  const keypair = zokratesProvider.setup(fs.readFileSync("./out"));
  fs.writeFileSync("scripts/zk_setup.json", JSON.stringify(keypair));

  const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk);
  fs.writeFileSync("contracts/zkp_verifier.sol", verifier);

  const program = artifacts.program;
  const abi = artifacts.abi;
  const program_abi = {
    program,
    abi,
  };


  const { witness, output } = zokratesProvider.computeWitness(program_abi, [
    "2",
  ]);


  const proof = zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);
console.log(proof)
fs.writeFileSync("scripts/proof.json", JSON.stringify(proof));

};

main();
