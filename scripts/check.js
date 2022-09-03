const { initialize } = require("zokrates-js");
const fs =require('fs')
const main = async () => {
  const zokratesProvider = await initialize();
  const artifacts = zokratesProvider.compile(
    `
    import "hashes/sha256/512bit" as hash;
    def main(u32[8] root, private u32[8] leaf) -> u32[8] {
        // Start from the leaf
        u32[8] digest = hash(root, leaf);

        return digest;
    }`
  );
fs.writeFileSync("./out", artifacts.program)

console.log(fs.readFileSync('/home/abc/Documents/Project/zk-hardhat/out')
// console.log(artifacts)
)














  // //243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89
  // let hash = ["0x243f6a88", "0x85a308d3", "0x13198a2e", "0x03707344", "0xa4093822", "0x299f31d0", "0x082efa98", "0xec4e6c89"];
  // //452821e638d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b5470917
  // let hash_two = ["0x452821e6", "0x38d01377", "0xbe5466cf", "0x34e90c6c", "0xc0ac29b7", "0xc97c50dd", "0x3f84d5b5", "0xb5470917"];

  // const { output, witness } = zokratesProvider.computeWitness(artifacts, [hash, hash_two]);
  // // Should get this: aca16131a2e4c4c49e656d35aac1f0e689b3151bb108fa6cf5bcc3ac08a09bf9
  // console.log(output);
};

main();