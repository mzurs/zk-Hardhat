const { initialize } = require("zokrates-js");
const fs = require("fs");

const main = async () => {
  const zk=(fs.readFileSync("/home/abc/Documents/Project/zk-hardhat/scripts/zokrates/src/zk_users.zok")).toString()
  const zokratesProvider = await initialize();
  
// console.log(zk)
  const artifacts = zokratesProvider.compile(zk);

  fs.writeFileSync("./scripts/zokrates/generated/out", artifacts.program);
  fs.writeFileSync(
    "scripts/zokrates/generated/zk_abi.json",
    JSON.stringify(artifacts.abi)
  
  );
  // console.log(artifacts)
};

main();
