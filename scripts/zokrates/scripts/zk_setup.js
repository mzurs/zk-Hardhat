const { initialize } = require("zokrates-js");
const fs = require("fs");
const main = async () => {
    const zokratesProvider=await initialize();
  const keypair = zokratesProvider.setup(fs.readFileSync("scripts/zokrates/generated/out"));
  fs.writeFileSync("scripts/zokrates/generated/zk_setup.json", JSON.stringify(keypair));
  // console.log(keypair)
};

main();
