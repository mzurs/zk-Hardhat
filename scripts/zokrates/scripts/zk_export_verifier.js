const { initialize } = require("zokrates-js");
const fs = require("fs");
const keypair=require('../generated/zk_setup.json')
const main = async () => {
    const MIT_LICENSE=`// SPDX-License-Identifier: MIT \n //`;
    const zokratesProvider=await initialize();
//  console.log(keypair)
    const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk);
    fs.writeFileSync("/home/abc/Documents/Project/zk-hardhat/contracts/Verifier.sol",MIT_LICENSE);
    fs.appendFileSync("/home/abc/Documents/Project/zk-hardhat/contracts/Verifier.sol", verifier);



};

main();
