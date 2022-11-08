const { expect } = require("chai");
const fs = require('fs');
const path = require('path');

const promisify = require('util').promisify;
const open = promisify(fs.open);
const read = promisify(fs.read);
const close = promisify(fs.close);

describe("plonk contract", function () {
  before(async function () {

    [deployer] = await ethers.getSigners();
    console.log(`> [INIT] deployer.address = ${deployer.address} ...... `);

    ZkTestFactory = await ethers.getContractFactory("ZkTest");
    ZkTest = await ZkTestFactory.deploy(deployer.address);

    await ZkTest.deployed();
    console.log(`> [DPLY] Contract deployed, addr=${ZkTest.address}`);

  });

  it("should verify valid email-header-1024 proof correctly", async function () {
    console.log(`[INFO] begin test 1024`);
    const files1024 = fs.readdirSync("test_data/inputs_1024");
    for (let i = 0; i < files1024.length; i++) {
      let data = fs.readFileSync(path.join("test_data/inputs_1024", files1024[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {
        await ZkTest.setupSRSHash(contractInput.srsHash);
        console.log(`[INFO] Setup SRS ... ok`);

        await ZkTest.setupVKHash(
          1024,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
        console.log(`[INFO] Setup setupVKHash ... ok`);
      }

      let testTx = await ZkTest.testV1024(
        contractInput.fromLeftIndex,
        contractInput.fromLen,
        contractInput.domainSize,
        contractInput.vkData,
        contractInput.publicInputs,
        contractInput.proof
      )

      // wait the tx being mined
      let testReceipt = await testTx.wait(1);

      console.log(`[Info] Check Email Use Zk >>> gasUsed: ${testReceipt.gasUsed}`);

      let VerifierABI = ["event Verified(bytes32 header_hash, uint256 success)"];
      let iface = new ethers.utils.Interface(VerifierABI);

      let ecode = -1;
      let header_hash = "";
      if (testReceipt.logs.length >= 1) {
        let log = iface.parseLog(testReceipt.logs[0]);
        ecode = log.args["success"];
        header_hash = log.args["header_hash"];
      }
      if (ecode == 1) {
        console.log(`[INFO] [${header_hash}] Verification Succeed! ✅`);
      } else {
        console.log(`[INFO] Verification Failed! Ecode=${ecode} ❌`);
      }

      expect(ecode).to.equal(1);
    }
  });

  it("should verify valid email-header-2048 proof correctly", async function () {
    console.log(`[INFO] begin test 2048`);
    const files2048 = fs.readdirSync("test_data/inputs_2048");
    for (let i = 0; i < files2048.length; i++) {
      let data = fs.readFileSync(path.join("test_data/inputs_2048", files2048[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {

        await ZkTest.setupSRSHash(contractInput.srsHash);
        console.log(`[INFO] Setup SRS ... ok`);

        await ZkTest.setupVKHash(
          2048,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
        console.log(`[INFO] Setup setupVKHash ... ok`);
      }

      let testTx = await ZkTest.testV2048(
        contractInput.fromLeftIndex,
        contractInput.fromLen,
        contractInput.domainSize,
        contractInput.vkData,
        contractInput.publicInputs,
        contractInput.proof
      )

      // wait the tx being mined
      let testReceipt = await testTx.wait(1);

      console.log(`[Info] Check Email Use Zk >>> gasUsed: ${testReceipt.gasUsed}`);

      let VerifierABI = ["event Verified(bytes32 header_hash, uint256 success)"];
      let iface = new ethers.utils.Interface(VerifierABI);

      let ecode = -1;
      let header_hash = "";
      if (testReceipt.logs.length >= 1) {
        let log = iface.parseLog(testReceipt.logs[0]);
        ecode = log.args["success"];
        header_hash = log.args["header_hash"];
      }
      if (ecode == 1) {
        console.log(`[INFO] [${header_hash}] Verification Succeed! ✅`);
      } else {
        console.log(`[INFO] Verification Failed! Ecode=${ecode} ❌`);
      }

      expect(ecode).to.equal(1);
    }

  });
});