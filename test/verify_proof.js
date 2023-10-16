const { expect } = require("chai");
const fs = require('fs');
const { ethers } = require("hardhat");
const path = require('path');

const promisify = require('util').promisify;
const open = promisify(fs.open);
const read = promisify(fs.read);
const close = promisify(fs.close);

describe("plonk contract", function () {
  before(async function () {

    [deployer] = await ethers.getSigners();
    console.log(`> [INIT] deployer.address = ${deployer.address} ...... `);

    VerifierFactory = await ethers.getContractFactory("UnipassVerifier")
    Verifier = await VerifierFactory.deploy(deployer.address);
    await Verifier.deployed();

    ZkTestFactory = await ethers.getContractFactory("ZkTest");
    ZkTest = await ZkTestFactory.deploy(Verifier.address);

    await ZkTest.deployed();
    console.log(`> [DPLY] Contract deployed, verifier=${Verifier.address},addr=${ZkTest.address}`);

  });

  it("should verify valid new1024 proof correctly", async function () {
    console.log(`[INFO] begin test new1024`);
    const files1024 = fs.readdirSync("test_data/inputs_1024");
    for (let i = 0; i < files1024.length; i++) {
      let data = fs.readFileSync(path.join("test_data/inputs_1024", files1024[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {

        await Verifier.setupSRSHash(contractInput.srsHash);
        console.log(`[INFO] Setup SRS ... ok`);

        await Verifier.setupVKHash(
          1024,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
        console.log(`[INFO] Setup setupVKHash ... ok`);
      }

      let testTx = await ZkTest.testNew1024(
        contractInput.headerHash,
        contractInput.addrHash,
        contractInput.headerPubMatch,
        contractInput.headerLen,
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

  it("should verify valid new2048 proof correctly", async function () {
    console.log(`[INFO] begin test new2048`);
    const files2048 = fs.readdirSync("test_data/inputs_2048");
    for (let i = 0; i < files2048.length; i++) {
      let data = fs.readFileSync(path.join("test_data/inputs_2048", files2048[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {

        await Verifier.setupSRSHash(contractInput.srsHash);
        console.log(`[INFO] Setup SRS ... ok`);

        await Verifier.setupVKHash(
          2048,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
        console.log(`[INFO] Setup setupVKHash ... ok`);
      }

      let testTx = await ZkTest.testNew2048(
        contractInput.headerHash,
        contractInput.addrHash,
        contractInput.headerPubMatch,
        contractInput.headerLen,
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

  it("should verify valid new2048triple proof correctly", async function () {
    console.log(`[INFO] begin test 2048tri`);
    const files2048tri = fs.readdirSync("test_data/inputs_2048triple");
    for (let i = 0; i < files2048tri.length; i++) {
      let data = fs.readFileSync(path.join("test_data/inputs_2048triple", files2048tri[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {

        await Verifier.setupSRSHash(contractInput.srsHash);
        console.log(`[INFO] Setup SRS ... ok`);

        await Verifier.setupVKHash(
          3,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
        console.log(`[INFO] Setup setupVKHash ... ok`);
      }

      let testTx = await ZkTest.testNew2048tri(
        contractInput.headerHashs,
        contractInput.addrHashs,
        contractInput.headerPubMatches,
        contractInput.headerLens,
        contractInput.fromLeftIndexes,
        contractInput.fromLens,
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

  it("should verify valid openId proof correctly", async function () {
    console.log(`[INFO] begin test OpenId`);
    const filesOpenid = fs.readdirSync("test_data/openid");
    for (let i = 0; i < filesOpenid.length; i++) {
      let data = fs.readFileSync(path.join("test_data/openid", filesOpenid[i]), 'utf8');
      let contractInput = JSON.parse(data);
      if (i == 0) {

        await Verifier.setupSRSHash(contractInput.srsHash);
        console.log(`[INFO] Setup SRS ... ok`);

        await Verifier.setupVKHash(
          4,
          contractInput.publicInputsNum,
          contractInput.domainSize,
          contractInput.vkData,
        );
        console.log(`[INFO] Setup setupVKHash ... ok`);
      }
      let concat_hash = contractInput.idtokenHash +
        contractInput.subHash.substring(2) +
        ethers.utils.sha256(contractInput.headerRawBytes).substring(2) +
        ethers.utils.sha256(contractInput.payloadPubMatch).substring(2);

      console.log("concat_hash: ", concat_hash);

      let testTx = await ZkTest.testOpenId(
        concat_hash,
        contractInput.headerBase64Len,
        contractInput.payloadLeftIndex,
        contractInput.payloadBase64Len,
        contractInput.subLeftIndex,
        contractInput.subLen,
        contractInput.domainSize,
        contractInput.vkData,
        contractInput.publicInputs,
        contractInput.proof
      )

      // wait the tx being mined
      let testReceipt = await testTx.wait(1);

      console.log(`[Info] Check OpenID Use Zk >>> gasUsed: ${testReceipt.gasUsed}`);

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