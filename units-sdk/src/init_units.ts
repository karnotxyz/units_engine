import * as starknet from "starknet";
import dotenv from "dotenv";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const provider = new starknet.RpcProvider({
  nodeUrl: process.env.MADARA_RPC,
});
const account = new starknet.Account({
  provider,
  address: process.env.ACCOUNT_ADDRESS,
  signer: process.env.PRIVATE_KEY,
  cairoVersion: "1",
  transactionVersion: "0x3",
  // Madara still used legacy UDC
  deployer: starknet.legacyDeployer,
});

async function deploy_declare_acl() {
  const sierraPath = resolve(
    __dirname,
    "../../crates/handlers/starknet/src/tests/get_program/test_contracts/target/dev/get_nonce_test_contracts_DeclareAclContract.contract_class.json"
  );
  const casmPath = resolve(
    __dirname,
    "../../crates/handlers/starknet/src/tests/get_program/test_contracts/target/dev/get_nonce_test_contracts_DeclareAclContract.compiled_contract_class.json"
  );

  const sierra = JSON.parse(readFileSync(sierraPath, "utf-8"));
  const casm = JSON.parse(readFileSync(casmPath, "utf-8"));

  try {
    const declareAndDeployResult = await account.declareAndDeploy({
      contract: sierra,
      casm: casm,
    });
    console.log(
      "This is the declare and deploy result - ",
      declareAndDeployResult
    );
  } catch (err) {
    console.log("Error declaring and deploying contract - ", err);
  }
}

deploy_declare_acl();
