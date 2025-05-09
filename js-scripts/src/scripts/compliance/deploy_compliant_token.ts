import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";
import { sleep } from "./utils";
import { byteArray, CallData, num } from "starknet";

dotenv.config();

async function deploy_compliance_token(
  classHash: string,
  owner: string,
  initial_supply: string,
  name: string,
  symbol: string,
) {
  console.log(process.env.UNITS_RPC);
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  console.log("Deploying compliant token...");

  let unixTime = new Date().getTime();
  // Then deploy the program
  let calldata = CallData.compile({
    owner,
    identity_registry: process.env.IDENTITY_REGISTRY,
    initial_supply,
    name: byteArray.byteArrayFromString(name),
    symbol: byteArray.byteArrayFromString(symbol),
  });
  const deployProgramResponse = await unitsAccount.deployProgram(
    classHash,
    calldata,
    unixTime.toString(),
  );

  await sleep(5000);

  console.log("✅ Deploy program response: ", deployProgramResponse);

  const receipt = await unitsAccount.getTransactionReceipt(
    deployProgramResponse.transaction_hash,
  );
  assert(receipt.execution_status.type == "SUCCEEDED");

  console.log("Compliant token address", receipt.events[0].data[0]);
}

/// CLI HELPERS

if (process.argv.length < 6) {
  console.error(
    "Usage: ts-node deploy_compliant_token.ts <owner> <initial_supply> <name> <symbol>",
  );
  process.exit(1);
}

const owner = process.argv[2];
const initial_supply = process.argv[3];
const name = process.argv[4];
const symbol = process.argv[5];

deploy_compliance_token(
  "0x052ca4b2d3b211bd64f7fa3080f69d02b78f293cb330e9ffec165c76f5203628",
  owner,
  initial_supply,
  name,
  symbol,
);
