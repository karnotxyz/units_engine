import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";

dotenv.config();

async function deploy_compliance_contract(classHash: string, fee: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY
  );

  console.log("Deploying Compliance fee module...");

  let unixTime = new Date().getTime();
  // Then deploy the program
  const deployProgramResponse = await unitsAccount.deployProgram(
    classHash,
    [fee],
    unixTime.toString()
  );

  console.log("✅ Deploy program response: ", deployProgramResponse);

  const receipt = await unitsAccount.waitForTransaction(
    deployProgramResponse.transaction_hash
  );
  assert(receipt.execution_status.type == "SUCCEEDED");

  console.log("Compliance token address: ", receipt.events[0].data[0]);
}

/// CLI HELPERS

if (process.argv.length < 2) {
  console.error("Usage: ts-node deploy_compliance_contract.ts <fee>");
  process.exit(1);
}
const fee = process.argv[2];

deploy_compliance_contract(
  "0x042f2a472daae05481b88ada14be4c9c180b9d96b07874842c8d70cec28ff320",
  fee
);
