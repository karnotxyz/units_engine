import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";
import { num } from "starknet";

dotenv.config();

async function deploy_identity_registry(classHash: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY
  );

  console.log("Deploying identity registry");
  let unixTime = new Date().getTime();
  // Then deploy the program
  const deployProgramResponse = await unitsAccount.deployProgram(
    classHash,
    ["0x1ed4238eea00b51c0719043413e3e12dcd8e8be2cc29750820b6da8a8cc64f4"],
    unixTime.toString()
  );

  console.log("✅ Deploy program response: ", deployProgramResponse);

  const receipt = await unitsAccount.waitForTransaction(
    deployProgramResponse.transaction_hash
  );
  assert(receipt.execution_status.type == "SUCCEEDED");

  console.log("New identity address", num.toHex(receipt.events[0].data[0]));
}

/// CLI HELPERS

if (process.argv.length < 2) {
  console.error("Usage: ts-node deploy_identity_registry.ts");
  process.exit(1);
}

deploy_identity_registry(
  "0x005daafa4df27b37dfef5cc79b67fb1b9cb1ea050fb9b77fc43bedaa507a0342"
);
