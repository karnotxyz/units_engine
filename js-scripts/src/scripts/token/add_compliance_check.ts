import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";

dotenv.config();

async function add_compliance_check() {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY
  );

  let { transaction_hash } = await unitsAccount.sendTransaction([
    {
      contractAddress: process.env.TOKEN,
      entrypoint: "add_compliance_check",
      calldata: [process.env.COMPLIANCE_MODULE],
    },
  ]);

  const receipt = await unitsAccount.waitForTransaction(transaction_hash);
  if (receipt.execution_status.type != "SUCCEEDED") {
    console.error("❌ Add compliance check failed:", receipt);
    process.exit(1);
  }

  console.log("✅ Added compliance check:", process.env.COMPLIANCE_MODULE);
}

/// CLI HELPERS

if (process.argv.length < 2) {
  console.error("Usage: ts-node add_compliance_check.ts");
  process.exit(1);
}

add_compliance_check();
