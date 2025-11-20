import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";

dotenv.config();

async function add_claim_check(topic: string, issuer: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY
  );

  let { transaction_hash } = await unitsAccount.sendTransaction([
    {
      contractAddress: process.env.TOKEN,
      entrypoint: "add_claim_check",
      calldata: [topic, issuer],
    },
  ]);

  const receipt = await unitsAccount.waitForTransaction(transaction_hash);
  assert(receipt.execution_status.type == "SUCCEEDED");

  console.log("✅ Added claim check:", topic, issuer);
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error("Usage: ts-node add_claim_check.ts <topic> <issuer>");
  process.exit(1);
}

const topic = process.argv[2];
const issuer = process.argv[3];

add_claim_check(topic, issuer);
