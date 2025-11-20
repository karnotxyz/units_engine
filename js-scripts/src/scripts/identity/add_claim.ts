import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import { num } from "starknet";
import dotenv from "dotenv";

dotenv.config();

async function add_claim(user: string, topic: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY
  );

  let { result } = await unitsAccount.call(
    process.env.IDENTITY_REGISTRY,
    "get_identity",
    [user]
  );

  let { transaction_hash } = await unitsAccount.sendTransaction([
    {
      contractAddress: result[2],
      entrypoint: "add_claim",
      calldata: [topic],
    },
  ]);

  const receipt = await unitsAccount.waitForTransaction(transaction_hash);
  if (receipt.execution_status.type != "SUCCEEDED") {
    console.error("❌ Add claim failed:", receipt);
    process.exit(1);
  }

  console.log("✅ Added claim:", topic);
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error("Usage: ts-node add_claim.ts <user> <topic>");
  process.exit(1);
}

const user = process.argv[2];
const topic = process.argv[3];

add_claim(user, topic);
