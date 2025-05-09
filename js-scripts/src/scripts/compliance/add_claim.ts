import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";
import { sleep } from "./utils";

dotenv.config();

async function add_claim(token: string, topic: string) {
  console.log(process.env.UNITS_RPC);
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  let { transaction_hash } = await unitsAccount.sendTransaction(
    [
      {
        contractAddress: token,
        entrypoint: "add_claim",
        calldata: [topic]
      }
    ]
  );

  await sleep(5000);
  console.log("✅ Initiated adding claim check:", transaction_hash);

  const receipt = await unitsAccount.getTransactionReceipt(transaction_hash);
  assert(receipt.execution_status.type == "SUCCEEDED")
}

/// CLI HELPERS

if (process.argv.length < 3) {
  console.error("Usage: ts-node add_claim.ts <token> <topic>");
  process.exit(1);
}

const token = process.argv[2];
const topic = process.argv[3];

add_claim(token, topic);