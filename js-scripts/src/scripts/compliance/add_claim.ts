import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import {num} from "starknet";
import dotenv from "dotenv";
import { sleep } from "./utils";

dotenv.config();

async function add_claim(user: string, topic: string) {
  console.log(process.env.UNITS_RPC);
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  let { result } = await unitsAccount.call(process.env.IDENTITY_REGISTRY, "get_identity", [user]);
  console.log("oid of user", result[0]);

  let { transaction_hash } = await unitsAccount.sendTransaction(
    [
      {
        contractAddress: result[0],
        entrypoint: "add_claim",
        calldata: [topic]
      }
    ]
  );

  await sleep(2000);
  console.log("✅ Initiated adding claim:", transaction_hash);

  const receipt = await unitsAccount.getTransactionReceipt(transaction_hash);
  assert(receipt.execution_status.type == "SUCCEEDED")
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error("Usage: ts-node add_claim.ts <user> <topic>");
  process.exit(1);
}

const user = process.argv[2];
const topic = process.argv[3];

add_claim(user, topic);