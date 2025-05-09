import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";
import { sleep } from "./utils";

dotenv.config();

async function register_new_identity(identity_address: string, user: string) {
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
        contractAddress: identity_address,
        entrypoint: "get_new_identity",
        calldata: [user]
      }
    ]
  );

  await sleep(5000);
  console.log("✅ Initiated getting identity:", transaction_hash);

  const receipt = await unitsAccount.getTransactionReceipt(transaction_hash);
  assert(receipt.execution_status.type == "SUCCEEDED")
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error("Usage: ts-node register_new_identity.ts <identity_addres> <user>");
  process.exit(1);
}

const identity_address = process.argv[2];
const user = process.argv[3];
register_new_identity(identity_address, user);