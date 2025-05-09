import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";
import { sleep } from "./utils";

dotenv.config();

async function register_new_identity() {
  console.log(process.env.UNITS_RPC);
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  let { transaction_hash } = await unitsAccount.sendTransaction([
    {
      contractAddress: process.env.IDENTITY_REGISTRY,
      entrypoint: "get_new_identity",
      calldata: [process.env.ACCOUNT_ADDRESS],
    },
  ]);

  await sleep(2000);
  console.log("✅ Initiated getting identity:", transaction_hash);

  const receipt = await unitsAccount.getTransactionReceipt(transaction_hash);
  assert(receipt.execution_status.type == "SUCCEEDED");
}

/// CLI HELPERS

if (process.argv.length < 2) {
  console.error("Usage: ts-node register_new_identity.ts");
  process.exit(1);
}

register_new_identity();
