import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";
import { selector } from "starknet";

dotenv.config();

async function grantBalanceRead(address: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  let { transaction_hash } = await unitsAccount.sendTransaction([
    {
      contractAddress: process.env.TOKEN,
      entrypoint: "give_approval",
      calldata: [
        selector.getSelectorFromName("balance_of"), // function giving approval for
        address, // address getting approved
        // calldata that the `address` is allowed to read
        1,
        process.env.ACCOUNT_ADDRESS,
      ],
    },
  ]);

  const receipt = await unitsAccount.waitForTransaction(transaction_hash);
  assert(receipt.execution_status.type == "SUCCEEDED");

  console.log("✅ Granted balance read to:", address);
}

/// CLI HELPERS

if (process.argv.length < 3) {
  console.error("Usage: ts-node grant_balance_read.ts <address>");
  process.exit(1);
}

const address = process.argv[2];

grantBalanceRead(address);
