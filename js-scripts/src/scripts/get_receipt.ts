import { UnitsAccount } from "../account";
import { UnitsProvider } from "../provider";
import dotenv from "dotenv";

dotenv.config();

async function get_receipt(transactionHash: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  const tx = await unitsAccount.getTransactionReceipt(transactionHash);

  console.log("✅ Send transaction response: ", tx);
}

/// CLI HELPERS

if (process.argv.length < 3) {
  console.error("Usage: ts-node get_receipt.ts <transaction-hash>");
  process.exit(1);
}

const transactionHash = process.argv[2];

get_receipt(transactionHash);
