import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";

dotenv.config();

async function transfer(amount: string, to: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY
  );

  let { transaction_hash } = await unitsAccount.sendTransaction([
    {
      contractAddress: process.env.TOKEN,
      entrypoint: "transfer",
      calldata: [to, amount, 0],
    },
  ]);

  const receipt = await unitsAccount.waitForTransaction(transaction_hash);
  if (receipt.execution_status.type != "SUCCEEDED") {
    console.error("❌ Transfer failed:", receipt);
    process.exit(1);
  }

  console.log("✅ Transferred:", amount, "to:", to);
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error("Usage: ts-node transfer.ts <amount> <to>");
  process.exit(1);
}

const amount = process.argv[2];
const to = process.argv[3];

transfer(amount, to);
