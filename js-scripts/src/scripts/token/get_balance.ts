import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";

dotenv.config();

async function getBalance(address: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY
  );

  let { result } = await unitsAccount.call(process.env.TOKEN, "balance_of", [
    address,
  ]);

  console.log("✅ Balance:", Number(result[2]));
}

/// CLI HELPERS

if (process.argv.length < 3) {
  console.error("Usage: ts-node get_balance.ts <address>");
  process.exit(1);
}

const address = process.argv[2];

getBalance(address);
