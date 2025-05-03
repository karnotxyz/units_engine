import { UnitsAccount } from "../account";
import { UnitsProvider } from "../provider";
import dotenv from "dotenv";

dotenv.config();

async function call(
  contractAddress: string,
  entrypoint: string,
  calldata: string[],
) {
  console.log(process.env.UNITS_RPC);
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  const tx = await unitsAccount.call(contractAddress, entrypoint, calldata);

  console.log("✅ Send transaction response: ", tx);
}

/// CLI HELPERS

if (process.argv.length < 3) {
  console.error("Usage: ts-node get_receipt.ts <transaction-hash>");
  process.exit(1);
}

const contractAddress = process.argv[2];
const entrypoint = process.argv[3];
const calldata = process.argv.slice(4);

call(contractAddress, entrypoint, calldata);
