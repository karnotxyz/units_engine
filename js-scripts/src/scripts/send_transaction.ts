import { UnitsAccount } from "../account";
import { UnitsProvider } from "../provider";
import dotenv from "dotenv";

dotenv.config();

async function send_transaction(
  contractAddress: string,
  entrypoint: string,
  calldata: string[]
) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY
  );

  const tx = await unitsAccount.sendTransaction([
    {
      contractAddress,
      calldata,
      entrypoint,
    },
  ]);

  console.log("✅ Send transaction response: ", tx);

  // Wait for receipt
  const receipt = await unitsAccount.waitForTransaction(tx.transaction_hash);
  console.log("✅ Transaction receipt: ", receipt);
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error(
    "Usage: ts-node send_transaction.ts <contract-address> <entrypoint> [calldata...]"
  );
  process.exit(1);
}

const contractAddress = process.argv[2];
const entrypoint = process.argv[3];
const calldata = process.argv.slice(4);

send_transaction(contractAddress, entrypoint, calldata);
