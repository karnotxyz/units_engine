import { UnitsAccount } from "../account";
import { UnitsProvider } from "../provider";
import dotenv from "dotenv";

dotenv.config();

async function send_transaction(
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

  const tx = await unitsAccount.sendTransaction([
    {
      contractAddress,
      calldata,
      entrypoint,
    },
  ]);

  console.log("✅ Send transaction response: ", tx);

  // Wait for receipt
  let receipt = null;
  for (let i = 0; i < 10; i++) {
    try {
      receipt = await unitsAccount.getTransactionReceipt(tx.transaction_hash);
      if (receipt) {
        console.log("✅ Transaction receipt: ", receipt);
        break;
      }
    } catch (error) {
      console.log(`Failed to get receipt, retrying... (${i + 1}/10)`);
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  if (!receipt) {
    console.log("❌ Failed to get transaction receipt after 10 attempts");
  }
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error(
    "Usage: ts-node send_transaction.ts <contract-address> <entrypoint> [calldata...]",
  );
  process.exit(1);
}

const contractAddress = process.argv[2];
const entrypoint = process.argv[3];
const calldata = process.argv.slice(4);

send_transaction(contractAddress, entrypoint, calldata);
