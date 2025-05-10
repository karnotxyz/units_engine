import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";

dotenv.config();

async function transfer(token: string, amount: string, to: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  let { transaction_hash } = await unitsAccount.sendTransaction([
    {
      contractAddress: token,
      entrypoint: "transfer",
      calldata: [to, amount, 0],
    },
  ]);

  console.log("✅ Initiated transfer:", transaction_hash);

  const receipt = await unitsAccount.waitForTransaction(transaction_hash);
  console.log(receipt);
  assert(receipt.execution_status.type == "SUCCEEDED");
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error("Usage: ts-node transfer.ts <token> <amount> <to>");
  process.exit(1);
}

const token = process.argv[2];
const amount = process.argv[3];
const to = process.argv[4];

transfer(token, amount, to);
