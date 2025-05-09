import assert from "assert";
import { UnitsAccount } from "../../account";
import { UnitsProvider } from "../../provider";
import dotenv from "dotenv";
import { sleep } from "./utils";

dotenv.config();

async function add_compliance_check(token: string, compliance_module: string) {
  console.log(process.env.UNITS_RPC);
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  let { transaction_hash } = await unitsAccount.sendTransaction([
    {
      contractAddress: token,
      entrypoint: "add_compliance_check",
      calldata: [compliance_module],
    },
  ]);

  await sleep(2000);
  console.log("✅ Initiated adding claim check:", transaction_hash);

  const receipt = await unitsAccount.getTransactionReceipt(transaction_hash);
  console.log(receipt);
  assert(receipt.execution_status.type == "SUCCEEDED");
}

/// CLI HELPERS

if (process.argv.length < 3) {
  console.error("Usage: ts-node add_compliance_check.ts <token>");
  process.exit(1);
}

const token = process.argv[2];
const compliance_module = process.env.COMPLIANCE_MODULE;

add_compliance_check(token, compliance_module);
