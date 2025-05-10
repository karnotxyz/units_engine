import { UnitsAccount } from "../account";
import { UnitsProvider } from "../provider";
import dotenv from "dotenv";

dotenv.config();

async function deploy_program(classHash: string) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  // Then deploy the program
  const deployProgramResponse = await unitsAccount.deployProgram(
    classHash,
    [],
    "0x" + new Date().getTime().toString(16),
  );

  console.log("✅ Deploy program response: ", deployProgramResponse);
}

/// CLI HELPERS

if (process.argv.length < 3) {
  console.error("Usage: ts-node deploy_program.ts <class-hash>");
  process.exit(1);
}

const classHash = process.argv[2];
deploy_program(classHash);
