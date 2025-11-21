import { hash } from "starknet";
import { getDefaultResourceBounds, UnitsAccount } from "../account";
import { UnitsProvider } from "../provider";
import dotenv from "dotenv";
import fs from "fs";

dotenv.config();

async function declare_program(programJson: any, compiledProgramJson: any) {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);
  const unitsAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

  const resourceBounds = getDefaultResourceBounds();
  resourceBounds.l2_gas.max_amount = 100000000; // setting a high value to avoud gas issues
  const declareProgramResponse = await unitsAccount.declareProgram(
    programJson,
    hash.computeCompiledClassHash(compiledProgramJson),
    "ACL",
    resourceBounds,
  );

  console.log("ℹ️ Class hash: ", hash.computeContractClassHash(programJson));
  console.log("✅ Declare program response: ", declareProgramResponse);
}

/// CLI HELPERS

if (process.argv.length < 4) {
  console.error(
    "Usage: ts-node declare_program.ts <program-json-path> <compiled-program-json-path>",
  );
  process.exit(1);
}

const programJsonPath = process.argv[2];
const compiledProgramJsonPath = process.argv[3];

const programJson = JSON.parse(fs.readFileSync(programJsonPath, "utf8"));
const compiledProgramJson = JSON.parse(
  fs.readFileSync(compiledProgramJsonPath, "utf8"),
);
declare_program(programJson, compiledProgramJson);
