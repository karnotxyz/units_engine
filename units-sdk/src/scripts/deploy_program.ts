import { UnitsAccount } from "../account.js";

export async function deployProgram(
  unitsAccount: UnitsAccount,
  classHash: string
) {
  // Then deploy the program
  const deployProgramResponse = await unitsAccount.deployProgram(
    classHash,
    [],
    "0x" + new Date().getTime().toString(16)
  );

  return deployProgramResponse;
}
