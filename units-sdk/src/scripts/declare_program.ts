import { hash } from "starknet";
import { getDefaultResourceBounds, UnitsAccount } from "../account.js";

export async function declareProgram(
  unitsAccount: UnitsAccount,
  programJson: any,
  compiledProgramJson: any,
) {
  const resourceBounds = getDefaultResourceBounds();
  resourceBounds.l2_gas.max_amount = 100000000; // setting a high value to avoud gas issues

  const declareProgramResponse = await unitsAccount.declareProgram(
    programJson,
    hash.computeCompiledClassHash(compiledProgramJson),
    "ACL",
    resourceBounds,
  );

  return {
    classHash: hash.computeContractClassHash(programJson),
    response: declareProgramResponse,
  };
}
