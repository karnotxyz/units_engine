import { UnitsAccount } from "../account.js";

export async function call(
  unitsAccount: UnitsAccount,
  contractAddress: string,
  entrypoint: string,
  calldata: string[]
) {
  const tx = await unitsAccount.call(contractAddress, entrypoint, calldata);
  return tx;
}
