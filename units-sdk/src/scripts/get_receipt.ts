import { UnitsAccount } from "../account.js";

export async function getReceipt(
  unitsAccount: UnitsAccount,
  transactionHash: string,
) {
  const tx = await unitsAccount.getTransactionReceipt(transactionHash);
  return tx;
}
