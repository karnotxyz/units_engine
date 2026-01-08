import { UnitsAccount } from "../account.js";

export async function sendTransaction(
  unitsAccount: UnitsAccount,
  contractAddress: string,
  entrypoint: string,
  calldata: string[],
) {
  const tx = await unitsAccount.sendTransaction([
    {
      contractAddress,
      calldata,
      entrypoint,
    },
  ]);

  // Wait for receipt
  const receipt = await unitsAccount.waitForTransaction(tx.transaction_hash);

  return {
    tx,
    receipt,
  };
}
