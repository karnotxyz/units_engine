import { Signer } from "starknet";
import { UnitsAccount } from "../account.js";
import { UnitsProvider } from "../provider.js";
import crypto from "crypto";

export async function deployAccount(
  unitsProvider: UnitsProvider,
  funderAccount: UnitsAccount
) {
  const privateKey = "0x" + crypto.randomBytes(31).toString("hex");
  const signer = new Signer(privateKey);
  const unitsAccount = UnitsAccount.newUndeployedAccount(
    unitsProvider,
    "0xe2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6", // pre declared account class hash on Dev
    "0x0",
    [await signer.getPubKey()],
    privateKey,
  );
  
  await fundAccount(funderAccount, unitsAccount.getAddress());

  const deployAccountResponse = await unitsAccount.deploySelf();

  return {
    privateKey,
    address: unitsAccount.getAddress(),
    response: deployAccountResponse
  };
}

async function fundAccount(
  ownerAccount: UnitsAccount,
  accountAddress: string,
) {
  const fundAccountResponse = await ownerAccount.sendTransaction([
    {
      contractAddress:
        "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d", // STRK token address
      entrypoint: "transfer",
      calldata: [accountAddress, "1000000000000000000", 0],
    },
  ]);

  const receipt = await ownerAccount.waitForTransaction(
    fundAccountResponse.transaction_hash,
  );
  return receipt;
}
