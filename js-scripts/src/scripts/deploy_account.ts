import { Signer } from "starknet";
import { UnitsAccount } from "../account";
import { UnitsProvider } from "../provider";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

async function deploy_account() {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);

  const privateKey = "0x" + crypto.randomBytes(31).toString("hex");
  console.log("🔑 Private key: ", privateKey);
  const signer = new Signer(privateKey);
  const unitsAccount = UnitsAccount.newUndeployedAccount(
    unitsProvider,
    "0xe2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6", // pre declared account class hash on Dev
    "0x0",
    [await signer.getPubKey()],
    privateKey,
  );
  await fund_account(unitsProvider, unitsAccount.getAddress());

  const deployAccountResponse = await unitsAccount.deploySelf();

  console.log("✅ Deploy account response: ", deployAccountResponse);
}

async function fund_account(
  unitsProvider: UnitsProvider,
  accountAddress: string,
) {
  const ownerAccount = new UnitsAccount(
    unitsProvider,
    process.env.ACCOUNT_ADDRESS,
    process.env.PRIVATE_KEY,
  );

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
  console.log("✅ Fund account response: ", receipt);
}

deploy_account();
