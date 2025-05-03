import { Signer } from "starknet";
import { UnitsAccount } from "../account";
import { UnitsProvider } from "../provider";
import dotenv from "dotenv";

dotenv.config();

async function deploy_account() {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);

  const privateKey = "0x123";
  const signer = new Signer(privateKey);
  const unitsAccount = UnitsAccount.newUndeployedAccount(
    unitsProvider,
    "0x00e2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6", // pre declared account class hash on Dev
    "0x0",
    [await signer.getPubKey()],
    privateKey,
  );

  const deployAccountResponse = await unitsAccount.deploySelf();

  console.log("✅ Deploy account response: ", deployAccountResponse);
}

deploy_account();
