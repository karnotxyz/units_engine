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
    "0x01484c93b9d6cf61614d698ed069b3c6992c32549194fc3465258c2194734189", // pre declared account class hash on Dev
    "0x0",
    [await signer.getPubKey()],
    privateKey,
  );


  const deployAccountResponse = await unitsAccount.deploySelf();

  console.log("✅ Deploy account response: ", deployAccountResponse);
}

deploy_account();
