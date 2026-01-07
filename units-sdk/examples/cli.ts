import dotenv from "dotenv";
import fs from "fs";
import { UnitsProvider } from "../src/provider.js";
import { UnitsAccount } from "../src/account.js";
import { call } from "../src/scripts/call.js";
import { getChainId } from "../src/scripts/chain_id.js";
import { declareProgram } from "../src/scripts/declare_program.js";
import { deployAccount } from "../src/scripts/deploy_account.js";
import { deployProgram } from "../src/scripts/deploy_program.js";
import { getReceipt } from "../src/scripts/get_receipt.js";
import { sendTransaction } from "../src/scripts/send_transaction.js";

dotenv.config();

async function main() {
  const command = process.argv[2];
  const args = process.argv.slice(3);

  if (!command) {
    console.error("Please provide a command.");
    process.exit(1);
  }

  const rpcUrl = process.env.UNITS_RPC;
  if (!rpcUrl) {
    console.error("UNITS_RPC environment variable is not set.");
    process.exit(1);
  }
  const provider = new UnitsProvider(rpcUrl);

  // Helper to get account
  const getAccount = () => {
    const address = process.env.ACCOUNT_ADDRESS;
    const privateKey = process.env.PRIVATE_KEY;
    if (!address || !privateKey) {
      console.error(
        "ACCOUNT_ADDRESS and PRIVATE_KEY environment variables are required for this command."
      );
      process.exit(1);
    }
    return new UnitsAccount(provider, address, privateKey);
  };

  try {
    switch (command) {
      case "call":
        if (args.length < 2) {
          console.error(
            "Usage: call <contract-address> <entrypoint> [calldata...]"
          );
          process.exit(1);
        }
        const [callContract, callEntry, ...callData] = args;
        const result = await call(
          getAccount(),
          callContract,
          callEntry,
          callData
        );
        console.log("✅ Call response:", result);
        break;

      case "chain_id":
        const chainId = await getChainId(provider);
        console.log("✅ Chain ID:", chainId);
        break;

      case "declare_program":
        if (args.length < 2) {
          console.error(
            "Usage: declare_program <program-json-path> <compiled-program-json-path>"
          );
          process.exit(1);
        }
        const [progPath, compiledPath] = args;
        const programJson = JSON.parse(fs.readFileSync(progPath, "utf8"));
        const compiledJson = JSON.parse(fs.readFileSync(compiledPath, "utf8"));
        const declareRes = await declareProgram(
          getAccount(),
          programJson,
          compiledJson
        );
        console.log("ℹ️ Class hash:", declareRes.classHash);
        console.log("✅ Declare program response:", declareRes.response);
        break;

      case "deploy_account":
        const deployAccRes = await deployAccount(provider, getAccount());
        console.log("🔑 Private key:", deployAccRes.privateKey);
        console.log("✅ Deploy account response:", deployAccRes.response);
        break;

      case "deploy_program":
        if (args.length < 1) {
          console.error("Usage: deploy_program <class-hash>");
          process.exit(1);
        }
        const [classHash] = args;
        const deployProgRes = await deployProgram(getAccount(), classHash);
        console.log("✅ Deploy program response:", deployProgRes);
        break;

      case "get_receipt":
        if (args.length < 1) {
          console.error("Usage: get_receipt <transaction-hash>");
          process.exit(1);
        }
        const [txHash] = args;
        const receipt = await getReceipt(getAccount(), txHash);
        console.log("✅ Transaction receipt:", receipt);
        break;

      case "send_transaction":
        if (args.length < 2) {
          console.error(
            "Usage: send_transaction <contract-address> <entrypoint> [calldata...]"
          );
          process.exit(1);
        }
        const [sendContract, sendEntry, ...sendData] = args;
        const sendRes = await sendTransaction(
          getAccount(),
          sendContract,
          sendEntry,
          sendData
        );
        console.log("✅ Send transaction response:", sendRes.tx);
        console.log("✅ Transaction receipt:", sendRes.receipt);
        break;

      default:
        console.error(`Unknown command: ${command}`);
        console.error(
          "Available commands: call, chain_id, declare_program, deploy_account, deploy_program, get_receipt, send_transaction"
        );
        process.exit(1);
    }
  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  }
}

main();
