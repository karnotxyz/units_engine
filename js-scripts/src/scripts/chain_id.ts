import { UnitsProvider } from "../provider";
import dotenv from "dotenv";

dotenv.config();

async function get_chain_id() {
  const unitsProvider = new UnitsProvider(process.env.UNITS_RPC);

  const chainId = await unitsProvider.getChainId();

  console.log("✅ Chain ID: ", chainId);
}

/// CLI HELPERS

get_chain_id();
