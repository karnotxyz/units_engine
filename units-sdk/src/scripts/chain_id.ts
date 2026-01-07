import { UnitsProvider } from "../provider.js";

export async function getChainId(unitsProvider: UnitsProvider) {
  const chainId = await unitsProvider.getChainId();
  return chainId;
}
