import { FixedScriptWalletNamespace } from "./wasm/wasm_utxo";
import type { UtxolibNetwork, UtxolibRootWalletKeys } from "./utxolibCompat";
import { Triple } from "./triple";

export type WalletKeys =
  /** Just an xpub triple, will assume default derivation prefixes  */
  | Triple<string>
  /** Compatible with utxolib RootWalletKeys */
  | UtxolibRootWalletKeys;

/**
 * Create the output script for a given wallet keys and chain and index
 */
export function outputScript(keys: WalletKeys, chain: number, index: number): Uint8Array {
  return FixedScriptWalletNamespace.output_script(keys, chain, index);
}

/**
 * Create the address for a given wallet keys and chain and index and network.
 * Wrapper for outputScript that also encodes the script to an address.
 */
export function address(
  keys: WalletKeys,
  chain: number,
  index: number,
  network: UtxolibNetwork,
): string {
  return FixedScriptWalletNamespace.address(keys, chain, index, network);
}
