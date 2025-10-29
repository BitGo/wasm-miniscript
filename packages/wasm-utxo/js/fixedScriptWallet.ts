import { FixedScriptWalletNamespace } from "./wasm/wasm_utxo";
import type { UtxolibNetwork, UtxolibRootWalletKeys } from "./utxolibCompat";
import { Triple } from "./triple";
import { AddressFormat } from "./address";

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
 * @param keys - The wallet keys to use.
 * @param chain - The chain to use.
 * @param index - The index to use.
 * @param network - The network to use.
 * @param addressFormat - The address format to use.
 *   Only relevant for Bitcoin Cash and eCash networks, where:
 *   - "default" means base58check,
 *   - "cashaddr" means cashaddr.
 */
export function address(
  keys: WalletKeys,
  chain: number,
  index: number,
  network: UtxolibNetwork,
  addressFormat?: AddressFormat,
): string {
  return FixedScriptWalletNamespace.address(keys, chain, index, network, addressFormat);
}
