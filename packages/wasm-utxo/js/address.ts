import { AddressNamespace } from "./wasm/wasm_utxo";
import type { CoinName } from "./coinName";

/**
 * Most coins only have one unambiguous address format (base58check and bech32/bech32m)
 * For Bitcoin Cash and eCash, we can select between base58check and cashaddr.
 */
export type AddressFormat = "default" | "cashaddr";

export function toOutputScriptWithCoin(address: string, coin: CoinName): Uint8Array {
  return AddressNamespace.to_output_script_with_coin(address, coin);
}

export function fromOutputScriptWithCoin(
  script: Uint8Array,
  coin: CoinName,
  format?: AddressFormat,
): string {
  return AddressNamespace.from_output_script_with_coin(script, coin, format);
}
