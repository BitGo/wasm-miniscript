import { AddressNamespace } from "./wasm/wasm_utxo";
import type { CoinName } from "./coinName";

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
