import * as wasm from "./wasm/wasm_utxo";

// we need to access the wasm module here, otherwise webpack gets all weird
// and forgets to include it in the bundle
void wasm;

export type DescriptorPkType = "derivable" | "definite" | "string";

export type ScriptContext = "tap" | "segwitv0" | "legacy";

export type AddressFormat = "default" | "cashaddr";

export type SignPsbtResult = {
  [inputIndex: number]: [pubkey: string][];
};

// BitGo coin names (from Network::from_coin_name in src/networks.rs)
export type CoinName =
  | "btc"
  | "tbtc"
  | "tbtc4"
  | "tbtcsig"
  | "tbtcbgsig"
  | "bch"
  | "tbch"
  | "bcha"
  | "tbcha"
  | "btg"
  | "tbtg"
  | "bsv"
  | "tbsv"
  | "dash"
  | "tdash"
  | "doge"
  | "tdoge"
  | "ltc"
  | "tltc"
  | "zec"
  | "tzec";

declare module "./wasm/wasm_utxo" {
  interface WrapDescriptor {
    /** These are not the same types of nodes as in the ast module */
    node(): unknown;
  }

  namespace WrapDescriptor {
    function fromString(descriptor: string, pkType: DescriptorPkType): WrapDescriptor;
    function fromStringDetectType(descriptor: string): WrapDescriptor;
  }

  interface WrapMiniscript {
    /** These are not the same types of nodes as in the ast module */
    node(): unknown;
  }

  namespace WrapMiniscript {
    function fromString(miniscript: string, ctx: ScriptContext): WrapMiniscript;
    function fromBitcoinScript(script: Uint8Array, ctx: ScriptContext): WrapMiniscript;
  }

  interface WrapPsbt {
    signWithXprv(this: WrapPsbt, xprv: string): SignPsbtResult;
    signWithPrv(this: WrapPsbt, prv: Uint8Array): SignPsbtResult;
  }

  interface Address {
    /**
     * Convert output script to address string
     * @param script - The output script as a byte array
     * @param network - The utxolib Network object from JavaScript
     * @param format - Optional address format: "default" or "cashaddr" (only applicable for Bitcoin Cash and eCash)
     */
    fromOutputScript(script: Uint8Array, network: any, format?: AddressFormat): string;
    /**
     * Convert address string to output script
     * @param address - The address string
     * @param network - The utxolib Network object from JavaScript
     * @param format - Optional address format (currently unused for decoding as all formats are accepted)
     */
    toOutputScript(address: string, network: any, format?: AddressFormat): Uint8Array;
  }
}

import { Address as WasmAddress } from "./wasm/wasm_utxo";

export { WrapDescriptor as Descriptor } from "./wasm/wasm_utxo";
export { WrapMiniscript as Miniscript } from "./wasm/wasm_utxo";
export { WrapPsbt as Psbt } from "./wasm/wasm_utxo";
export { FixedScriptWallet } from "./wasm/wasm_utxo";

export namespace utxolibCompat {
  export const Address = WasmAddress;
}

export function toOutputScriptWithCoin(address: string, coin: CoinName): Uint8Array {
  return wasm.toOutputScriptWithCoin(address, coin);
}

export function fromOutputScriptWithCoin(
  script: Uint8Array,
  coin: CoinName,
  format?: AddressFormat,
): string {
  return wasm.fromOutputScriptWithCoin(script, coin, format);
}

export * as ast from "./ast";
