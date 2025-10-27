import * as wasm from "./wasm/wasm_utxo";

// we need to access the wasm module here, otherwise webpack gets all weird
// and forgets to include it in the bundle
void wasm;

export type DescriptorPkType = "derivable" | "definite" | "string";

export type ScriptContext = "tap" | "segwitv0" | "legacy";

export type SignPsbtResult = {
  [inputIndex: number]: [pubkey: string][];
};

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
}

import { Address as WasmAddress } from "./wasm/wasm_utxo";

export { WrapDescriptor as Descriptor } from "./wasm/wasm_utxo";
export { WrapMiniscript as Miniscript } from "./wasm/wasm_utxo";
export { WrapPsbt as Psbt } from "./wasm/wasm_utxo";
export { FixedScriptWallet } from "./wasm/wasm_utxo";

export namespace utxolibCompat {
  export const Address = WasmAddress;
}

export * as ast from "./ast";
