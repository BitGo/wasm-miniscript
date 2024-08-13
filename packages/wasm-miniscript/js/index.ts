import * as wasm from "./wasm/wasm_miniscript";

// we need to access the wasm module here, otherwise webpack gets all weird
// and forgets to include it in the bundle
void wasm;

export type DescriptorPkType = "derivable" | "definite" | "string";

export type ScriptContext = "tap" | "segwitv0" | "legacy";

declare module "./wasm/wasm_miniscript" {
  interface WrapDescriptor {
    node(): unknown;
  }

  namespace WrapDescriptor {
    function fromString(descriptor: string, pkType: DescriptorPkType): WrapDescriptor;
  }

  interface WrapMiniscript {
    node(): unknown;
  }

  namespace WrapMiniscript {
    function fromString(miniscript: string, ctx: ScriptContext): WrapMiniscript;
    function fromBitcoinScript(script: Uint8Array, ctx: ScriptContext): WrapMiniscript;
  }
}

export { WrapDescriptor as Descriptor } from "./wasm/wasm_miniscript";
export { WrapMiniscript as Miniscript } from "./wasm/wasm_miniscript";
export { WrapPsbt as Psbt } from "./wasm/wasm_miniscript";
