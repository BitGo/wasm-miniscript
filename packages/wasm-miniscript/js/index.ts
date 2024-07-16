import * as wasm from "./wasm/wasm_miniscript";

// we need to access the wasm module here, otherwise webpack gets all weird
// and forgets to include it in the bundle
void wasm;

export type MiniscriptNode = unknown;

export type Miniscript = {
  node(): MiniscriptNode;
  toString(): string;
  encode(): Uint8Array;
  toAsmString(): string;
};

export function isMiniscript(obj: unknown): obj is Miniscript {
  return obj instanceof wasm.WrapMiniscript;
}

export type ScriptContext = "tap" | "segwitv0" | "legacy";

export function miniscriptFromString(script: string, scriptContext: ScriptContext): Miniscript {
  return wasm.miniscript_from_string(script, scriptContext);
}

export function miniscriptFromBitcoinScript(
  script: Uint8Array,
  scriptContext: ScriptContext,
): Miniscript {
  return wasm.miniscript_from_bitcoin_script(script, scriptContext);
}

export type DescriptorNode = unknown;

export type Descriptor = {
  node(): DescriptorNode;
  toString(): string;
  hasWildcard(): boolean;
  atDerivationIndex(index: number): Descriptor;
  encode(): Uint8Array;
  toAsmString(): string;
};

export function isDescriptor(obj: unknown): obj is Descriptor {
  return obj instanceof wasm.WrapDescriptor;
}

type DescriptorPkType = "derivable" | "definite" | "string";

export function descriptorFromString(descriptor: string, pkType: DescriptorPkType): Descriptor {
  return wasm.descriptor_from_string(descriptor, pkType);
}
