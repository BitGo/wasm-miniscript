import * as wasm from "./wasm/wasm_miniscript";

type MiniscriptNode = unknown;

type Miniscript = {
  node(): MiniscriptNode;
  toString(): string;
  encode(): Uint8Array;
};

type ScriptContext = "tap" | "segwitv0" | "legacy";

export function miniscriptFromString(script: string, scriptContext: ScriptContext): Miniscript {
  return wasm.miniscript_from_string(script, scriptContext);
}

export function miniscriptFromBitcoinScript(
  script: Uint8Array,
  scriptContext: ScriptContext,
): Miniscript {
  return wasm.miniscript_from_bitcoin_script(script, scriptContext);
}

type DescriptorNode = unknown;

type Descriptor = {
  node(): DescriptorNode;
  toString(): string;
};

export function descriptorFromString(descriptor: string): Descriptor {
  return wasm.descriptor_from_string(descriptor);
}
