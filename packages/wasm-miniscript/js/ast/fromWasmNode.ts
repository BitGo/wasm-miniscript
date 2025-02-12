import assert from "node:assert";
import { DescriptorNode, MiniscriptNode } from "./formatNode";
import { Descriptor } from "../index";

function getSingleEntry(v: unknown): [string, unknown] {
  if (typeof v === "object" && v) {
    const entries = Object.entries(v);
    if (entries.length === 1) {
      return entries[0];
    }
  }

  throw new Error("Expected single entry object");
}

function node(type: string, value: unknown): MiniscriptNode | DescriptorNode {
  return { [type]: fromUnknown(value) } as MiniscriptNode | DescriptorNode;
}

function wrap(type: string, value: unknown): MiniscriptNode {
  const n = fromWasmNode(value);
  const [name, inner] = getSingleEntry(n);
  return { [`${type}:${name}`]: inner } as MiniscriptNode;
}

type Node = DescriptorNode | MiniscriptNode | string | number;

export function fromUnknown(v: unknown): Node | Node[] {
  if (typeof v === "number" || typeof v === "string") {
    return v;
  }
  if (Array.isArray(v)) {
    return v.map(fromUnknown) as Node[];
  }
  if (typeof v === "object" && v) {
    const [type, value] = getSingleEntry(v);
    switch (type) {
      case "Bare":
      case "Single":
      case "Ms":
      case "XPub":
      case "relLockTime":
      case "absLockTime":
        return fromUnknown(value);
      case "Sh":
      case "Wsh":
      case "Pk":
      case "Pkh":
      case "Wpkh":
      case "Combo":
      case "SortedMulti":
      case "Addr":
      case "Raw":
      case "RawTr":
        return node(type.toLocaleLowerCase(), value);
      case "Tr":
        return node("tr", value);
      case "PkK":
        return node("pk", value);
      case "PkH":
        return node("pkh", value);
      case "RawPkH":
        return node("raw_pkh", value);

      // Timelocks
      case "After":
        return node("after", value);
      case "Older":
        return node("older", value);

      // Hashlocks
      case "Sha256":
        return node("sha256", value);
      case "Hash256":
        return node("hash256", value);
      case "Ripemd160":
        return node("ripemd160", value);
      case "Hash160":
        return node("hash160", value);

      // Wrappers
      case "Alt":
        return wrap("a", value);
      case "Swap":
        return wrap("s", value);
      case "Check":
        return fromUnknown(value);
      case "DupIf":
        return wrap("d", value);
      case "Verify":
        return wrap("v", value);
      case "ZeroNotEqual":
        return wrap("n", value);

      // Conjunctions
      case "AndV":
        return node("and_v", value);
      case "AndB":
        return node("and_b", value);
      case "AndOr":
        assert(Array.isArray(value));
        const [cond, success, failure] = value;
        if (failure === false) {
          return node("and_n", [cond, success]);
        }
        return node("andor", [cond, success, failure]);

      // Disjunctions
      case "OrB":
        return node("or_b", value);
      case "OrD":
        return node("or_d", value);
      case "OrC":
        return node("or_c", value);
      case "OrI":
        return node("or_i", value);

      // Thresholds
      case "Thresh":
        return node("thresh", value);
      case "Multi":
        return node("multi", value);
      case "MultiA":
        return node("multi_a", value);
    }
  }

  throw new Error(`Unknown node ${JSON.stringify(v)}`);
}

function fromWasmNode(v: unknown): DescriptorNode | MiniscriptNode {
  return fromUnknown(v) as DescriptorNode | MiniscriptNode;
}

export function fromDescriptor(d: Descriptor): DescriptorNode {
  return fromWasmNode(d.node()) as DescriptorNode;
}
