import * as miniscript from "@bitgo/wasm-miniscript";

import "./style.css";

import { getElement } from "./html";
import { buildOptions, getOptions, Options } from "./options";
import { getHtmlForAst } from "./htmlAST";
import {
  isDescriptor,
  isMiniscript,
  Miniscript,
  Descriptor,
} from "@bitgo/wasm-miniscript";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hex string must have an even number of characters");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function parseInput(
  inputValue: string,
  options: Options,
): miniscript.Miniscript | miniscript.Descriptor {
  switch (options.inputType) {
    case "descriptor":
      return miniscript.descriptorFromString(inputValue, "derivable");
    case "miniscript":
      return miniscript.miniscriptFromString(inputValue, options.scriptContext);
    default:
      throw new Error(`unknown input type ${options.inputType}`);
  }
}

function toScriptBuf(obj: Miniscript | Descriptor): Uint8Array {
  if (isDescriptor(obj)) {
    return obj.atDerivationIndex(0).encode();
  }
  if (isMiniscript(obj)) {
    return obj.encode();
  }
  throw new Error("unknown object type");
}

function toAsm(obje: Miniscript | Descriptor): string {
  if (isDescriptor(obje)) {
    return obje.atDerivationIndex(0).toAsmString();
  }
  if (isMiniscript(obje)) {
    return obje.toAsmString();
  }
  throw new Error("unknown object type");
}

const elEditDescriptor = getElement("edit-descriptor", HTMLTextAreaElement);
const elEditBitcoinScript = getElement(
  "edit-bitcoin-script",
  HTMLTextAreaElement,
);
const elOutputAst = getElement("output-ast", HTMLDivElement);
const elStatus = getElement("status", HTMLElement);

function applyUpdate(changedEl: HTMLElement, options: Options) {
  console.log(changedEl, options);

  if (changedEl === getElement("input-example", HTMLElement)) {
    elEditDescriptor.value = options.example;
    return applyUpdate(elEditDescriptor, options);
  }

  elEditBitcoinScript.readOnly = options.inputType !== "miniscript";

  if (changedEl === elEditBitcoinScript && options.inputType === "miniscript") {
    const inputBytes = elEditBitcoinScript.value;
    const obj = miniscript.miniscriptFromBitcoinScript(
      fromHex(inputBytes),
      options.scriptContext,
    );
    elEditDescriptor.value = obj.toString();
    return applyUpdate(elEditDescriptor, options);
  }

  const inputDescriptor = elEditDescriptor.value;
  const obj = parseInput(inputDescriptor, options);

  switch (options.bitcoinScriptFormat) {
    case "hex":
      elEditBitcoinScript.value = toHex(toScriptBuf(obj));
      break;
    case "asm":
      elEditBitcoinScript.value = toAsm(obj);
      break;
    default:
      throw new Error(
        `unknown bitcoin script format ${options.bitcoinScriptFormat}`,
      );
  }

  const ast = getHtmlForAst(obj.node());
  elOutputAst.innerHTML = "";
  elOutputAst.appendChild(ast);

  elStatus.innerText = "Status: OK";
}

function update(changedEl: HTMLElement, options: Options) {
  try {
    elStatus.innerText = "";
    elEditBitcoinScript.value = "";
    elOutputAst.innerHTML = "";
    applyUpdate(changedEl, options);
  } catch (e: any) {
    console.error(e);
    elStatus.innerText = `Status: Error: ${e}`;
  }
}

function bindUpdate(el: HTMLElement, event: string) {
  el.addEventListener(event, () => {
    update(el, getOptions());
  });
}

buildOptions();

document.querySelectorAll("select").forEach((el) => {
  bindUpdate(el, "change");
});

bindUpdate(elEditDescriptor, "input");
bindUpdate(elEditBitcoinScript, "input");

update(getElement("input-example", HTMLElement), getOptions());

window.addEventListener("error", (event) => {
  console.error(event);
  event.preventDefault();
});
