import * as t from "io-ts";
import { isLeft } from "fp-ts/Either";
import { PathReporter } from "io-ts/PathReporter";
import { fixtures } from "./descriptorFixtures";
import { getElement } from "./html";

function decodeOrThrow<A, O, I>(codec: t.Type<A, O, I>, value: I): A {
  const result = codec.decode(value);
  if (isLeft(result)) {
    throw new Error(PathReporter.report(result).join("\n"));
  }
  return result.right;
}

function getOption(id: string): unknown {
  const el = getElement(id, HTMLElement);
  if (el instanceof HTMLSelectElement) {
    return el.value;
  }
  if (el instanceof HTMLInputElement) {
    return el.value;
  }
  throw new Error(`element with id ${id} is not a select or input`);
}

function showOutput(output: string) {
  const outputElement = document.getElementById("output");
  if (!outputElement) {
    throw new Error("output element not found");
  }
  outputElement.innerText = output;
}

type DropdownItem = {
  label: string;
  value: string;
};

export function getExampleOptions(
  index: number | undefined = 41,
): DropdownItem[] {
  let valid = fixtures.valid;
  if (index !== undefined) {
    valid = [valid[index]];
  }
  return valid.map((fixture, i) => {
    return {
      label: `Example ${i}: ${fixture.descriptor.slice(0, 16)}...`,
      value: fixture.descriptor,
    };
  });
}

function buildSelect(
  elSelect: HTMLSelectElement,
  options: DropdownItem[],
): void {
  options.forEach((option) => {
    const optionElement = document.createElement("option");
    optionElement.value = option.value;
    optionElement.innerText = option.label;
    elSelect.appendChild(optionElement);
  });
}

function buildDivLabelSelect(
  label: string,
  id: string,
  options: DropdownItem[],
): HTMLElement {
  const container = document.createElement("div");
  const labelElement = document.createElement("label");
  labelElement.innerText = label;
  labelElement.htmlFor = id;
  container.appendChild(labelElement);
  const select = document.createElement("select");
  select.id = id;
  buildSelect(select, options);
  container.appendChild(select);
  return container;
}

/*
export function buildOptions(): HTMLElement[] {
  return [
    buildSelect("Input Type", "input-type", [
      { label: "Descriptor", value: "descriptor" },
      { label: "Miniscript", value: "miniscript" },
    ]),
    buildSelect("Script Context", "script-context", [
      { label: "Tap", value: "tap" },
      { label: "Segwitv0", value: "segwitv0" },
      { label: "Legacy", value: "legacy" },
    ]),
    buildSelect("Load Example", "example", getExampleOptions()),
  ];
}

 */

function getOptionsFromUnion(u: t.UnionType<t.Any[]>): DropdownItem[] {
  return u.types.map((e) => {
    if (e instanceof t.LiteralType) {
      return { label: e.value, value: e.value };
    }
    throw new Error(`unexpected type ${t}`);
  });
}

export function getOptionsFromType(c: t.Type<any>): DropdownItem[] {
  if (c instanceof t.UnionType) {
    return getOptionsFromUnion(c);
  }
  throw new Error(`unexpected type ${c}`);
}

export const InputType = t.union([
  t.literal("descriptor"),
  t.literal("miniscript"),
]);

export const ScriptContext = t.union([
  t.literal("tap"),
  t.literal("segwitv0"),
  t.literal("legacy"),
]);

export const BitcoinScriptFormat = t.union([
  t.literal("hex"),
  t.literal("asm"),
]);

export const Options = t.type({
  inputType: InputType,
  scriptContext: ScriptContext,
  bitcoinScriptFormat: BitcoinScriptFormat,
  example: t.string,
});

export type Options = t.TypeOf<typeof Options>;

export function buildOptions(): void {
  buildSelect(
    getElement("input-type", HTMLSelectElement),
    getOptionsFromType(InputType),
  );
  buildSelect(
    getElement("input-script-context", HTMLSelectElement),
    getOptionsFromType(ScriptContext),
  );
  buildSelect(
    getElement("input-example", HTMLSelectElement),
    getExampleOptions(),
  );
  buildSelect(
    getElement("input-bitcoin-script", HTMLSelectElement),
    getOptionsFromType(BitcoinScriptFormat),
  );
}

export function getOptions(): Options {
  return decodeOrThrow(Options, {
    inputType: getOption("input-type"),
    scriptContext: getOption("input-script-context"),
    bitcoinScriptFormat: getOption("input-bitcoin-script"),
    example: getOption("input-example"),
  });
}
