import * as utxolib from "@bitgo/utxo-lib";
import * as assert from "node:assert";
import { getPsbtFixtures, PsbtStage } from "./psbtFixtures";
import { Descriptor, Psbt } from "../js";

import { getDescriptorForScriptType } from "./descriptorUtil";
import { assertEqualPsbt, toUtxoPsbt, toWrappedPsbt, updateInputWithDescriptor } from "./psbt.util";

const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(utxolib.testutil.getKeyTriple("wasm"));

function assertEqualBuffer(a: Buffer | Uint8Array, b: Buffer | Uint8Array, message?: string) {
  assert.strictEqual(Buffer.from(a).toString("hex"), Buffer.from(b).toString("hex"), message);
}

const fixtures = getPsbtFixtures(rootWalletKeys);

function getWasmDescriptor(
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
  scope: "internal" | "external",
) {
  return Descriptor.fromString(
    getDescriptorForScriptType(rootWalletKeys, scriptType, scope),
    "derivable",
  );
}

function describeUpdateInputWithDescriptor(
  psbt: utxolib.bitgo.UtxoPsbt,
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
) {
  function getFixtureAtStage(stage: PsbtStage) {
    const f = fixtures.find((f) => f.scriptType === scriptType && f.stage === stage);
    if (!f) {
      throw new Error(`Could not find fixture for scriptType ${scriptType} and stage ${stage}`);
    }
    return f;
  }

  const descriptorStr = getDescriptorForScriptType(rootWalletKeys, scriptType, "internal");
  const index = 0;
  const descriptor = Descriptor.fromString(descriptorStr, "derivable");

  describe("Wrapped PSBT updateInputWithDescriptor", function () {
    it("should update the input with the descriptor", function () {
      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.updateInputWithDescriptor(0, descriptor.atDerivationIndex(index));
      wrappedPsbt.updateOutputWithDescriptor(0, descriptor.atDerivationIndex(index));
      const updatedPsbt = toUtxoPsbt(wrappedPsbt);
      assertEqualPsbt(updatedPsbt, getFixtureAtStage("unsigned").psbt);
      updatedPsbt.signAllInputsHD(rootWalletKeys.triple[0]);
      updatedPsbt.signAllInputsHD(rootWalletKeys.triple[2]);
      const wrappedSignedPsbt = toWrappedPsbt(updatedPsbt);
      updatedPsbt.finalizeAllInputs();
      wrappedSignedPsbt.finalize();

      assertEqualBuffer(updatedPsbt.toBuffer(), wrappedSignedPsbt.serialize());

      assertEqualBuffer(
        getFixtureAtStage("fullsigned")
          .psbt.clone()
          .finalizeAllInputs()
          .extractTransaction()
          .toBuffer(),
        updatedPsbt.extractTransaction().toBuffer(),
      );
    });
  });

  describe("updateInputWithDescriptor util", function () {
    it("should update the input with the descriptor", function () {
      const cloned = psbt.clone();
      updateInputWithDescriptor(cloned, 0, descriptor.atDerivationIndex(index));
      cloned.signAllInputsHD(rootWalletKeys.triple[0]);
      cloned.signAllInputsHD(rootWalletKeys.triple[2]);
      cloned.finalizeAllInputs();

      assertEqualBuffer(
        getFixtureAtStage("fullsigned")
          .psbt.clone()
          .finalizeAllInputs()
          .extractTransaction()
          .toBuffer(),
        cloned.extractTransaction().toBuffer(),
      );
    });
  });
}

fixtures.forEach(({ psbt, scriptType, stage }) => {
  describe(`PSBT fixture ${scriptType} ${stage}`, function () {
    let buf: Buffer;
    let wrappedPsbt: Psbt;

    before(function () {
      buf = psbt.toBuffer();
      wrappedPsbt = toWrappedPsbt(buf);
    });

    it("should map to same hex", function () {
      assertEqualBuffer(buf, wrappedPsbt.serialize());
    });

    it("should round-trip utxolib -> ms -> utxolib", function () {
      assertEqualBuffer(buf, toUtxoPsbt(wrappedPsbt).toBuffer());
    });

    if (stage === "bare") {
      describeUpdateInputWithDescriptor(psbt, scriptType);
    }
  });
});
