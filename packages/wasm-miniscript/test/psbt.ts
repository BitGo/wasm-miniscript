import * as utxolib from "@bitgo/utxo-lib";
import * as assert from "node:assert";
import { getPsbtFixtures } from "./psbtFixtures";
import { Descriptor, Psbt } from "../js";

import { getDescriptorForScriptType } from "./descriptorUtil";
import { toUtxoPsbt, toWrappedPsbt } from "./psbt.util";

const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(utxolib.testutil.getKeyTriple("wasm"));

function assertEqualBuffer(a: Buffer | Uint8Array, b: Buffer | Uint8Array, message?: string) {
  assert.strictEqual(Buffer.from(a).toString("hex"), Buffer.from(b).toString("hex"), message);
}

const fixtures = getPsbtFixtures(rootWalletKeys);

function describeUpdateInputWithDescriptor(
  psbt: utxolib.bitgo.UtxoPsbt,
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
) {
  const fullSignedFixture = fixtures.find(
    (f) => f.scriptType === scriptType && f.stage === "fullsigned",
  );
  if (!fullSignedFixture) {
    throw new Error("Could not find fullsigned fixture");
  }

  describe("updateInputWithDescriptor", function () {
    it("should update the input with the descriptor", function () {
      const descriptorStr = getDescriptorForScriptType(rootWalletKeys, scriptType, "internal");
      const index = 0;
      const descriptor = Descriptor.fromString(descriptorStr, "derivable");
      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.updateInputWithDescriptor(0, descriptor.atDerivationIndex(index));
      const updatedPsbt = toUtxoPsbt(wrappedPsbt);
      updatedPsbt.signAllInputsHD(rootWalletKeys.triple[0]);
      updatedPsbt.signAllInputsHD(rootWalletKeys.triple[2]);
      const wrappedSignedPsbt = toWrappedPsbt(updatedPsbt);
      updatedPsbt.finalizeAllInputs();
      wrappedSignedPsbt.finalize();

      assertEqualBuffer(updatedPsbt.toBuffer(), wrappedSignedPsbt.serialize());

      assertEqualBuffer(
        fullSignedFixture.psbt.clone().finalizeAllInputs().extractTransaction().toBuffer(),
        updatedPsbt.extractTransaction().toBuffer(),
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
