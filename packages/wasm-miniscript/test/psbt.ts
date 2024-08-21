import * as utxolib from "@bitgo/utxo-lib";
import * as assert from "node:assert";
import { getPsbtFixtures, toPsbtWithPrevOutOnly } from "./psbtFixtures";
import { Descriptor, Psbt } from "../js";

import { getDescriptorForScriptType } from "./descriptorUtil";

const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(utxolib.testutil.getKeyTriple("wasm"));

function toWrappedPsbt(psbt: utxolib.bitgo.UtxoPsbt | Buffer | Uint8Array) {
  if (psbt instanceof utxolib.bitgo.UtxoPsbt) {
    psbt = psbt.toBuffer();
  }
  if (psbt instanceof Buffer || psbt instanceof Uint8Array) {
    return Psbt.deserialize(psbt);
  }
  throw new Error("Invalid input");
}

function toUtxoPsbt(psbt: Psbt | Buffer | Uint8Array) {
  if (psbt instanceof Psbt) {
    psbt = psbt.serialize();
  }
  if (psbt instanceof Buffer || psbt instanceof Uint8Array) {
    return utxolib.bitgo.UtxoPsbt.fromBuffer(Buffer.from(psbt), {
      network: utxolib.networks.bitcoin,
    });
  }
  throw new Error("Invalid input");
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
      const wrappedPsbt = toWrappedPsbt(toPsbtWithPrevOutOnly(psbt));
      wrappedPsbt.updateInputWithDescriptor(0, descriptor.atDerivationIndex(index));
      const updatedPsbt = toUtxoPsbt(wrappedPsbt);
      updatedPsbt.signAllInputsHD(rootWalletKeys.triple[0]);
      updatedPsbt.signAllInputsHD(rootWalletKeys.triple[2]);
      updatedPsbt.finalizeAllInputs();
      assert.deepStrictEqual(
        fullSignedFixture.psbt
          .clone()
          .finalizeAllInputs()
          .extractTransaction()
          .toBuffer()
          .toString("hex"),
        updatedPsbt.extractTransaction().toBuffer().toString("hex"),
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
      assert.strictEqual(buf.toString("hex"), Buffer.from(wrappedPsbt.serialize()).toString("hex"));
    });

    it("should round-trip utxolib -> ms -> utxolib", function () {
      assert.strictEqual(buf.toString("hex"), toUtxoPsbt(wrappedPsbt).toBuffer().toString("hex"));
    });

    if (stage === "bare") {
      describeUpdateInputWithDescriptor(psbt, scriptType);
    }
  });
});
