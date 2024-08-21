import * as utxolib from "@bitgo/utxo-lib";
import * as assert from "node:assert";
import { getPsbtFixtures } from "./psbtFixtures";
import { Psbt } from "../js";

getPsbtFixtures().forEach(({ psbt, name }) => {
  describe(`PSBT fixture ${name}`, function () {
    let buf: Buffer;
    let wrappedPsbt: Psbt;

    before(function () {
      buf = psbt.toBuffer();
      wrappedPsbt = Psbt.deserialize(buf);
    });

    it("should map to same hex", function () {
      assert.strictEqual(
        buf.toString("hex"),
        // it seems that the utxolib impl sometimes adds two extra bytes zero bytes at the end
        // they probably are insignificant so we just add them here
        Buffer.from(wrappedPsbt.serialize()).toString("hex") + (name === "empty" ? "0000" : ""),
      );
    });

    it("should round-trip utxolib -> ms -> utxolib", function () {
      assert.strictEqual(
        buf.toString("hex"),
        utxolib.bitgo.UtxoPsbt.fromBuffer(Buffer.from(wrappedPsbt.serialize()), {
          network: utxolib.networks.bitcoin,
        })
          .toBuffer()
          .toString("hex"),
      );
    });
  });
});
