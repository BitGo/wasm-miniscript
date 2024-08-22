import * as assert from "assert";
import * as utxolib from "@bitgo/utxo-lib";
import { Descriptor } from "../js";
import { getDescriptorForScriptType } from "./descriptorUtil";

const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(utxolib.testutil.getKeyTriple("wasm"));
const scriptTypes = ["p2sh", "p2shP2wsh", "p2wsh"] as const;
const scope = ["external", "internal"] as const;
const index = [0, 1, 2];

function runTest(
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
  index: number,
  scope: "internal" | "external",
) {
  describe(`scriptType=${scriptType}, index=${index}, scope=${scope}`, function () {
    const chainCode =
      scope === "external"
        ? utxolib.bitgo.getExternalChainCode(scriptType)
        : utxolib.bitgo.getInternalChainCode(scriptType);
    const derivedKeys = rootWalletKeys.deriveForChainAndIndex(chainCode, index);
    const scriptUtxolib = utxolib.bitgo.outputScripts.createOutputScript2of3(
      derivedKeys.publicKeys,
      scriptType,
    ).scriptPubKey;

    it("descriptor should have expected format", function () {
      const descriptor = Descriptor.fromString(
        getDescriptorForScriptType(rootWalletKeys, scriptType, scope),
        "derivable",
      );
      const [x1, x2, x3] = rootWalletKeys.triple.map((xpub) => xpub.neutered().toBase58());
      if (scriptType === "p2sh" && scope === "external") {
        // spot check
        assert.ok(
          descriptor
            .toString()
            .startsWith(`sh(multi(2,${x1}/0/0/0/*,${x2}/0/0/0/*,${x3}/0/0/0/*))`),
        );
      }
      if (scriptType === "p2shP2wsh" && scope === "internal") {
        // spot check
        assert.ok(
          descriptor
            .toString()
            .startsWith(`sh(wsh(multi(2,${x1}/0/0/11/*,${x2}/0/0/11/*,${x3}/0/0/11/*)))`),
        );
      }
    });

    it("address should match descriptor", function () {
      const scriptFromDescriptor = Buffer.from(
        Descriptor.fromString(
          getDescriptorForScriptType(rootWalletKeys, scriptType, scope),
          "derivable",
        )
          .atDerivationIndex(index)
          .scriptPubkey(),
      );
      assert.deepStrictEqual(scriptUtxolib.toString("hex"), scriptFromDescriptor.toString("hex"));
    });
  });
}

scriptTypes.forEach((scriptType) => {
  index.forEach((index) => {
    scope.forEach((scope) => {
      runTest(scriptType, index, scope);
    });
  });
});
