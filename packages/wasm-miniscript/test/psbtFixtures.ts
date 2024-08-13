import * as utxolib from "@bitgo/utxo-lib";

function getEmptyPsbt() {
  return new utxolib.bitgo.UtxoPsbt();
}

function getPsbtWithScriptTypeAndStage(
  seed: string,
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
  stage: "unsigned" | "halfsigned" | "fullsigned",
) {
  const keys = new utxolib.bitgo.RootWalletKeys(utxolib.testutil.getKeyTriple(seed));
  return utxolib.testutil.constructPsbt(
    [
      {
        scriptType,
        value: BigInt(1e8),
      },
    ],
    [
      {
        value: BigInt(1e8 - 1000),
        scriptType: "p2sh",
      },
    ],
    utxolib.networks.bitcoin,
    keys,
    "unsigned",
  );
}

export type PsbtFixture = {
  psbt: utxolib.bitgo.UtxoPsbt;
  name: string;
};

export function getPsbtFixtures(): PsbtFixture[] {
  const testMatrixScriptTypes = ["p2sh", "p2shP2wsh", "p2wsh"] as const;
  const testMatrixStages = ["unsigned", "halfsigned", "fullsigned"] as const;

  const fixturesBitGo2Of3 = testMatrixStages.flatMap((stage) => {
    return testMatrixScriptTypes.map((scriptType) => {
      return {
        psbt: getPsbtWithScriptTypeAndStage("wasm", scriptType, stage),
        name: `${scriptType}-${stage}`,
      };
    });
  });

  return [{ psbt: getEmptyPsbt(), name: "empty" }, ...fixturesBitGo2Of3];
}
