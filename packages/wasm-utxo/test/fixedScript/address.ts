import assert from "node:assert";

import * as utxolib from "@bitgo/utxo-lib";

import { fixedScriptWallet } from "../../js";

type Triple<T> = [T, T, T];

function getAddressUtxoLib(
  keys: utxolib.bitgo.RootWalletKeys,
  chain: number,
  index: number,
  network: utxolib.Network,
): string {
  if (!utxolib.bitgo.isChainCode(chain)) {
    throw new Error(`Invalid chain code: ${chain}`);
  }

  const derived = keys.deriveForChainAndIndex(chain, index);
  const script = utxolib.bitgo.outputScripts.createOutputScript2of3(
    derived.publicKeys,
    utxolib.bitgo.outputScripts.scriptTypeForChain(chain),
  );
  const address = utxolib.address.fromOutputScript(script.scriptPubKey, network);
  return address;
}

function runTest(network: utxolib.Network, derivationPrefixes?: Triple<string>) {
  describe(`address for network ${utxolib.getNetworkName(network)}, derivationPrefixes=${Boolean(derivationPrefixes)}`, function () {
    const keyTriple = utxolib.testutil.getKeyTriple("wasm");

    const supportedChainCodes = utxolib.bitgo.chainCodes.filter((chainCode) => {
      const scriptType = utxolib.bitgo.outputScripts.scriptTypeForChain(chainCode);
      return utxolib.bitgo.outputScripts.isSupportedScriptType(network, scriptType);
    });

    it(`can recreate address from wallet keys for chain codes ${supportedChainCodes.join(", ")}`, function () {
      for (const chainCode of supportedChainCodes) {
        for (let index = 0; index < 2; index++) {
          const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(
            keyTriple.map((k) => k.neutered()) as Triple<utxolib.BIP32Interface>,
            derivationPrefixes,
          );
          const utxolibAddress = getAddressUtxoLib(rootWalletKeys, chainCode, index, network);
          const wasmAddress = fixedScriptWallet.address(rootWalletKeys, chainCode, index, network);
          assert.strictEqual(utxolibAddress, wasmAddress);
        }
      }
    });
  });
}

utxolib.getNetworkList().forEach((network) => {
  runTest(network);
  runTest(network, ["m/1/2", "m/0/0", "m/0/0"]);
});
