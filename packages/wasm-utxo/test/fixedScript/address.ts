import assert from "node:assert";

import * as utxolib from "@bitgo/utxo-lib";

import { FixedScriptWallet } from "../../js";

type Triple<T> = [T, T, T];

function getAddressUtxoLib(
  keys: Triple<utxolib.BIP32Interface>,
  chain: number,
  index: number,
  network: utxolib.Network,
): string {
  if (!utxolib.bitgo.isChainCode(chain)) {
    throw new Error(`Invalid chain code: ${chain}`);
  }

  const walletKeys = new utxolib.bitgo.RootWalletKeys(keys);
  const derived = walletKeys.deriveForChainAndIndex(chain, index);
  const script = utxolib.bitgo.outputScripts.createOutputScript2of3(
    derived.publicKeys,
    utxolib.bitgo.outputScripts.scriptTypeForChain(chain),
  );
  const address = utxolib.address.fromOutputScript(script.scriptPubKey, network);
  return address;
}

function getAddressWasm(
  keys: Triple<utxolib.BIP32Interface>,
  chain: number,
  index: number,
  network: utxolib.Network,
): string {
  const xpubs = keys.map((key) => key.neutered().toBase58());
  const wasmAddress = FixedScriptWallet.address(xpubs, chain, index, network);
  return wasmAddress;
}

function runTest(network: utxolib.Network) {
  describe(`address for network ${utxolib.getNetworkName(network)}`, function () {
    const keyTriple = utxolib.testutil.getKeyTriple("wasm");

    const supportedChainCodes = utxolib.bitgo.chainCodes.filter((chainCode) => {
      const scriptType = utxolib.bitgo.outputScripts.scriptTypeForChain(chainCode);
      return utxolib.bitgo.outputScripts.isSupportedScriptType(network, scriptType);
    });

    it(`can recreate address from wallet keys for chain codes ${supportedChainCodes.join(", ")}`, function () {
      for (const chainCode of supportedChainCodes) {
        for (let index = 0; index < 2; index++) {
          const utxolibAddress = getAddressUtxoLib(keyTriple, chainCode, index, network);
          const wasmAddress = getAddressWasm(keyTriple, chainCode, index, network);
          assert.strictEqual(utxolibAddress, wasmAddress);
        }
      }
    });
  });
}

utxolib.getNetworkList().forEach((network) => {
  runTest(network);
});
