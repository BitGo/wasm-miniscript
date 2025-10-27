import * as path from "node:path";
import * as fs from "node:fs/promises";

import * as utxolib from "@bitgo/utxo-lib";
import assert from "node:assert";
import { utxolibCompat, FixedScriptWallet } from "../../js";

type Triple<T> = [T, T, T];

type Fixture = [type: string, script: string, address: string];

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

async function getFixtures(name: string): Promise<Fixture[]> {
  if (name === "bitcoinBitGoSignet") {
    name = "bitcoinPublicSignet";
  }
  const fixturePath = path.join(__dirname, "..", "fixtures", "address", `${name}.json`);
  const fixtures = await fs.readFile(fixturePath, "utf8");
  return JSON.parse(fixtures);
}

function runTest(network: utxolib.Network) {
  const name = utxolib.getNetworkName(network);
  describe(`utxolibCompat ${name}`, function () {
    let fixtures;
    before(async function () {
      fixtures = await getFixtures(name);
    });

    it("should convert to utxolib compatible network", async function () {
      for (const fixture of fixtures) {
        const [_type, script, addressRef] = fixture;
        const scriptBuf = Buffer.from(script, "hex");
        const address = utxolibCompat.Address.fromOutputScript(scriptBuf, network);
        assert.strictEqual(address, addressRef);
        const scriptFromAddress = utxolibCompat.Address.toOutputScript(address, network);
        assert.deepStrictEqual(Buffer.from(scriptFromAddress), scriptBuf);
      }
    });

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
