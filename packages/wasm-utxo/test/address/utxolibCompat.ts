import * as path from "node:path";
import * as fs from "node:fs/promises";

import * as utxolib from "@bitgo/utxo-lib";
import assert from "node:assert";
import { utxolibCompat } from "../../js";

type Fixture = [type: string, script: string, address: string];

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
  });
}

utxolib.getNetworkList().forEach((network) => {
  runTest(network);
});
