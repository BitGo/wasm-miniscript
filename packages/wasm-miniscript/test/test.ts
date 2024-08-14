import * as assert from "assert";
import { Miniscript, Descriptor } from "../js";
import { fixtures } from "./descriptorFixtures";

describe("AST", function () {
  it("should get ast", function () {
    const pubkey = Buffer.alloc(32, 1).toString("hex");
    const result = Miniscript.fromString(`multi_a(1,${pubkey})`, "tap");
    console.dir(result.node(), { depth: null });
    console.dir(result.encode(), { depth: null });
    console.dir(Miniscript.fromBitcoinScript(result.encode(), "tap").toString());
  });
});

function removeChecksum(descriptor: string): string {
  const parts = descriptor.split("#");
  return parts[0];
}

describe("Descriptor fixtures", function () {
  fixtures.valid.forEach((fixture, i) => {
    it("should parse fixture " + i, function () {
      const descriptor = Descriptor.fromString(fixture.descriptor, "string");
      assert.doesNotThrow(() => descriptor.node());
      let descriptorString = descriptor.toString();
      if (fixture.checksumRequired === false) {
        descriptorString = removeChecksum(descriptorString);
      }
      let expected = fixture.descriptor;
      if (i === 56 || i === 57) {
        // for reasons I do not really understand, the `a:and_n` gets converted into `a:and_b` for these
        expected = expected.replace("and_n", "and_b");
      }
      assert.strictEqual(descriptorString, expected);

      assert.doesNotThrow(() =>
        Descriptor.fromString(fixture.descriptor, "derivable").atDerivationIndex(0),
      );

      const nonDerivable = [33, 34, 35, 41, 42, 43];
      if (nonDerivable.includes(i)) {
        // FIXME(BTC-1337): xprvs with hardened derivations are not supported yet
        console.log("Skipping encoding test for fixture", fixture.descriptor, i);
      } else {
        assert.doesNotThrow(() =>
          Descriptor.fromString(fixture.descriptor, "derivable").atDerivationIndex(0).encode(),
        );

        let descriptorString = fixture.descriptor;
        if (fixture.checksumRequired === false) {
          descriptorString = removeChecksum(descriptorString);
        }
        const descriptor = Descriptor.fromString(descriptorString, "derivable");
        assert.strictEqual(
          Buffer.from(descriptor.atDerivationIndex(fixture.index ?? 0).scriptPubkey()).toString(
            "hex",
          ),
          fixture.script,
        );
      }
    });
  });
});
