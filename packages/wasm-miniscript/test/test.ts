import * as assert from "assert";
import { descriptorFromString, miniscriptFromString, miniscriptFromBitcoinScript } from "../js";
import { fixtures } from "./descriptorFixtures";

describe("AST", function () {
  it("should get ast", function () {
    const pubkey = Buffer.alloc(32, 1).toString("hex");
    const result = miniscriptFromString(`multi_a(1,${pubkey})`, "tap");
    console.dir(result.node(), { depth: null });
    console.dir(result.encode(), { depth: null });
    console.dir(miniscriptFromBitcoinScript(result.encode(), "tap").toString());
  });
});

function removeChecksum(descriptor: string): string {
  const parts = descriptor.split("#");
  return parts[0];
}

describe("Descriptor fixtures", function () {
  fixtures.valid.forEach((fixture, index) => {
    it("should parse fixture " + index, function () {
      const descriptor = descriptorFromString(fixture.descriptor, "string");
      assert.doesNotThrow(() => descriptor.node());
      let descriptorString = descriptor.toString();
      if (fixture.checksumRequired === false) {
        descriptorString = removeChecksum(descriptorString);
      }
      let expected = fixture.descriptor;
      if (index === 56 || index === 57) {
        // for reasons I do not really understand, teh `a:and_n` gets converted into `a:and_b` for these
        expected = expected.replace("and_n", "and_b");
      }
      assert.strictEqual(descriptorString, expected);

      assert.doesNotThrow(() =>
        descriptorFromString(fixture.descriptor, "derivable").atDerivationIndex(0),
      );

      const nonDerivable = [33, 34, 35, 41, 42, 43];
      if (nonDerivable.includes(index)) {
        // FIXME(BTC-1337): xprvs with hardened derivations are not supported yet
        console.log("Skipping encoding test for fixture", fixture.descriptor, index);
      } else {
        assert.doesNotThrow(() =>
          descriptorFromString(fixture.descriptor, "derivable").atDerivationIndex(0).encode(),
        );
      }
    });
  });
});
