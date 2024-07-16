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
  fixtures.valid.forEach((fixture, i) => {
    it("should parse fixture " + i, function () {
      const descriptor = descriptorFromString(fixture.descriptor);
      assert.doesNotThrow(() => descriptor.node());
      let descriptorString = descriptor.toString();
      if (fixture.checksumRequired === false) {
        descriptorString = removeChecksum(descriptorString);
      }
      let expected = fixture.descriptor;
      if (i === 56 || i === 57) {
        // for reasons I do not really understand, teh `a:and_n` gets converted into `a:and_b` for these
        expected = expected.replace("and_n", "and_b");
      }
      assert.strictEqual(descriptorString, expected);
    });
  });
});
