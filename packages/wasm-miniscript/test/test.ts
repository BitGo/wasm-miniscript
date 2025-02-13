import * as assert from "assert";
import { Descriptor } from "../js";
import { fixtures } from "./descriptorFixtures";
import { assertEqualFixture } from "./descriptorUtil";
import { fromDescriptor } from "../js/ast";
import { formatNode } from "../js/ast";

function removeChecksum(descriptor: string): string {
  const parts = descriptor.split("#");
  return parts[0];
}

function getScriptPubKeyLength(descType: string): number {
  switch (descType) {
    case "Wpkh":
      return 22;
    case "Sh":
    case "ShWsh":
    case "ShWpkh":
      return 23;
    case "Pkh":
      return 25;
    case "Wsh":
    case "Tr":
      return 34;
    case "Bare":
      throw new Error("cannot determine scriptPubKey length for Bare descriptor");
    default:
      throw new Error("unexpected descriptor type " + descType);
  }
}

function isDerivable(i: number): boolean {
  return ![33, 34, 35, 41, 42, 43].includes(i);
}

function assertKnownDescriptorType(descriptor: Descriptor) {
  switch (descriptor.descType()) {
    case "Bare":
    case "Pkh":
    case "Sh":
    case "ShWsh":
    case "Wsh":
    case "Wpkh":
    case "ShWpkh":
    case "Tr":
      break;
    default:
      throw new Error("unexpected descriptor type " + descriptor.descType());
  }
}

function assertIsErrorUnknownWrapper(error: unknown, wrapper: string) {
  assert.ok(error instanceof Error);
  assert.ok(error.message.includes(`Error: unknown wrapper «${wrapper}»`));
}

describe("Descriptor fixtures", function () {
  fixtures.valid.forEach((fixture, i) => {
    describe("fixture " + i, function () {
      const isOpDropFixture = i === 59;
      let descriptor: Descriptor;

      before("setup descriptor", function () {
        try {
          descriptor = Descriptor.fromString(fixture.descriptor, "derivable");
        } catch (e) {
          if (isOpDropFixture) {
            assertIsErrorUnknownWrapper(e, "r:");
            return;
          }
          throw e;
        }
      });

      if (isOpDropFixture) {
        return;
      }

      it("should round-trip (pkType string)", function () {
        let descriptorString = Descriptor.fromString(fixture.descriptor, "string").toString();
        if (fixture.checksumRequired === false) {
          descriptorString = removeChecksum(descriptorString);
        }
        assert.strictEqual(descriptorString, fixture.descriptor);
      });

      it("should parse (pkType derivable)", async function () {
        const descriptor = Descriptor.fromString(fixture.descriptor, "derivable");

        assert.doesNotThrow(() =>
          Descriptor.fromString(fixture.descriptor, "derivable").atDerivationIndex(0),
        );

        if (isDerivable(i)) {
          if (descriptor.descType() !== "Tr") {
            assert.doesNotThrow(() => descriptor.atDerivationIndex(0).encode());
          }

          const scriptPubKey = Buffer.from(
            descriptor.atDerivationIndex(fixture.index ?? 0).scriptPubkey(),
          );
          assert.strictEqual(scriptPubKey.toString("hex"), fixture.script);
          if (descriptor.descType() !== "Bare") {
            assert.strictEqual(
              scriptPubKey.length,
              getScriptPubKeyLength(descriptor.descType()),
              `Unexpected scriptPubKey length for descriptor ${descriptor.descType()}: ${scriptPubKey.length}`,
            );
          }
        } else {
          // FIXME(BTC-1337): xprvs with hardened derivations are not supported yet
          console.log("Skipping encoding test for fixture", fixture.descriptor, i);
        }

        assert.ok(Number.isInteger(descriptor.maxWeightToSatisfy()));
        assertKnownDescriptorType(descriptor);
      });

      it("can round-trip with formatNode(toWasmNode(.))", async function () {
        const ast = fromDescriptor(descriptor);
        assert.strictEqual(formatNode(ast), removeChecksum(descriptor.toString()));
      });

      it("has expected fixture", async function () {
        await assertEqualFixture(__dirname + `/fixtures/${i}.json`, {
          descriptor: descriptor.toString(),
          wasmNode: descriptor.node(),
          ast: fromDescriptor(descriptor),
        });
      });
    });
  });
});
