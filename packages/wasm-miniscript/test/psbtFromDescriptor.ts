import assert from "node:assert";
import { BIP32Interface } from "@bitgo/utxo-lib";
import { getKey } from "@bitgo/utxo-lib/dist/src/testutil";

import { DescriptorNode, formatNode } from "../js/ast";
import { mockPsbtDefault } from "./psbtFromDescriptor.util";
import { Descriptor } from "../js";
import { toWrappedPsbt } from "./psbt.util";

function toKeyWithPath(k: BIP32Interface, path = "*"): string {
  return k.toBase58() + "/" + path;
}

function toKeyPlain(k: Buffer): string {
  return k.toString("hex");
}

const external = getKey("external");
const a = getKey("a");
const b = getKey("b");
const c = getKey("c");
const keys = { external, a, b, c };
function getKeyName(bipKey: BIP32Interface) {
  return Object.keys(keys).find(
    (k) => keys[k as keyof typeof keys] === bipKey,
  ) as keyof typeof keys;
}

function describeSignDescriptor(
  name: string,
  descriptor: DescriptorNode,
  signSeqs: BIP32Interface[][],
) {
  describe(`psbt with descriptor ${name}`, function () {
    const isTaproot = Object.keys(descriptor)[0] === "tr";
    const psbt = mockPsbtDefault({
      descriptorSelf: Descriptor.fromString(formatNode(descriptor), "derivable"),
      descriptorOther: Descriptor.fromString(
        formatNode({ wpkh: toKeyWithPath(external) }),
        "derivable",
      ),
    });

    function getSigResult(keys: BIP32Interface[]) {
      return {
        [isTaproot ? "Schnorr" : "Ecdsa"]: keys.map((key) =>
          key.publicKey.subarray(isTaproot ? 1 : 0).toString("hex"),
        ),
      };
    }

    signSeqs.forEach((signSeq, i) => {
      it(`should sign ${signSeq.map((k) => getKeyName(k))} xprv`, function () {
        const wrappedPsbt = toWrappedPsbt(psbt);
        signSeq.forEach((key) => {
          assert.deepStrictEqual(wrappedPsbt.signWithXprv(key.toBase58()), {
            0: getSigResult([key.derive(0)]),
            1: getSigResult([key.derive(1)]),
          });
        });
        wrappedPsbt.finalize();
      });

      it(`should sign ${signSeq.map((k) => getKeyName(k))} prv buffer`, function () {
        if (isTaproot) {
          // signing with non-bip32 taproot keys is not supported apparently
          this.skip();
        }
        const wrappedPsbt = toWrappedPsbt(psbt);
        signSeq.forEach((key) => {
          assert.deepStrictEqual(wrappedPsbt.signWithPrv(key.derive(0).privateKey), {
            0: getSigResult([key.derive(0)]),
            1: getSigResult([]),
          });
        });
      });
    });
  });
}

describeSignDescriptor(
  "Wsh2Of3",
  {
    wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] },
  },
  [
    [a, b],
    [b, a],
  ],
);

describeSignDescriptor(
  "Tr1Of3",
  {
    tr: [toKeyWithPath(a), [{ pk: toKeyWithPath(b) }, { pk: toKeyWithPath(c) }]],
  },
  [[a], [b], [c]],
);

// while we cannot sign with a derived plain xonly key, we can sign with an xprv
describeSignDescriptor(
  "TrWithExternalPlain",
  {
    tr: [
      toKeyPlain(external.publicKey),
      [
        { pk: toKeyPlain(external.publicKey) },
        { or_b: [{ pk: toKeyPlain(external.publicKey) }, { "s:pk": toKeyWithPath(a) }] },
      ],
    ],
  },
  [[a]],
);
