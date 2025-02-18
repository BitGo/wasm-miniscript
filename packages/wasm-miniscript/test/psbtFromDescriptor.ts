import { BIP32Interface } from "@bitgo/utxo-lib";
import { getKey } from "@bitgo/utxo-lib/dist/src/testutil";

import { DescriptorNode, formatNode } from "../js/ast";
import { mockPsbtDefault } from "./psbtFromDescriptor.util";
import { Descriptor } from "../js";
import { toWrappedPsbt } from "./psbt.util";

function toKeyWithPath(k: BIP32Interface, path = "*"): string {
  return k.toBase58() + "/" + path;
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
    const psbt = mockPsbtDefault({
      descriptorSelf: Descriptor.fromString(formatNode(descriptor), "derivable"),
      descriptorOther: Descriptor.fromString(
        formatNode({ wpkh: toKeyWithPath(external) }),
        "derivable",
      ),
    });

    signSeqs.forEach((signSeq, i) => {
      it(`should sign ${signSeq.map((k) => getKeyName(k))}`, function () {
        const wrappedPsbt = toWrappedPsbt(psbt);
        signSeq.forEach((key) => {
          wrappedPsbt.signWithXprv(key.toBase58());
        });
        wrappedPsbt.finalize();
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
