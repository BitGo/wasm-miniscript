import * as utxolib from "@bitgo/utxo-lib";
import { Descriptor, Psbt } from "../js";

function toAddress(descriptor: Descriptor, network: utxolib.Network) {
  utxolib.address.fromOutputScript(Buffer.from(descriptor.scriptPubkey()), network);
}

export function toWrappedPsbt(psbt: utxolib.bitgo.UtxoPsbt | utxolib.Psbt | Buffer | Uint8Array) {
  if (psbt instanceof utxolib.bitgo.UtxoPsbt || psbt instanceof utxolib.Psbt) {
    psbt = psbt.toBuffer();
  }
  if (psbt instanceof Buffer || psbt instanceof Uint8Array) {
    return Psbt.deserialize(psbt);
  }
  throw new Error("Invalid input");
}

export function toUtxoPsbt(psbt: Psbt | Buffer | Uint8Array) {
  if (psbt instanceof Psbt) {
    psbt = psbt.serialize();
  }
  if (psbt instanceof Buffer || psbt instanceof Uint8Array) {
    return utxolib.bitgo.UtxoPsbt.fromBuffer(Buffer.from(psbt), {
      network: utxolib.networks.bitcoin,
    });
  }
  throw new Error("Invalid input");
}

export function updateInputWithDescriptor(
  psbt: utxolib.Psbt,
  inputIndex: number,
  descriptor: Descriptor,
) {
  const wrappedPsbt = toWrappedPsbt(psbt);
  wrappedPsbt.updateInputWithDescriptor(inputIndex, descriptor);
  psbt.data.inputs[inputIndex] = toUtxoPsbt(wrappedPsbt).data.inputs[inputIndex];
}

export function finalizePsbt(psbt: utxolib.Psbt) {
  const wrappedPsbt = toWrappedPsbt(psbt);
  wrappedPsbt.finalize();
  const unwrappedPsbt = toUtxoPsbt(wrappedPsbt);
  for (let i = 0; i < psbt.data.inputs.length; i++) {
    psbt.data.inputs[i] = unwrappedPsbt.data.inputs[i];
  }
}
