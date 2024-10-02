import * as utxolib from "@bitgo/utxo-lib";
import { Psbt } from "../js";

export function toWrappedPsbt(psbt: utxolib.bitgo.UtxoPsbt | Buffer | Uint8Array) {
  if (psbt instanceof utxolib.bitgo.UtxoPsbt) {
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