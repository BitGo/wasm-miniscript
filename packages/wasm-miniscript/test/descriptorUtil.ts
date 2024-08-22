import * as utxolib from "@bitgo/utxo-lib";

/** Expand a template with the given root wallet keys and chain code */
function expand(template: string, rootWalletKeys: utxolib.bitgo.RootWalletKeys, chainCode: number) {
  return template.replace(/\$([0-9])/g, (_, i) => {
    const keyIndex = parseInt(i, 10);
    if (keyIndex !== 0 && keyIndex !== 1 && keyIndex !== 2) {
      throw new Error("Invalid key index");
    }
    const xpub = rootWalletKeys.triple[keyIndex].neutered().toBase58();
    const prefix = rootWalletKeys.derivationPrefixes[keyIndex];
    return xpub + "/" + prefix + "/" + chainCode + "/*";
  });
}

/**
 * Get a standard output descriptor that corresponds to the proprietary HD wallet setup
 * used in BitGo wallets.
 * Only supports a subset of script types.
 */
export function getDescriptorForScriptType(
  rootWalletKeys: utxolib.bitgo.RootWalletKeys,
  scriptType: utxolib.bitgo.outputScripts.ScriptType2Of3,
  scope: "internal" | "external",
): string {
  const chain =
    scope === "external"
      ? utxolib.bitgo.getExternalChainCode(scriptType)
      : utxolib.bitgo.getInternalChainCode(scriptType);
  switch (scriptType) {
    case "p2sh":
      return expand("sh(multi(2,$0,$1,$2))", rootWalletKeys, chain);
    case "p2shP2wsh":
      return expand("sh(wsh(multi(2,$0,$1,$2)))", rootWalletKeys, chain);
    case "p2wsh":
      return expand("wsh(multi(2,$0,$1,$2))", rootWalletKeys, chain);
    default:
      throw new Error(`Unsupported script type ${scriptType}`);
  }
}
