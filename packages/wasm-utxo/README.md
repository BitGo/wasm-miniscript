# wasm-utxo

This project is the successor of the Javascript `utxo-lib` package.

It provides WASM bindings for the `rust-bitcoin` and `rust-miniscript` crates
that help verify and co-sign transactions built by the BitGo Wallet Platform API.

## Status

This project is under active development.

| Feature                                 | Bitcoin        | BitcoinCash | BitcoinGold | Dash    | Doge    | Litecoin | Zcash   |
| --------------------------------------- | -------------- | ----------- | ----------- | ------- | ------- | -------- | ------- |
| Descriptor Wallet: Address Support      | ✅ Complete    | 🚫          | 🚫          | 🚫      | 🚫      | 🚫       | 🚫      |
| Descriptor Wallet: Transaction Support  | ✅ Complete    | 🚫          | 🚫          | 🚫      | 🚫      | 🚫       | 🚫      |
| FixedScript Wallet: Address Generation  | 🏗️ In Progress | ⏳ TODO     | ⏳ TODO     | ⏳ TODO | ⏳ TODO | ⏳ TODO  | ⏳ TODO |
| FixedScript Wallet: Transaction Support | ⏳ TODO        | ⏳ TODO     | ⏳ TODO     | ⏳ TODO | ⏳ TODO | ⏳ TODO  | ⏳ TODO |

## Building

If your system has problems with `wasm-pack` (Mac M1), you can use the `Container.mk` Makefile to build the wasm files:

```bash
cd packages/wasm-utxo
make -f Container.mk build-image
make -f Container.mk build-wasm
```
