# BitGoWASM

This repo is the home of BitGo's WASM libraries.


# Dependencies

- [Rust](https://www.rust-lang.org/) nightly
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) (install with `cargo install wasm-pack`)
- [Node.js](https://nodejs.org/en/)

# Packages


## wasm-utxo

This is a wrapper around the
[rust-bitcoin](https://github.com/rust-bitcoin/rust-miniscript) and
[rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) crates that is
compiled to WebAssembly.

### wasm-utxo-web

A live playground for the wasm-utxo crate.

Go to https://bitgo.github.io/wasm-utxo to see a live demo of the wasm-utxo library in action. *WIP*

