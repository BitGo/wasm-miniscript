# wasm-miniscript

This is a wrapper around the [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) crate that is compiled
to WebAssembly. It allows you to use Miniscript in NodeJS and in the browser.

# Dependencies

- [Rust](https://www.rust-lang.org/) nightly
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) (install with `cargo install wasm-pack`)
- [NodeJS](https://nodejs.org/en/)


# Packages

## packages/wasm-miniscript

This contains the core library that is compiled to WebAssembly.
It is a wrapper around the `rust-miniscript` crate.

###  Building

If your system has problems with `wasm-pack` (Mac M1), you can use the `Container.mk` Makefile to build the wasm files:

```bash
cd packages/wasm-miniscript
make -f Container.mk build-image
make -f Conatiner.mk build-wasm
```
