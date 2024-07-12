# wasm-miniscript

This is a wrapper around the [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) crate that is compiled
to WebAssembly. It allows you to use Miniscript in NodeJS and in the browser.


# Dependencies

- [Rust](https://www.rust-lang.org/) nightly
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) (install with `cargo install wasm-pack`)
- [NodeJS](https://nodejs.org/en/)