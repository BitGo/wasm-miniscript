mod descriptor;
mod error;
mod miniscript;
mod psbt;
mod try_into_js_value;

// re-export bitcoin from the miniscript crate
// this package is transitioning to a all-purpose bitcoin package, so we want easy access
pub use ::miniscript::bitcoin;

pub use descriptor::WrapDescriptor;
pub use miniscript::WrapMiniscript;
pub use psbt::WrapPsbt;
