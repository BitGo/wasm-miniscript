use std::convert::TryInto;

use crate::bitcoin::{bip32::Xpub, CompressedPublicKey};

pub type XpubTriple = [Xpub; 3];

pub type PubTriple = [CompressedPublicKey; 3];

pub fn to_pub_triple(xpubs: &XpubTriple) -> PubTriple {
    xpubs
        .iter()
        .map(|x| x.to_pub())
        .collect::<Vec<_>>()
        .try_into()
        .expect("could not convert vec to array")
}

#[cfg(test)]
pub mod tests {
    use crate::bitcoin::bip32::{Xpriv, Xpub};
    use crate::bitcoin::hashes::{sha256, Hash};
    use crate::fixed_script_wallet::wallet_keys::XpubTriple;

    pub type XprivTriple = [Xpriv; 3];

    pub fn get_xpriv_from_seed(seed: &str) -> Xpriv {
        use crate::bitcoin::bip32::Xpriv;
        use crate::bitcoin::Network;

        // hash seed into 32 bytes
        let seed_hash = sha256::Hash::hash(seed.as_bytes()).to_byte_array();

        Xpriv::new_master(Network::Testnet, &seed_hash).expect("could not create xpriv from seed")
    }

    pub fn get_test_wallet_xprvs(seed: &str) -> XprivTriple {
        let a = get_xpriv_from_seed(&format!("{}/0", seed));
        let b = get_xpriv_from_seed(&format!("{}/1", seed));
        let c = get_xpriv_from_seed(&format!("{}/2", seed));
        [a, b, c]
    }

    pub fn get_test_wallet_keys(seed: &str) -> XpubTriple {
        let xprvs = get_test_wallet_xprvs(seed);
        let secp = crate::bitcoin::secp256k1::Secp256k1::new();
        let xpubs: XpubTriple = xprvs.map(|x| Xpub::from_priv(&secp, &x));
        xpubs
    }

    #[test]
    fn it_works() {
        let keys = get_test_wallet_keys("test");
        assert_eq!(keys[0].to_string(), "tpubD6NzVbkrYhZ4XUs2skvAi3vaZPKQ2oebm4FNyzbHwo8cWoZ81e2Gt1w836KdQWNtf7AgsPBtZ4t4KuoTuaKdzAbgeoygoKqgU6L2GnisU9a");
    }
}
