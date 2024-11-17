use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Nonce, Key, KeyInit,
};
use sha2::{Sha256, Digest};

const NONCE_LEN: usize = 12;

pub struct SealedState {
    cipher: Aes256Gcm,
}

impl SealedState {
    pub fn new(secret: &str) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"hagrid");
        hash.update(secret);
        let hashed_secret = hash.finalize();
        let key = Key::<Aes256Gcm>::from_slice(&hashed_secret);
        let cipher = Aes256Gcm::new(&key);

        SealedState { cipher }
    }

    pub fn unseal(&self, data: &[u8]) -> Result<String, &'static str> {
        if data.len() < NONCE_LEN {
            return Err("invalid sealed value: too short");
        }
        let (sealed, nonce) = data.split_at(data.len() - NONCE_LEN);
        let unsealed = self.cipher.decrypt(Nonce::from_slice(nonce), sealed)
            .map_err(|_| "invalid key/nonce/value: bad seal")?;

        core::str::from_utf8(&unsealed)
            .map(|s| s.to_string())
            .map_err(|_| "bad unsealed utf8")
    }

    pub fn seal(&self, input: &str) -> Vec<u8> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut sealed = self.cipher
            .encrypt(&nonce, input.as_bytes())
            .expect("sealing works");
        sealed.extend(nonce);
        sealed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let sv = SealedState::new("swag");
        let sealed = sv.seal("test");

        // use a different instance to make sure no internal state remains
        let sv = SealedState::new("swag");
        let unsealed = sv.unseal(sealed.as_slice()).unwrap();

        assert_eq!("test", unsealed);
    }

    #[test]
    fn too_short() {
        let sv = SealedState::new("swag");

        let sealed = sv.seal("test");
        let sealed_short = &sealed[0..8];
        let unsealed_error = sv.unseal(sealed_short);

        assert_eq!(Err("invalid sealed value: too short"), unsealed_error);
    }
}
