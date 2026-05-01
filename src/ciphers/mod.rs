use crate::utils::fixed_xor;

pub mod aes_ciphers;
pub mod breakers;

pub trait Cipher<T: AsRef<[u8]>> {
    fn encrypt(&self, plaintext: T) -> Vec<u8>;
    fn decrypt(&self, ciphertext: T) -> Vec<u8>;
}

pub struct XorCipher {
    key: u8,
}

impl XorCipher {
    pub fn new(key: u8) -> Self {
        XorCipher { key }
    }
}

pub struct RepeatingXorCipher<'a> {
    key: &'a [u8],
}

impl RepeatingXorCipher<'_> {
    pub fn new(key: &'static [u8]) -> Self {
        RepeatingXorCipher { key }
    }
}

impl<T: AsRef<[u8]>> Cipher<T> for RepeatingXorCipher<'_> {
    fn encrypt(&self, plaintext: T) -> Vec<u8> {
        repeating_key_xor_cipher(plaintext, self.key)
    }

    fn decrypt(&self, ciphertext: T) -> Vec<u8> {
        repeating_key_xor_cipher(ciphertext, self.key)
    }
}

impl<T: AsRef<[u8]>> Cipher<T> for XorCipher {
    fn encrypt(&self, plaintext: T) -> Vec<u8> {
        single_byte_xor_cipher(plaintext, self.key)
    }

    fn decrypt(&self, ciphertext: T) -> Vec<u8> {
        single_byte_xor_cipher(ciphertext, self.key)
    }
}

fn single_byte_xor_cipher<T: AsRef<[u8]>>(ciphertext: T, key: u8) -> Vec<u8> {
    let ciphertext = ciphertext.as_ref();
    let key = vec![key; ciphertext.len()];
    fixed_xor(key, ciphertext)
}

fn repeating_key_xor_cipher<T: AsRef<[u8]>, S: AsRef<[u8]>>(ciphertext: T, key: S) -> Vec<u8> {
    let mut r = Vec::new();
    for (i, v) in ciphertext.as_ref().iter().enumerate() {
        let temp = v ^ key.as_ref()[i % key.as_ref().len()];
        r.push(temp);
    }

    r
}

#[cfg(test)]
mod tests {
    use super::aes_ciphers::*;
    use super::*;

    #[test]
    fn ecb_encrypt_decrypt_test() {
        let clear_text = "YELLOW SUBMARINE".as_bytes();
        let key = "AAAAAAAAAAAAAAAA".as_bytes();
        let cipher = AesEcbCipher::new(key, 16);

        let ciphertext = cipher.encrypt(clear_text);
        let new_plaintext = String::from_utf8(cipher.decrypt(ciphertext)).unwrap();

        assert_eq!("YELLOW SUBMARINE", new_plaintext)
    }
}
