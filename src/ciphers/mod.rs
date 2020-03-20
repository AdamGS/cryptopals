use crate::utils::fixed_xor;

pub mod aes_ciphers;

pub trait Cipher {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;
}

struct XorCipher {
    key: u8,
}

impl XorCipher {
    pub fn new(key: u8) -> Self {
        XorCipher { key }
    }
}

impl Cipher for XorCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        single_byte_xor_cipher(plaintext, self.key)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        single_byte_xor_cipher(ciphertext, self.key)
    }
}

pub fn single_byte_xor_cipher(ciphertext: &[u8], key: u8) -> Vec<u8> {
    let key = vec![key; ciphertext.len()];
    fixed_xor(key, ciphertext.to_owned())
}

pub fn repeating_key_xor_cipher(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    for (i, v) in ciphertext.iter().enumerate() {
        let temp = v ^ key[i % key.len()];
        r.push(temp);
    }

    r
}

pub mod breakers {
    use std::iter::FromIterator;

    use crate::utils::all_ascii_chars;
    use crate::utils::rate_string;

    use super::single_byte_xor_cipher;

    pub fn break_single_xor_cipher(ciphertext: &[u8]) -> u8 {
        let hex_keys: Vec<u8> = all_ascii_chars().iter().map(|c| *c as u8).collect();

        let mut base = 0;
        let mut suspected_key = 0_u8;
        for key in hex_keys {
            let plaintext: Vec<char> = single_byte_xor_cipher(&ciphertext, key)
                .iter()
                .map(|b| *b as char)
                .collect();
            let plaintext_string = String::from_iter(plaintext);

            let string_rating = rate_string(&plaintext_string.as_str());

            if string_rating > base {
                suspected_key = key;
                base = string_rating
            }
        }

        suspected_key
    }
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
        let new_plaintext = String::from_utf8(cipher.decrypt(ciphertext.as_slice())).unwrap();

        assert_eq!("YELLOW SUBMARINE", new_plaintext)
    }
}
