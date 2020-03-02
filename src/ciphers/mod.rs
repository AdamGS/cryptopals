use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;
use rand::Rng;

use crate::utils::random::get_rand_bytes;
use crate::utils::{fixed_xor, read_base64file_to_hex, ByteSlice};

pub mod aes_ciphers;

pub trait Cipher {
    fn encrypt(&self, cleartext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;
}

pub fn single_byte_xor_cipher(ciphertext: &[u8], byte_key: u8) -> Vec<u8> {
    let key = vec![byte_key; ciphertext.len()];
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
            let cleartext: Vec<char> = single_byte_xor_cipher(&ciphertext, key)
                .iter()
                .map(|b| *b as char)
                .collect();
            let cleartext_string = String::from_iter(cleartext);

            let string_rating = rate_string(&cleartext_string.as_str());

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
        let new_cleartext = String::from_utf8(cipher.decrypt(ciphertext.as_slice())).unwrap();

        assert_eq!("YELLOW SUBMARINE", new_cleartext)
    }
}
