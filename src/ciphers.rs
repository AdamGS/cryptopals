use crate::utils::{fixed_xor, pkcs7_pad};

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

pub trait Cipher {
    fn encrypt(&self, cleartext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;
}

pub struct AesCbcCipher<'b> {
    key: &'b [u8],
    block_size: usize,
    iv: &'b [u8],
}

pub struct AesEcbCipher<'a> {
    key: &'a [u8],
}

impl<'c> AesEcbCipher<'c> {
    pub fn new(key: &'c [u8]) -> Self {
        AesEcbCipher { key }
    }
}

impl<'a> Cipher for AesEcbCipher<'a> {
    fn encrypt(&self, cleartext: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new(GenericArray::from_slice(self.key));

        let mut block = GenericArray::from_slice(cleartext).clone();

        cipher.encrypt_block(&mut block);

        block.to_vec()
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let cipher = Aes128::new(GenericArray::from_slice(self.key));

        let mut block = GenericArray::from_slice(ciphertext).clone();

        cipher.decrypt_block(&mut block);

        block.to_vec()
    }
}

impl<'b> AesCbcCipher<'b> {
    pub fn new(key: &'b [u8], block_size: usize, iv: &'b [u8]) -> Self {
        AesCbcCipher {
            key,
            block_size,
            iv,
        }
    }
}

impl<'b> Cipher for AesCbcCipher<'b> {
    fn encrypt(&self, cleartext: &[u8]) -> Vec<u8> {
        let padded_text = pkcs7_pad(cleartext, self.block_size);
        let ecb = AesEcbCipher::new(self.key);

        padded_text
            .chunks(self.block_size)
            .fold(Vec::new(), |mut acc: Vec<u8>, curr_block| {
                let xored_value = if acc.is_empty() {
                    fixed_xor(curr_block.to_vec(), self.iv.to_vec())
                } else {
                    fixed_xor(
                        curr_block.to_vec(),
                        acc[acc.len() - self.block_size..acc.len()].to_vec(),
                    )
                };

                let mut encrypted_block = ecb.encrypt(xored_value.as_slice());

                acc.append(encrypted_block.as_mut());

                acc
            })
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let padded_text = pkcs7_pad(ciphertext, self.block_size);
        let ecb = AesEcbCipher::new(self.key);

        padded_text.chunks(self.block_size).enumerate().fold(
            Vec::new(),
            |mut acc: Vec<u8>, (index, curr_block)| {
                let decrypted_block = ecb.decrypt(curr_block);

                let mut xored_value = if acc.is_empty() {
                    fixed_xor(decrypted_block, self.iv.to_vec())
                } else {
                    let ciphertext_blocks: Vec<&[u8]> =
                        padded_text.chunks(self.block_size).collect();
                    fixed_xor(decrypted_block, ciphertext_blocks[index - 1].to_vec())
                };

                acc.append(xored_value.as_mut());

                acc
            },
        )
    }
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
    use super::single_byte_xor_cipher;
    use crate::utils::all_ascii_chars;
    use crate::utils::rate_string;
    use std::iter::FromIterator;

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
    use super::*;

    #[test]
    fn ecb_encrypt_decrypt_test() {
        let clear_text = "YELLOW SUBMARINE".as_bytes();
        let key = "AAAAAAAAAAAAAAAA".as_bytes();
        let cipher = AesEcbCipher::new(key);
        let ciphertext = cipher.encrypt(clear_text);
        let new_cleartext = String::from_utf8(cipher.decrypt(ciphertext.as_slice())).unwrap();

        assert_eq!("YELLOW SUBMARINE", new_cleartext)
    }
}
