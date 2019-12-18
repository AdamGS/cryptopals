use crate::utils::{fixed_xor, frequency_map, pkcs7_pad};
use itertools::Itertools;
use std::iter;

pub struct AesCbcCipher<'a> {
    key: &'a [u8],
    block_size: usize,
    iv: &'a [u8],
}

impl AesCbcCipher<'_> {
    pub fn new(key: &'static [u8], block_size: usize, iv: &'static [u8]) -> Self {
        AesCbcCipher {
            key,
            block_size,
            iv,
        }
    }

    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        let padded_text = pkcs7_pad(input, self.block_size);

        padded_text
            .chunks(self.block_size)
            .fold(Vec::new(), |mut acc: Vec<u8>, curr_block| {
                let mut xored_value = if acc.is_empty() {
                    fixed_xor(curr_block.to_vec(), self.iv.to_vec())
                } else {
                    fixed_xor(
                        curr_block.to_vec(),
                        acc[acc.len() - self.block_size..acc.len()].to_vec(),
                    )
                };

                let mut encrypted_block = aes_ecb_cipher_encrypt(xored_value.as_slice(), self.key);

                acc.append(encrypted_block.as_mut());

                acc
            })
    }

    pub fn decrypt(&self, input: &[u8]) -> Vec<u8> {
        let padded_text = pkcs7_pad(input, self.block_size);

        padded_text.chunks(self.block_size).enumerate().fold(
            Vec::new(),
            |mut acc: Vec<u8>, (index, curr_block)| {
                let decrypted_block = aes_ecb_cipher_decrypt(curr_block, self.key);

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

pub fn aes_ecb_cipher_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;
    use aes::Aes128;

    let cipher = Aes128::new(GenericArray::from_slice(key));

    let mut block = GenericArray::from_slice(ciphertext).clone();

    cipher.decrypt_block(&mut block);

    block.to_vec()
}

pub fn aes_ecb_cipher_encrypt(cleartext: &[u8], key: &[u8]) -> Vec<u8> {
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;
    use aes::Aes128;

    let cipher = Aes128::new(GenericArray::from_slice(key));

    let mut block = GenericArray::from_slice(cleartext).clone();

    cipher.encrypt_block(&mut block);

    block.to_vec()
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
        let ciphertext = aes_ecb_cipher_encrypt(clear_text, key);
        let new_cleartext =
            String::from_utf8(aes_ecb_cipher_decrypt(ciphertext.as_slice(), key)).unwrap();

        assert!("YELLOW SUBMARINE" == new_cleartext)
    }
}
