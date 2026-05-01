use std::iter::FromIterator;

use crate::utils::all_ascii_chars;
use crate::utils::rate_string;

use super::single_byte_xor_cipher;

pub fn break_single_xor_cipher<T: AsRef<[u8]>>(ciphertext: T) -> u8 {
    let hex_keys: Vec<u8> = all_ascii_chars().iter().map(|c| *c as u8).collect();

    let mut base = 0;
    let mut suspected_key = 0_u8;
    for key in hex_keys {
        let plaintext: Vec<char> = single_byte_xor_cipher(&ciphertext, key)
            .iter()
            .map(|b| *b as char)
            .collect();
        let plaintext_string = String::from_iter(plaintext);

        let string_rating = rate_string(plaintext_string);

        if string_rating > base {
            suspected_key = key;
            base = string_rating
        }
    }

    suspected_key
}
