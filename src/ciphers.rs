use crate::utils::fixed_xor;

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
            let cleartext_string = String::from_iter(cleartext);;

            let string_rating = rate_string(&cleartext_string.as_str());

            if string_rating > base {
                suspected_key = key;
                base = string_rating
            }
        }

        suspected_key
    }
}
