use crate::utils::fixed_xor;

pub fn single_byte_xor_cipher(ciphertext: &Vec<u8>, byte_key: u8) -> Vec<u8> {
    let key = vec![byte_key; ciphertext.len()];
    fixed_xor(key, ciphertext.clone())
}

pub fn repeating_key_xor_cipher(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut r = Vec::new();
    for (i, v) in ciphertext.iter().enumerate() {
        let temp = ciphertext[i] ^ key[i % key.len()];
        r.push(temp);
    }

    r
}
