use rand::Rng;

use crate::ciphers::{AesBlockCipher, Cipher};
use crate::utils::random::get_rand_bytes;
use crate::utils::read_base64file_to_hex;
use crate::utils::ByteSlice;

pub fn random_padded_encryption_oracle(cleartext: &[u8], cipher: AesBlockCipher) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let pre_pad = rng.gen_range(5, 11);
    let post_pad = rng.gen_range(5, 11);
    let padded = &[
        get_rand_bytes(pre_pad),
        cleartext.to_vec(),
        get_rand_bytes(post_pad),
    ]
    .concat()
    .pad(16);

    cipher.encrypt(&padded)
}

pub fn unknown_string_padded_oracle(cleartext: &[u8], cipher: AesBlockCipher) -> Vec<u8> {
    let unknown_str = read_base64file_to_hex("statics/ch12.txt");
    let padded = &[cleartext, &unknown_str].concat().pad(16);

    cipher.encrypt(&padded)
}

pub fn prefix_unknown_string_padded_oracle(cleartext: &[u8], cipher: AesBlockCipher) -> Vec<u8> {
    let unknown_str = read_base64file_to_hex("statics/ch12.txt");

    let mut rng = rand::thread_rng();
    let pre_pad = rng.gen_range(5, 11);
    let padded = &[get_rand_bytes(pre_pad), cleartext.to_vec(), unknown_str]
        .concat()
        .pad(16);

    cipher.encrypt(padded)
}
