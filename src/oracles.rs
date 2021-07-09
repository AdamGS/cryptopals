use rand::Rng;

use crate::ciphers::aes_ciphers::AesBlockCipher;
use crate::ciphers::Cipher;
use crate::utils::random::get_rand_bytes;
use crate::utils::read_base64file_to_hex;
use crate::utils::ByteSlice;

pub fn random_padded_encryption_oracle<T: AsRef<[u8]>>(plaintext: T, cipher: AesBlockCipher) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let pre_pad = rng.gen_range(5, 11);
    let post_pad = rng.gen_range(5, 11);
    let padded = [
        get_rand_bytes(pre_pad),
        plaintext.as_ref().to_vec(),
        get_rand_bytes(post_pad),
    ]
    .concat()
    .pad(16);

    cipher.encrypt(padded)
}

pub fn unknown_string_padded_oracle<T: AsRef<[u8]>>(plaintext: T, cipher: AesBlockCipher) -> Vec<u8> {
    prefix_unknown_string_padded_oracle(Vec::new(), plaintext, cipher)
}

pub fn prefix_unknown_string_padded_oracle<T: AsRef<[u8]>, S: AsRef<[u8]>>(
    prefix: T,
    plaintext: S,
    cipher: AesBlockCipher,
) -> Vec<u8> {
    // Maybe move this part out
    let unknown_str = read_base64file_to_hex("statics/ch12.txt");
    let padded = [prefix.as_ref(), plaintext.as_ref(), unknown_str.as_ref()]
        .concat()
        .pad(16);

    cipher.encrypt(padded)
}

pub fn cbc_keyval_oracle<T: AsRef<[u8]>>(plaintext: T, cipher: AesBlockCipher) -> Vec<u8> {
    let prefix = b"comment1=cooking%20MCs;userdata=";
    let sufix = b";comment2=%20like%20a%20pound%20of%20bacon";
    let padded = [prefix, plaintext.as_ref(), sufix].concat().pad(16);

    cipher.encrypt(padded)
}

pub fn cbc_padding_oracle<T: AsRef<[u8]>>(text: T, cipher: AesBlockCipher) -> bool {
    cipher.decrypt(text).strip_pad().is_ok()
}
