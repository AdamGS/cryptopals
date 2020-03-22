use crate::ciphers::Cipher;
use crate::utils::fixed_xor;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

#[derive(Debug, Clone, Copy)]
pub enum AesBlockCipher<'a> {
    CBC(AesCbcCipher<'a>),
    ECB(AesEcbCipher<'a>),
}

impl AesBlockCipher<'_> {
    pub fn name(&self) -> &str {
        match self {
            AesBlockCipher::CBC(_) => "CBC",
            AesBlockCipher::ECB(_) => "ECB",
        }
    }
}

impl<'e, T: AsRef<[u8]>> Cipher<T> for AesBlockCipher<'e> {
    fn encrypt<'g>(&self, plaintext: T) -> Vec<u8> {
        match self {
            AesBlockCipher::CBC(c) => c.encrypt(plaintext),
            AesBlockCipher::ECB(c) => c.encrypt(plaintext),
        }
    }

    fn decrypt<'f>(&self, ciphertext: T) -> Vec<u8> {
        match self {
            AesBlockCipher::CBC(c) => c.decrypt(ciphertext),
            AesBlockCipher::ECB(c) => c.decrypt(ciphertext),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AesCbcCipher<'b> {
    key: &'b [u8],
    block_size: usize,
    iv: &'b [u8],
}

impl<'b> AesCbcCipher<'b> {
    pub fn new(key: &'b [u8], block_size: usize, iv: &'b [u8]) -> Self {
        AesCbcCipher { key, block_size, iv }
    }
}

impl<'b, T: AsRef<[u8]>> Cipher<T> for AesCbcCipher<'b> {
    fn encrypt(&self, plaintext: T) -> Vec<u8> {
        let padded_text = plaintext.as_ref();
        let ecb = AesEcbCipher::new(self.key, self.block_size);

        padded_text
            .chunks(self.block_size)
            .fold(Vec::new(), |mut acc: Vec<u8>, curr_block| {
                let xored_value = if acc.is_empty() {
                    fixed_xor(curr_block, self.iv)
                } else {
                    fixed_xor(&curr_block, &acc[acc.len() - self.block_size..acc.len()])
                };

                let mut encrypted_block = ecb.encrypt(xored_value);

                acc.append(encrypted_block.as_mut());

                acc
            })
    }

    fn decrypt(&self, ciphertext: T) -> Vec<u8> {
        let ecb = AesEcbCipher::new(self.key, self.block_size);

        ciphertext.as_ref().chunks(self.block_size).enumerate().fold(
            Vec::new(),
            |mut acc: Vec<u8>, (index, curr_block)| {
                let decrypted_block = ecb.decrypt(curr_block);

                let mut xored_value = if acc.is_empty() {
                    fixed_xor(decrypted_block, self.iv)
                } else {
                    let ciphertext_blocks: Vec<&[u8]> = ciphertext.as_ref().chunks(self.block_size).collect();
                    fixed_xor(decrypted_block, ciphertext_blocks[index - 1].to_vec())
                };

                acc.append(xored_value.as_mut());

                acc
            },
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AesEcbCipher<'a> {
    key: &'a [u8],
    block_size: usize,
}

impl<'c> AesEcbCipher<'c> {
    pub fn new(key: &'c [u8], block_size: usize) -> Self {
        assert_eq!(key.len(), block_size);
        AesEcbCipher { key, block_size }
    }
}

impl<'a, T: AsRef<[u8]>> Cipher<T> for AesEcbCipher<'a> {
    fn encrypt(&self, plaintext: T) -> Vec<u8> {
        let cipher = Aes128::new(GenericArray::from_slice(self.key));
        let mut v = Vec::new();

        for c in plaintext.as_ref().chunks(self.block_size) {
            let mut block = GenericArray::from_slice(c).clone();
            cipher.encrypt_block(&mut block);
            v.append(&mut block.to_vec());
        }

        v
    }

    fn decrypt(&self, ciphertext: T) -> Vec<u8> {
        let cipher = Aes128::new(GenericArray::from_slice(self.key));
        let mut v = Vec::new();

        for c in ciphertext.as_ref().chunks(self.block_size) {
            let mut block = GenericArray::from_slice(&c).clone();
            cipher.decrypt_block(&mut block);
            v.append(&mut block.to_vec());
        }

        v
    }
}
