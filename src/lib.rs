extern crate aes;

mod base64;
mod bitarray;
mod ciphers;
mod utils;

#[cfg(test)]
mod tests {
    use crate::base64::{base64tohex, hex2base64, hex2string, string2hex};
    use crate::ciphers::breakers::break_single_xor_cipher;
    use crate::ciphers::{
        random_padded_encryption_oracle, repeating_key_xor_cipher, single_byte_xor_cipher,
        unknown_string_padded_oracle, AesBlockCipher,
    };
    use crate::ciphers::{AesCbcCipher, AesEcbCipher, Cipher};
    use crate::utils::{
        all_ascii_chars, fixed_xor, hamming_distance, pkcs7_pad, rate_string,
        read_base64file_to_hex,
    };
    use rand::Rng;
    use std::any::Any;
    use std::collections::HashMap;
    use std::ops::Deref;

    #[test]
    fn challenge1() {
        let base_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let hex_string = string2hex(base_string);
        assert_eq!(base64_output, hex2base64(hex_string));
    }

    #[test]
    fn challenge2() {
        let a_string = "1c0111001f010100061a024b53535009181c";
        let b_string = "686974207468652062756c6c277320657965";
        let output = "746865206b696420646f6e277420706c6179";
        assert_eq!(
            fixed_xor(string2hex(a_string), string2hex(b_string)),
            string2hex(output)
        );
    }

    #[test]
    fn challenge3() {
        let ciphertext =
            string2hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

        let key = break_single_xor_cipher(ciphertext.as_slice());
        let fin_string = String::from_utf8(single_byte_xor_cipher(&ciphertext, key)).unwrap();

        assert_eq!("Cooking MC's like a pound of bacon", fin_string);
    }

    #[test]
    fn challenge4() {
        use std::fs::File;
        use std::io::Read;

        let mut score_map = HashMap::new();
        let hex_keys: Vec<u8> = all_ascii_chars().iter().map(|b| *b as u8).collect();

        let mut file = File::open("statics/set1ch4.txt").unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s).expect("Unable to read file");
        let file_lines = s.lines();

        for line in file_lines {
            for key in hex_keys.to_owned() {
                let cleartext = single_byte_xor_cipher(&string2hex(line), key);
                let cleartext_string = String::from_utf8(cleartext);

                match cleartext_string {
                    Ok(v) => {
                        score_map.insert(v.clone(), rate_string(v.clone().as_str()));
                    }
                    _ => (),
                }
            }
        }

        let mut curr_score = 0;
        let mut curr_string = String::new();

        for (string, score) in score_map {
            if score >= curr_score {
                curr_score = score;
                curr_string = string;
            }
        }

        assert_eq!("Now that the party is jumping\n", curr_string);
    }

    #[test]
    fn challenge5() {
        let key = "ICE".as_bytes();
        let cleartext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes();
        let ciphertext = hex2string(repeating_key_xor_cipher(cleartext, key));

        assert_eq!(
            ciphertext,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn challenge6() {
        let ciphertext = read_base64file_to_hex("statics/set1ch6.txt");

        let mut vec = Vec::new();

        // For every keysize in the a likely range
        for keysize in 2..40 {
            let mut chunks = ciphertext.chunks(keysize);
            let mut num_of_pairs = 0;
            let mut dist = 0;

            // We calculate the differense between the first keysize-sized block and the second
            while let (Some(f), Some(s)) = (chunks.next(), chunks.next()) {
                dist += hamming_distance(f, s);
                num_of_pairs += 1;
            }

            // Average distance between two blocks, normalized by dividing by the keysize
            let normalized_distance = (dist / num_of_pairs) / keysize;

            vec.push((normalized_distance, keysize));
        }

        vec.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());

        let actual_keysize = vec.first().unwrap().1;
        assert_eq!(actual_keysize, 29);

        let mut strings = vec![Vec::new(); actual_keysize];
        let mut key = vec![0u8; actual_keysize];

        for (i, c) in ciphertext.iter().enumerate() {
            strings[i % actual_keysize].push(*c);
        }

        for (i, s) in strings.iter().enumerate() {
            key[i] = break_single_xor_cipher(s.as_slice());
        }

        let f = repeating_key_xor_cipher(ciphertext.as_slice(), key.as_slice());
        let s = String::from_utf8(f).unwrap();
        let s_key = String::from_utf8(key).unwrap();

        assert_eq!(s_key, "Terminator X: Bring the noise");
    }

    #[test]
    fn challenge7() {
        use std::fs;
        use std::io::Read;
        use std::ops::Add;

        let ciphertext = read_base64file_to_hex("statics/set1ch7.txt");

        let key = "YELLOW SUBMARINE";
        let cipher = AesEcbCipher::new(key.as_bytes(), 16);

        let s = cipher.decrypt(ciphertext.as_slice());

        println!("{:?}", String::from_utf8(s).unwrap());
    }

    #[test]
    fn challenge8() {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open("statics/ch8.txt").unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s).expect("Unable to read file");
        let file_lines = s.lines().map(|l| base64tohex(l));

        let mut result_map: HashMap<usize, usize> = Default::default();

        let block_size = 16;

        // Count how many block of block_size repeat within each line,
        // The line with the most repeats is assumed to be encrypted in ecb mode.
        for (idx, line) in file_lines.enumerate() {
            for chunk in line.chunks(block_size) {
                for internal in line.chunks(block_size) {
                    if internal == chunk {
                        *result_map.entry(idx).or_insert(0) += 1;
                    }
                }
            }
        }

        let ecb_line = result_map.iter().max_by(|x, y| x.1.cmp(y.1)).unwrap();

        println!("The line is the AES-ECB encrypted data is: {}", ecb_line.0);
        assert_eq!(*ecb_line.0, 132usize);
    }

    #[test]
    fn challenge9() {
        use crate::utils::pkcs7_pad;
        assert_eq!(
            String::from_utf8(pkcs7_pad("YELLOW_SUBMARINE".as_bytes(), 20)).unwrap(),
            "YELLOW_SUBMARINE\x04\x04\x04\x04"
        )
    }

    #[test]
    fn challenge10() {
        use crate::ciphers::AesCbcCipher;
        let cipher = AesCbcCipher::new(
            "AAAAAAAAAAAAAAAA".as_bytes(),
            16,
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".as_bytes(),
        );
        let cleartext = "YELLOW SUBMARINEYELLOW SUBMARINE";
        let ciphertext = cipher.encrypt(cleartext.as_bytes());
        let new_cleartext = cipher.decrypt(ciphertext.as_slice());

        assert_eq!(cleartext.as_bytes(), &new_cleartext[0..cleartext.len()]);
    }

    #[test]
    fn challenge11() {
        use crate::ciphers::random_padded_encryption_oracle;
        use crate::ciphers::AesBlockCipher;
        use crate::utils::random::get_rand_bytes;

        let block_size = 16;
        let text = String::from_utf8(vec![65u8; 200]).unwrap();

        let mut rng = rand::thread_rng();
        let coinflip: i32 = rng.gen();
        let key = get_rand_bytes(block_size);
        let iv = get_rand_bytes(block_size);

        let cipher: AesBlockCipher = match coinflip % 2 == 0 {
            true => AesBlockCipher::ECB(AesEcbCipher::new(key.as_ref(), block_size)),
            false => {
                AesBlockCipher::CBC(AesCbcCipher::new(key.as_ref(), block_size, iv.as_slice()))
            }
        };

        let ciphertext = random_padded_encryption_oracle(text.as_bytes(), cipher.clone());

        let mut identical_block_count = 0;

        // Count identical blocks, becase ECB has those for the input we engineered
        for a in ciphertext.chunks(16) {
            for b in ciphertext.chunks(16) {
                if a == b {
                    identical_block_count += 1;
                }
            }
        }

        // identical_block_count / ( ciphertext.len() / block_size) Because it makes some wired sense
        let detected_cipher = if identical_block_count / (ciphertext.len() / block_size) > 2 {
            "ECB"
        } else {
            "CBC"
        };

        assert_eq!(cipher.name(), detected_cipher);
    }

    #[test]
    fn challenge12() {
        let key = "ABCDEFGHIJKLMNOP".as_bytes();
        let block_size = 16;
        let mut guessed_block_size = 0;

        let cipher = AesBlockCipher::ECB(AesEcbCipher::new(key, block_size));

        let baseline = unknown_string_padded_oracle(&[65u8], cipher).len();

        //Let's figure out the block size!
        for l in 2..40 {
            let dummy_cleartext = vec![65u8; l];
            let ciphertext = unknown_string_padded_oracle(&dummy_cleartext, cipher);
            if ciphertext.len() != baseline {
                guessed_block_size = ciphertext.len() - baseline;
                break;
            }
        }

        assert_eq!(guessed_block_size, 16);

        //Now we detected it's AES-ECB (Using the method from the 11th challenge)
        let known_str: Vec<u8> = vec![65u8; 200];
        let ciphertext = unknown_string_padded_oracle(&known_str, cipher);
        let mut identical_block_count = 0;

        for a in ciphertext.chunks(16) {
            for b in ciphertext.chunks(16) {
                if a == b {
                    identical_block_count += 1;
                }
            }
        }

        // identical_block_count / ( ciphertext.len() / block_size) Because it makes some wired sense
        let detected_cipher = if identical_block_count / (ciphertext.len() / block_size) > 3 {
            "ECB"
        } else {
            "CBC"
        };

        // Tests to make sure I don't break anything
        assert_eq!(detected_cipher, cipher.name());
        assert_eq!(detected_cipher, "ECB");

        let mut unknown_string = String::new();
        let final_result = read_base64file_to_hex("statics/ch12.txt");

        for i in 1..final_result.len() + 1 {
            let end_block_idx = (1 + (i / 16)) * guessed_block_size;

            let mut hashmap: HashMap<Vec<u8>, char> = Default::default();
            let base_ciphertext =
                unknown_string_padded_oracle(&vec![65u8; end_block_idx - i], cipher);

            for c in all_ascii_chars() {
                let mut input = vec![65u8; end_block_idx - i];

                for byte in unknown_string.bytes() {
                    input.push(byte as u8);
                }

                input.push(c as u8);
                let ciphertext = unknown_string_padded_oracle(&input, cipher);

                if ciphertext[0..end_block_idx] == base_ciphertext[0..end_block_idx] {
                    hashmap.insert(ciphertext[0..end_block_idx].to_vec(), c);
                }
            }

            unknown_string.push(*hashmap.get(&base_ciphertext[0..end_block_idx]).unwrap());
        }

        assert_eq!(final_result, unknown_string.into_bytes());
    }
}
