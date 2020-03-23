extern crate aes;

mod bitarray;
mod ciphers;
mod oracles;
mod utils;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Read;

    use rand::Rng;

    use crate::ciphers::aes_ciphers::{AesBlockCipher, AesCbcCipher, AesEcbCipher};
    use crate::ciphers::breakers::break_single_xor_cipher;
    use crate::ciphers::{repeating_key_xor_cipher, single_byte_xor_cipher, Cipher};
    use crate::oracles::{
        cbc_keyval_oracle, prefix_unknown_string_padded_oracle, random_padded_encryption_oracle,
        unknown_string_padded_oracle,
    };
    use crate::utils::base64::{base64tohex, hex2base64, hex2string, string2hex};
    use crate::utils::cookie::{escape_control_chars, parse_kv, profile_for};
    use crate::utils::random::get_rand_bytes;
    use crate::utils::{all_ascii_chars, fixed_xor, hamming_distance, rate_string, read_base64file_to_hex, ByteSlice};

    #[test]
    fn challenge1() {
        let base_string =
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
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
        let ciphertext = string2hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

        let key = break_single_xor_cipher(&ciphertext);
        let final_string = single_byte_xor_cipher(&ciphertext, key);

        assert_eq!(b"Cooking MC's like a pound of bacon".to_vec(), final_string);
    }

    #[test]
    fn challenge4() {
        let mut score_map = HashMap::new();
        let hex_keys: Vec<u8> = all_ascii_chars().iter().map(|b| *b as u8).collect();

        let mut file = File::open("statics/set1ch4.txt").unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s).expect("Unable to read file");
        let file_lines = s.lines();

        for line in file_lines {
            for key in hex_keys.to_owned() {
                let plaintext = single_byte_xor_cipher(string2hex(line), key);
                let plaintext_string = String::from_utf8(plaintext);

                if let Ok(v) = plaintext_string {
                    score_map.insert(v.clone(), rate_string(v.clone().as_str()));
                }
            }
        }

        let max_score = score_map.iter().max_by(|a, b| a.1.cmp(b.1)).unwrap().0;

        assert_eq!("Now that the party is jumping\n", max_score);
    }

    #[test]
    fn challenge5() {
        let key = "ICE";
        let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let ciphertext = hex2string(repeating_key_xor_cipher(plaintext, key));

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

        let actual_keysize = vec.iter().min_by(|a, b| a.0.cmp(&b.0)).unwrap().1;

        assert_eq!(actual_keysize, 29);

        let mut strings = vec![Vec::new(); actual_keysize];
        let mut key = vec![0u8; actual_keysize];

        for (i, c) in ciphertext.iter().enumerate() {
            strings[i % actual_keysize].push(*c);
        }

        for (i, s) in strings.iter().enumerate() {
            key[i] = break_single_xor_cipher(s.as_slice());
        }

        let s_key = String::from_utf8(key).unwrap();

        assert_eq!(s_key, "Terminator X: Bring the noise");
    }

    #[test]
    fn challenge7() {
        let ciphertext = read_base64file_to_hex("statics/set1ch7.txt");
        let key = b"YELLOW SUBMARINE";
        let cipher = AesEcbCipher::new(key, 16);

        let s = cipher.decrypt(ciphertext);

        println!("{:?}", String::from_utf8(s).unwrap());
    }

    #[test]
    fn challenge8() {
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
        assert_eq!(
            "YELLOW_SUBMARINE".as_bytes().pad(20),
            b"YELLOW_SUBMARINE\x04\x04\x04\x04"
        )
    }

    #[test]
    fn challenge10() {
        let cipher = AesCbcCipher::new(
            "AAAAAAAAAAAAAAAA".as_bytes(),
            16,
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".as_bytes(),
        );
        let plaintext = b"YELLOW SUBMARINEYELLOW SUBMARINE";
        let ciphertext = cipher.encrypt(plaintext);
        let new_plaintext = cipher.decrypt(ciphertext);

        assert_eq!(plaintext, &new_plaintext[0..plaintext.len()]);
    }

    #[test]
    fn challenge11() {
        let block_size = 16;
        let text = String::from_utf8(vec![65u8; 200]).unwrap();

        let mut rng = rand::thread_rng();
        let coinflip: i32 = rng.gen();
        let key = get_rand_bytes(block_size);
        let iv = get_rand_bytes(block_size);

        let cipher: AesBlockCipher = match coinflip % 2 == 0 {
            true => AesBlockCipher::ECB(AesEcbCipher::new(key.as_slice(), block_size)),
            false => AesBlockCipher::CBC(AesCbcCipher::new(key.as_slice(), block_size, iv.as_slice())),
        };

        let ciphertext = random_padded_encryption_oracle(text, cipher);

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
            let dummy_plaintext = vec![65u8; l];
            let ciphertext = unknown_string_padded_oracle(&dummy_plaintext, cipher);
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
        //For testing purposes later, and also because it makes the top loop prettier.
        let final_result = read_base64file_to_hex("statics/ch12.txt");

        // i is basically always unknown_string.len() + 1 at the start of the loop
        for i in 1..final_result.len() + 1 {
            // Length of the prefix padding, block_size * the block count for the block we are dealing
            // with within the unknown-string. We later subtract i because that's where the new guesses 'go'
            // with the already known characters
            let block_count = (1 + (i / 16)) * guessed_block_size;

            let mut hashmap: HashMap<Vec<u8>, char> = Default::default();
            //This is a known prefix
            let base_ciphertext = unknown_string_padded_oracle(&vec![65u8; block_count - i], cipher);

            for c in all_ascii_chars() {
                let mut input = vec![65u8; block_count - i];

                // Push all the known characters
                for byte in unknown_string.bytes() {
                    input.push(byte as u8);
                }

                // That's our current "guess", and we compute the ciphertext for it.
                input.push(c as u8);
                let ciphertext = unknown_string_padded_oracle(&input, cipher);

                //We put the precomputed ciphertext in here
                hashmap.insert(ciphertext[0..block_count].to_vec(), c);
            }

            //From all of the ciphertexts we just computed, we take the guess that shares the same
            //first block_count bytes with our base_ciphertext, and then unto the next character.
            unknown_string.push(*hashmap.get(&base_ciphertext[0..block_count]).unwrap());
        }

        assert_eq!(final_result, unknown_string.into_bytes());
    }

    #[test]
    fn challenge13() {
        let key = get_rand_bytes(16);
        let cipher = AesBlockCipher::ECB(AesEcbCipher::new(&key, 16));

        let plaintext_profile = profile_for("user@user.com").as_bytes().pad(16);
        let ciphertext = cipher.encrypt(plaintext_profile);
        let admin_profile = profile_for("user@user.admin").as_bytes().pad(16);
        let admin_ciphertext = cipher.encrypt(admin_profile);

        let manipulated = [ciphertext[0..32].to_vec(), admin_ciphertext[16..32].to_vec()]
            .concat()
            .pad(16);

        let manipulated_plaintext = &cipher.decrypt(manipulated)[0..37];
        assert_eq!(
            parse_kv(manipulated_plaintext, b'&')[b"role".as_ref()],
            b"admin".as_ref()
        );
    }

    #[test]
    fn challenge14() {
        let key = "ABCDEFGHIJKLMNOP".as_bytes();
        let mut rng = rand::thread_rng();
        let prefix_length = rng.gen_range(0, 16);
        let prefix = get_rand_bytes(prefix_length);
        let block_size = 16;
        let mut guessed_block_size = 0;

        let cipher = AesBlockCipher::ECB(AesEcbCipher::new(key, block_size));

        let baseline = prefix_unknown_string_padded_oracle(&prefix, [65u8], cipher).len();

        //Let's figure out the block size!
        for l in 2..40 {
            let dummy_plaintext = vec![65u8; l];
            let ciphertext = prefix_unknown_string_padded_oracle(&prefix, dummy_plaintext, cipher);
            if ciphertext.len() != baseline {
                guessed_block_size = ciphertext.len() - baseline;
                break;
            }
        }

        assert_eq!(guessed_block_size, 16);

        //Now we detected it's AES-ECB (Using the method from the 11th challenge)
        let known_str: Vec<u8> = vec![65u8; 200];
        let ciphertext = prefix_unknown_string_padded_oracle(&prefix, known_str, cipher);
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

        //We have to know the length of the prefix!
        let mut guessed_prefix_length: usize = 0;
        let mut prev_block: Vec<u8> = Default::default();

        // We send the oracle a known text, and i is actually equal (block_size - guessed_prefix_length + 1)
        for i in 1..17 {
            let cipher = prefix_unknown_string_padded_oracle(&prefix, vec![65u8; i], cipher);

            // If we filled the block ("overpadded" it), it will look the same as the previous 16 bytes.
            if cipher[0..16].to_vec() == prev_block {
                guessed_prefix_length = guessed_block_size - i + 1;
                break;
            }

            prev_block = cipher[0..16].to_vec();
        }

        assert_eq!(guessed_prefix_length, prefix_length);

        let mut unknown_string = String::new();
        //For testing purposes later, and also because it makes the top loop prettier.
        let final_result = read_base64file_to_hex("statics/ch12.txt");

        // This part is very similar to challenge
        for i in 1..final_result.len() + 1 {
            let block_count = (2 + (i / 16)) * guessed_block_size;

            let mut hashmap: HashMap<Vec<u8>, char> = Default::default();
            //This is a known prefix
            let base_ciphertext = prefix_unknown_string_padded_oracle(
                &prefix,
                vec![65u8; block_count - i - guessed_prefix_length],
                cipher,
            );

            for c in all_ascii_chars() {
                let mut input = vec![65u8; block_count - i - guessed_prefix_length];

                // Push all the known characters
                for byte in unknown_string.bytes() {
                    input.push(byte as u8);
                }

                // That's our current "guess", and we compute the ciphertext for it.
                input.push(c as u8);
                let ciphertext = prefix_unknown_string_padded_oracle(&prefix, input, cipher);

                //We put the precomputed ciphertext in here
                hashmap.insert(ciphertext[0..block_count].to_vec(), c);
            }

            //From all of the ciphertexts we just computed, we take the guess that shares the same
            //first block_count bytes with our base_ciphertext, and then unto the next character.r
            unknown_string.push(*hashmap.get(&base_ciphertext[0..block_count]).unwrap());
        }

        assert_eq!(final_result, unknown_string.into_bytes());
    }

    #[test]
    fn challenge15() {
        let valid = b"ICE ICE BABY\x04\x04\x04\x04";
        assert!(valid.strip_pad().is_ok());
        assert_eq!(valid.strip_pad().unwrap(), b"ICE ICE BABY");

        let invalid = b"ICE ICE BABY\x04\x04\x04";
        assert!(invalid.strip_pad().is_err());

        let another_invalid = b"ICE ICE BABY\x01\x02\x03\x04";
        assert!(another_invalid.strip_pad().is_err());
    }

    #[test]
    fn challenge16() {
        let block_size = 16;
        let key = get_rand_bytes(block_size);
        let iv = get_rand_bytes(block_size);

        let cipher = AesBlockCipher::CBC(AesCbcCipher::new(&key, block_size, &iv));
        let escaped = escape_control_chars("XadminXtrue");
        let mut modified_ciphertext = cbc_keyval_oracle(escaped, cipher);

        let prev_block_idx = 16;
        modified_ciphertext[prev_block_idx] ^= b'X' ^ b';';
        modified_ciphertext[prev_block_idx + 6] ^= b'X' ^ b'=';

        let decrypted = cipher.decrypt(modified_ciphertext);
        let parsed = parse_kv(&decrypted, b';');

        assert!(parsed.contains_key("admin".as_bytes()))
    }
}
