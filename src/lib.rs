extern crate aes;

mod base64;
mod bitarray;
mod ciphers;
mod utils;

#[cfg(test)]
mod tests {
    use crate::base64::{base64tohex, hex2base64, hex2string, string2hex};
    use crate::ciphers::breakers::break_single_xor_cipher;
    use crate::ciphers::{repeating_key_xor_cipher, single_byte_xor_cipher};
    use crate::utils::{
        all_ascii_chars, fixed_xor, hamming_distance, rate_string, read_base64file_to_hex,
    };
    use std::collections::HashMap;

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

        let mut file = File::open("/home/adam/programming/cryptopals/statics/set1ch4.txt").unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s).expect("Unable to read file");
        let file_lines = s.lines();

        for line in file_lines {
            for key in hex_keys.to_owned() {
                let ciphertext = string2hex(line);
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

        let mut base = 0;
        let mut fin_string = String::new();

        for (a, b) in score_map {
            if b >= base {
                base = b;
                fin_string = a;
            }
        }

        assert_eq!("Now that the party is jumping\n", fin_string);
    }

    #[test]
    fn challenge5() {
        let cleartext_string =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

        let key = "ICE".as_bytes().to_vec();
        let r1_bytes = cleartext_string.as_bytes().to_vec();
        let r1 = hex2string(repeating_key_xor_cipher(&r1_bytes, &key));

        assert_eq!(
            r1,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn challenge6() {
        let ciphertext =
            read_base64file_to_hex("/home/adam/programming/cryptopals/statics/set1ch6.txt");

        let mut vec = Vec::new();

        for keysize in 2..40 {
            let mut chunks = ciphertext.chunks(keysize);
            let mut count = 0;
            let mut dist = 0;

            while let (Some(f), Some(s)) = (chunks.next(), chunks.next()) {
                dist += hamming_distance(f, s);
                count += 1;
            }

            let normalized_distance = (dist / count) / keysize;

            vec.push((normalized_distance, keysize));
        }

        vec.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());

        let final_keysize = vec.iter().map(|(_, v)| *v).next().unwrap();
        assert_eq!(final_keysize, 29);

        let mut strings = vec![Vec::new(); final_keysize];
        let mut key = vec![0u8; final_keysize];

        for (i, c) in ciphertext.iter().enumerate() {
            strings[i % final_keysize].push(*c);
        }

        for (i, s) in strings.iter().enumerate() {
            key[i] = break_single_xor_cipher(s.as_slice());
        }

        let f = repeating_key_xor_cipher(ciphertext.as_slice(), key.as_slice());

        let s = String::from_utf8(f).unwrap();
        let s_key = String::from_utf8(key).unwrap();
    }

    #[test]
    fn challenge7() {
        use crate::ciphers::aes_ecb_cipher_decrypt;
        use std::io::Read;
        use std::ops::Add;

        let ciphertext =
            read_base64file_to_hex("/home/adam/programming/cryptopals/statics/set1ch7.txt");

        let key = "YELLOW SUBMARINE";

        let mut s = String::new();

        for chunk in ciphertext.chunks(16) {
            let r = aes_ecb_cipher_decrypt(chunk, key.as_bytes());
            s.push_str(String::from_utf8(r).unwrap().as_str());
        }

        println!("{}", s);
    }
}
