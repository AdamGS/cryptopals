use crate::bitarray::BitArray;
use crate::utils::fixed_xor;
use crate::utils::{char_to_hex, hex_to_char};
use std::collections::HashMap;

const BASE64_TABLE: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

const ALL_CHARS: [char; 62] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9',
];

fn string2hex(string: &str) -> Vec<u8> {
    let mut byte_vec = Vec::new();
    let mut chars = string.chars();
    while let (Some(l), Some(r)) = (chars.next(), chars.next()) {
        let left = char_to_hex(l) << 4;
        let right = char_to_hex(r);
        byte_vec.push(left | right);
    }

    byte_vec
}

fn hex2string(hex_bytes: Vec<u8>) -> String {
    let mut string = String::new();

    for b in hex_bytes.iter() {
        let l = b >> 4;
        let r = b & 15;
        string.push(hex_to_char(l));
        string.push(hex_to_char(r));
    }

    string
}

fn hex2base64(bytearray: Vec<u8>) -> String {
    let mut base64_string = String::new();
    let mut bits = BitArray::new(bytearray.as_slice(), 6);

    loop {
        let block = (bits.next(), bits.next(), bits.next(), bits.next());
        match block {
            (None, _, _, _) => break,
            (Some(a), Some(b), c, d) => {
                base64_string.push(BASE64_TABLE[a as usize]);
                base64_string.push(BASE64_TABLE[b as usize]);

                match c {
                    Some(c) => base64_string.push(BASE64_TABLE[c as usize]),
                    _ => base64_string.push('='),
                }

                match d {
                    Some(d) => base64_string.push(BASE64_TABLE[d as usize]),
                    _ => base64_string.push('='),
                }
            }
            _ => unreachable!(),
        }
    }
    base64_string
}

fn base64tohex(string: &str) -> Vec<u8> {
    use std::iter::FromIterator;
    let mut v = Vec::new();
    let char_to_index_map: HashMap<&char, i32> = HashMap::from_iter(BASE64_TABLE.iter().zip(0..64));
    let mut temp_vec = Vec::new();

    for c in string.chars() {
        if c != '=' {
            temp_vec.push(char_to_index_map[&c] as u8);
        }
    }

    let mut r: u8 = 0;
    let mut has = 0;
    let mut bits = BitArray::new(temp_vec.as_slice(), 2);

    for (i, two_bits) in bits.enumerate() {
        if i % 4 != 0 {
            has += 1;
            r = (r | two_bits) << if has % 4 == 0 { 0 } else { 2 };;

            if has == 4 {
                v.push(r);
                has = 0;
                r = 0;
            }
        }
    }

    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphers::breakers::break_single_xor_cipher;
    use crate::ciphers::single_byte_xor_cipher;
    use crate::utils::{all_chars, hamming_distance, rate_string};
    use std::io::Read;

    #[test]
    fn challenge1() {
        let base_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let hex_string = string2hex(base_string);
        assert_eq!(base64_output, hex2base64(hex_string));
    }

    #[test]
    fn base64tohex_test() {
        let base64_input = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let hexstring_output = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let test_value = base64tohex(base64_input);
        let known_value = string2hex(hexstring_output);

        assert_eq!(test_value, known_value);
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
        let hex_keys: Vec<u8> = all_chars().iter().map(|b| *b as u8).collect();

        let mut file = File::open("/home/adam/programming/cryptopals/statics/set1ch4.txt").unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s);
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
        use crate::ciphers::repeating_key_xor_cipher;
        use std::ops::Add;

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
        use crate::ciphers::breakers::break_single_xor_cipher;
        use crate::ciphers::repeating_key_xor_cipher;
        use std::fs::File;

        let mut file: File =
            File::open("/home/adam/programming/cryptopals/statics/set1ch6.txt").unwrap();
        let mut file_string = String::new();
        file.read_to_string(&mut file_string);

        let ciphertext = base64tohex(file_string.replace("\n", "").as_str());

        let mut vec = Vec::new();

        use std::f64::MAX;
        let distance = MAX;

        for keysize in 2..40 {
            let mut chunks = ciphertext.chunks(keysize);
            let mut count = 0;
            let mut dist = 0;
            loop {
                let (f, s) = (chunks.next(), chunks.next());

                match (f, s) {
                    (Some(f), Some(s)) => {
                        dist += hamming_distance(f, s);
                        count += 1;
                    }
                    _ => break,
                }
            }

            let normalized_distance = (dist / count) / keysize;

            vec.push((normalized_distance, keysize));
        }

        vec.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());

        let final_keysize = vec.iter().map(|(k, v)| *v).next().unwrap();

        let mut strings = vec![Vec::new(); final_keysize];
        let mut key = vec![0u8; final_keysize];

        for (i, c) in ciphertext.iter().enumerate() {
            strings[i % final_keysize].push(*c);
        }

        for (i, s) in strings.iter().enumerate() {
            key[i] = break_single_xor_cipher(s.as_slice());
        }

        let f = repeating_key_xor_cipher(ciphertext.as_slice(), key.as_slice());

        //let s: Vec<char> = f.iter().map(|b| *b as char).collect();
        let s = String::from_utf8(f).unwrap();
        let s_key = String::from_utf8(key).unwrap();

        // println!("{}", String::from_utf8(key).unwrap());
        println!("{}", s_key);
    }
    #[test]
    fn char_to_hex_test() {
        assert_eq!(char_to_hex('f'), 15);
    }

    #[test]
    fn hex_to_char_test() {
        assert_eq!(hex_to_char(15), 'f');
    }
    #[test]
    fn hex2string_test() {
        assert_eq!(hex2string(string2hex("1fa2")), "1fa2");
    }

    #[test]
    fn hamming_distance_test() {
        use crate::utils::hamming_distance;

        let distance = hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes());
        assert_eq!(distance, 37);
    }
}
