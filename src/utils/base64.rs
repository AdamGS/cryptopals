use std::collections::HashMap;

use crate::bitarray::BitArray;
use crate::utils::{char_to_hex, hex_to_char};
use itertools::Itertools;

//TODO: Replace with macro
const BASE64_TABLE: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
];

pub fn string2hex<T: AsRef<str>>(string: T) -> Vec<u8> {
    let mut byte_vec = Vec::new();
    let mut chars = string.as_ref().chars();

    while let (Some(l), Some(r)) = (chars.next(), chars.next()) {
        let left = char_to_hex(l) << 4;
        let right = char_to_hex(r);
        byte_vec.push(left | right);
    }

    byte_vec
}

pub fn hex2string<T: AsRef<[u8]>>(hex_bytes: T) -> String {
    let mut string = String::new();

    for b in hex_bytes.as_ref() {
        let l = b >> 4;
        let r = b & 15;
        string.push(hex_to_char(l));
        string.push(hex_to_char(r));
    }

    string
}

pub fn hex2base64<T: AsRef<[u8]>>(bytearray: T) -> String {
    let mut base64_string = String::new();
    let mut bits = BitArray::new(bytearray.as_ref(), 6);

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

pub fn base64tohex<T: AsRef<str>>(string: T) -> Vec<u8> {
    use std::iter::FromIterator;
    let char_to_index_map: HashMap<&char, i32> = HashMap::from_iter(BASE64_TABLE.iter().zip(0..64));

    // Encode the base64 string into 6-bit values
    let bitencoded_vec = string
        .as_ref()
        .chars()
        .filter(|c| *c != '=')
        .map(|c| char_to_index_map[&c] as u8)
        .collect_vec();

    let bits = BitArray::new(&bitencoded_vec, 2);

    bits.enumerate()
        .filter(|(idx, _)| idx % 4 != 0)
        .tuples()
        .map(|((_, a), (_, b), (_, c), (_, d))| a << 6 | b << 4 | c << 2 | d)
        .collect_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64tohex_test() {
        let base64_input = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let test_value = base64tohex(base64_input);

        let hexstring_output =
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let known_value = string2hex(hexstring_output);

        assert_eq!(test_value, known_value);
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
}
