use std::cmp::Ordering;
use std::collections::HashMap;

use crate::bitarray::BitArray;

pub trait ByteSlice {
    fn pad(&self, block_size: usize) -> Vec<u8>;
    fn strip_pad(&self) -> Result<Vec<u8>, ()>;
}

impl ByteSlice for [u8] {
    fn pad(&self, block_size: usize) -> Vec<u8> {
        pkcs7_pad(self, block_size)
    }

    fn strip_pad(&self) -> Result<Vec<u8>, ()> {
        let last_byte = *self.last().unwrap() as usize;
        if self[self.len() - last_byte..self.len()].to_vec() == vec![last_byte as u8; last_byte] {
            Ok(self[0..self.len() - last_byte].to_vec())
        } else {
            Err(())
        }
    }
}

pub fn fixed_xor(arg1: Vec<u8>, arg2: Vec<u8>) -> Vec<u8> {
    assert_eq!(arg1.len(), arg2.len());
    let zip = arg1.iter().zip(arg2.iter());

    zip.map(|(a, b)| a ^ b).collect()
}

pub fn rate_string(input: &str) -> i64 {
    let freq_map = frequency_map();

    input
        .as_bytes()
        .iter()
        .map(|c| *c as char)
        .filter(|c| freq_map.contains_key(c))
        .map(|k| (*freq_map.get(&k).unwrap() * 1000_f64) as i64)
        .sum()
}

pub fn hamming_distance(arg1: &[u8], arg2: &[u8]) -> usize {
    match arg1.len().cmp(&arg2.len()) {
        Ordering::Less => (arg2.len() - arg1.len()),
        Ordering::Greater => (arg1.len() - arg2.len()),
        Ordering::Equal => {
            let first_bits = BitArray::new(arg1, 1);
            let second_bits = BitArray::new(arg2, 1);

            first_bits.zip(second_bits).map(|(a, b)| a ^ b).sum::<u8>() as usize
        }
    }
}

pub fn hex_to_char(i: u8) -> char {
    match i {
        0x0..=0x9 => (i + b'0') as char,
        0xa..=0xf => (i - 0xa + b'a') as char,
        _ => panic!("hex_to_char only converts short values between 0x0 and 0xf"),
    }
}

pub fn char_to_hex(c: char) -> u8 {
    match c {
        '0'..='9' => (c as u8 - b'0'),
        'a'..='f' => 10 + (c as u8 - b'a'),
        _ => panic!("char_to_hex only converts char values between '0' and 'f'"),
    }
}

pub fn all_ascii_chars() -> Vec<char> {
    //TODO: Replace with macro
    use std::iter::FromIterator;

    Vec::from_iter((0_u8..128_u8).map(|x| (x as char)))
}

pub fn frequency_map() -> HashMap<char, f64> {
    [
        (' ', 17.16),
        ('0', 0.551),
        ('1', 0.460),
        ('2', 0.332),
        ('3', 0.184),
        ('4', 0.135),
        ('5', 0.166),
        ('6', 0.115),
        ('7', 0.103),
        ('8', 0.105),
        ('9', 0.102),
        ('A', 0.313),
        ('B', 0.216),
        ('C', 0.390),
        ('D', 0.315),
        ('E', 0.267),
        ('F', 0.141),
        ('G', 0.187),
        ('H', 0.232),
        ('I', 0.321),
        ('J', 0.172),
        ('K', 0.068),
        ('L', 0.188),
        ('M', 0.353),
        ('N', 0.208),
        ('O', 0.184),
        ('P', 0.261),
        ('Q', 0.031),
        ('R', 0.252),
        ('S', 0.400),
        ('T', 0.332),
        ('U', 0.081),
        ('V', 0.089),
        ('W', 0.252),
        ('X', 0.034),
        ('Y', 0.03),
        ('Z', 0.007),
        ('a', 5.118),
        ('b', 1.019),
        ('c', 2.112),
        ('d', 2.507),
        ('e', 8.577),
        ('f', 1.372),
        ('g', 1.559),
        ('h', 2.744),
        ('i', 4.901),
        ('j', 0.086),
        ('k', 0.675),
        ('l', 3.175),
        ('m', 1.643),
        ('n', 4.970),
        ('o', 5.770),
        ('p', 1.548),
        ('q', 0.074),
        ('r', 4.258),
        ('s', 4.368),
        ('t', 6.370),
        ('u', 2.099),
        ('v', 0.846),
        ('w', 1.303),
        ('x', 0.195),
        ('y', 1.133),
        ('z', 0.059),
    ]
    .iter()
    .cloned()
    .collect()
}

pub fn read_base64file_to_hex(path: &str) -> Vec<u8> {
    use crate::base64::base64tohex;
    use std::fs;

    let s = fs::read_to_string(path).unwrap();

    let modified_string = s.replace("\n", "");

    base64tohex(modified_string.as_str())
}

fn pkcs7_pad(byte_slice: &[u8], block_size: usize) -> Vec<u8> {
    let pad_char = (block_size - byte_slice.len() % block_size) as u8;
    let pad_length = block_size - (byte_slice.len() % block_size);

    [byte_slice, vec![pad_char; pad_length].as_slice()].concat()
}

pub mod random {
    use rand::Rng;

    pub fn get_rand_bytes(length: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..length).map(|_| rng.gen()).collect()
    }
}

pub mod cookie {
    use std::collections::HashMap;

    pub fn escape_control_chars(input: &str) -> String {
        input.replace('&', "%26").replace('=', "%3D").replace(';', "%3B")
    }

    pub fn parse_kv(args: &[u8], separator: u8) -> HashMap<&[u8], &[u8]> {
        let mut hm = HashMap::new();
        for sub in args.split(|c| *c == separator) {
            let tup: Vec<&[u8]> = sub.split(|c| *c == b'=').collect();
            hm.insert(tup[0], tup[1]);
        }

        hm
    }

    pub fn encode_kv(hm: HashMap<&str, &str>) -> String {
        let email = escape_control_chars(*hm.get("email").unwrap());
        let uid = escape_control_chars(*hm.get("uid").unwrap());
        let role = escape_control_chars(*hm.get("role").unwrap());
        format!("email={}&uid={}&role={}", email, uid, role)
    }

    pub fn profile_for(email: &str) -> String {
        let mut hm = HashMap::new();
        hm.insert("uid", "10");
        hm.insert("role", "user");
        hm.insert("email", email);
        encode_kv(hm)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::cookie::{parse_kv, profile_for};

    use super::*;

    #[test]
    fn hamming_distance_test() {
        let distance = hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes());
        assert_eq!(distance, 37);
    }

    #[test]
    fn no_padding_needed_test() {
        let padded = b"YELLOW SUBMARINE".pad(16);
        assert_eq!(
            b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            padded.as_slice()
        );
    }

    #[test]
    fn test_cookie_parsing() {
        assert_eq!(profile_for("foo@bar.com"), "email=foo@bar.com&uid=10&role=user");
    }
}
