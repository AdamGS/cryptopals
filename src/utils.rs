use crate::bitarray::BitArray;
use std::collections::HashMap;

const CHAR_FREQUENCY_TABLE: [f64; 26] = [
    0.1202, 0.910, 0.812, 0.768, 0.731, 0.695, 0.628, 0.602, 0.592, 0.432, 0.398, 0.288, 0.271,
    0.261, 0.23, 0.211, 0.209, 0.203, 0.182, 0.149, 0.111, 0.069, 0.017, 0.011, 0.01, 0.007,
];

pub fn euclidean_distance(vec1: Vec<f64>, vec2: Vec<f64>) -> f64 {
    assert_eq!(vec1.len(), vec2.len());
    let mut sum = 0f64;

    for i in 0..vec1.len() {
        sum += (vec1[i] - vec2[i]).powf(2.0);
    }

    sum.sqrt()
}

pub fn fixed_xor(arg1: Vec<u8>, arg2: Vec<u8>) -> Vec<u8> {
    assert_eq!(arg1.len(), arg2.len());
    let mut x: Vec<u8> = Vec::new();
    let it = arg1.iter().zip(arg2.iter());
    for (a, b) in it {
        x.push(a ^ b);
    }
    x
}

pub fn rate_string(input: &str) -> i64 {
    let freq_map = frequency_map();

    let mut score = 0;

    for clear_c in input.as_bytes() {
        let new_char = *clear_c as char;
        if let Some(_) = freq_map.get(&new_char) {
            score += (freq_map.get(&new_char).unwrap() * 1000_f64) as i64;
        }
    }

    score
}

pub fn hamming_distance(first: &[u8], second: &[u8]) -> usize {
    if first.len() > second.len() {
        return (first.len() - second.len());
    } else if first.len() < second.len() {
        return second.len() - first.len();
    }

    let mut first_bits = BitArray::new(first, 1);
    let mut second_bits = BitArray::new(second, 1);

    let mut count: usize = 0;

    loop {
        let (f, s) = (first_bits.next(), second_bits.next());

        match (f, s) {
            (Some(f), Some(s)) => {
                if f != s {
                    count += 1;
                }
            }
            _ => break,
        }
    }

    count
}

pub fn hex_to_char(i: u8) -> char {
    match i {
        0x0...0x9 => (i + b'0') as char,
        0xa...0xf => (i - 0xa + b'a') as char,
        _ => panic!("hex_to_char only converts short values between 0x0 and 0xf"),
    }
}

pub fn char_to_hex(c: char) -> u8 {
    match c {
        '0'...'9' => (c as u8 - b'0'),
        'a'...'f' => 10 + (c as u8 - b'a'),
        _ => panic!("char_to_hex only converts char values between '0' and 'f'"),
    }
}

pub fn all_chars() -> Vec<char> {
    use std::iter::FromIterator;
    let iter = (0_u8..128_u8).map(|x| (x as char));

    Vec::from_iter(iter)
}

pub fn frequency_map() -> HashMap<char, f64> {
    let map = [
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
        ('z', 0.059)
    ]
    .iter()
    .cloned()
    .collect();

    map
}
