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
    let chars_by_freq = "ETAOINSRHDLUCMFYWGPBVKXQJZ".chars();
    let freq_zip = chars_by_freq.zip(CHAR_FREQUENCY_TABLE.iter().map(|f| (f * 1000f64) as i64));
    let mut frequency_map = HashMap::new();

    for (c, f) in freq_zip {
        frequency_map.insert(c, f);
    }

    let mut score = 0;

    for clear_c in input.chars() {
        if clear_c.is_alphabetic(){
            score += frequency_map.get(&clear_c.to_ascii_uppercase()).unwrap();
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
