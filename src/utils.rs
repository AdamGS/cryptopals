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
    let freq_zip = chars_by_freq.zip(CHAR_FREQUENCY_TABLE.iter().map(|f| (f * 100f64) as i64));
    let mut frequency_map = HashMap::new();

    for (c, f) in freq_zip {
        frequency_map.insert(c, f);
    }

    let mut score = 0;

    for clear_c in input.chars() {
        score += frequency_map
            .get(&clear_c.to_ascii_uppercase())
            .unwrap_or(&0);
    }

    score
}

pub fn hamming_distance(first: &str, second: &str) -> usize {
    assert_eq!(first.len(), second.len());
    use crate::bitarray::BitArray;

    let mut first_bits = BitArray::new(first.as_bytes(), 1);
    let mut second_bits = BitArray::new(second.as_bytes(), 1);

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
