pub struct BitArray<'a> {
    step: usize,
    bytes: &'a [u8],
    index: usize,
    bidx: usize,
}

impl<'a> BitArray<'a> {
    pub fn new(bytes: &'a [u8], step: usize) -> BitArray {
        assert!(step <= 8);
        BitArray {
            bytes,
            step,
            index: 0,
            bidx: 0,
        }
    }
}

impl<'a> Iterator for BitArray<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let remaining_in_byte: usize = 8 - self.bidx;

        let spare_bits = if remaining_in_byte > self.step {
            remaining_in_byte - self.step
        } else {
            0
        };

        let to_read = remaining_in_byte - spare_bits;

        let high_byte = match self.bytes.get(self.index) {
            Some(b) => b << self.bidx >> (spare_bits + self.bidx),
            _ => return None,
        };

        if to_read < self.step {
            self.index += 1;
            let needed = self.step - remaining_in_byte;

            let low_byte = match self.bytes.get(self.index) {
                Some(v) => (v >> (8 - needed)),
                _ => 0,
            };

            self.bidx = needed;

            return Some((high_byte << needed | low_byte) as u8);
        }

        self.bidx += to_read;
        assert!(self.bidx <= 8);
        if self.bidx == 8 {
            self.bidx = 0;
            self.index += 1;
        }

        Some(high_byte as u8)
    }
}
