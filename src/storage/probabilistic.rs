use crate::storage::hashtable::{fnv1a_64, siphash24};

pub const HLL_PRECISION: usize = 14;
pub const HLL_REGISTERS: usize = 1 << HLL_PRECISION; // 16,384 registers
pub const HLL_PACKED_BYTES: usize = (HLL_REGISTERS * 6) / 8; // 12,288 bytes (6-bit packed)

#[inline]
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

#[inline]
fn uniform_hash64(seed0: u64, seed1: u64, item: &[u8]) -> u64 {
    fmix64(siphash24(seed0, seed1, item) ^ fnv1a_64(item).rotate_left(13))
}

/// HyperLogLog with 16,384 6-bit packed registers (12 KiB), bias-corrected harmonic mean & LinearCounting.
#[derive(Clone, Debug)]
pub struct HyperLogLog {
    packed: Box<[u8]>,
}

impl Default for HyperLogLog {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperLogLog {
    pub fn new() -> Self {
        Self {
            packed: vec![0u8; HLL_PACKED_BYTES].into_boxed_slice(),
        }
    }

    pub fn from_packed_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() != HLL_PACKED_BYTES {
            return None;
        }
        Some(Self {
            packed: raw.to_vec().into_boxed_slice(),
        })
    }

    #[inline]
    pub fn as_packed_bytes(&self) -> &[u8] {
        &self.packed
    }

    #[inline]
    pub fn get_register(&self, idx: usize) -> u8 {
        let bit_offset = idx * 6;
        let byte_idx = bit_offset >> 3;
        let shift = bit_offset & 7;
        let lo = self.packed[byte_idx] as u16;
        let hi = if byte_idx + 1 < HLL_PACKED_BYTES {
            (self.packed[byte_idx + 1] as u16) << 8
        } else {
            0
        };
        (((lo | hi) >> shift) & 0x3F) as u8
    }

    #[inline]
    pub fn set_register(&mut self, idx: usize, val: u8) {
        let v = (val & 0x3F) as u16;
        let bit_offset = idx * 6;
        let byte_idx = bit_offset >> 3;
        let shift = bit_offset & 7;
        let clear_mask = !(0x3Fu16 << shift);

        let lo = self.packed[byte_idx] as u16;
        let hi = if byte_idx + 1 < HLL_PACKED_BYTES {
            (self.packed[byte_idx + 1] as u16) << 8
        } else {
            0
        };
        let combined = ((lo | hi) & clear_mask) | (v << shift);
        self.packed[byte_idx] = (combined & 0xFF) as u8;
        if byte_idx + 1 < HLL_PACKED_BYTES {
            self.packed[byte_idx + 1] = (combined >> 8) as u8;
        }
    }

    /// Inserts `item`, returning `true` if any internal 6-bit register changed.
    pub fn add(&mut self, item: &[u8]) -> bool {
        let h = uniform_hash64(0x9e37_79b9_7f4a_7c15, 0xd1b5_4a32_d192_ed03, item);
        let idx = (h & ((HLL_REGISTERS as u64) - 1)) as usize;
        let w = h >> HLL_PRECISION;
        // Count leading zeros in the remaining (64 - 14) = 50 bits, capped at 51.
        let shifted = (w << HLL_PRECISION) | (1u64 << (HLL_PRECISION - 1));
        let rho = (shifted.leading_zeros() as u8).saturating_add(1).min(63);
        let cur = self.get_register(idx);
        if rho > cur {
            self.set_register(idx, rho);
            true
        } else {
            false
        }
    }

    pub fn merge_from(&mut self, other: &HyperLogLog) -> bool {
        let mut changed = false;
        for idx in 0..HLL_REGISTERS {
            let other_v = other.get_register(idx);
            if other_v > self.get_register(idx) {
                self.set_register(idx, other_v);
                changed = true;
            }
        }
        changed
    }

    pub fn count(&self) -> u64 {
        let m = HLL_REGISTERS as f64;
        let alpha_m = 0.7213 / (1.0 + 1.079 / m);

        let mut harmonic_sum = 0.0f64;
        let mut zero_regs = 0usize;
        for idx in 0..HLL_REGISTERS {
            let r = self.get_register(idx);
            if r == 0 {
                zero_regs += 1;
                harmonic_sum += 1.0;
            } else {
                harmonic_sum += f64::from_bits((1023u64 - (r as u64)) << 52);
            }
        }

        let raw_est = alpha_m * m * m / harmonic_sum;
        let corrected = if raw_est <= 2.5 * m {
            if zero_regs > 0 {
                // Small-range LinearCounting bias correction
                m * (m / (zero_regs as f64)).ln()
            } else {
                raw_est
            }
        } else {
            raw_est
        };
        corrected.round() as u64
    }
}

/// Kirsch-Mitzenmacher double-hashed Bloom Filter (`g_i(x) = h1(x) + i * h2(x) mod m`).
#[derive(Clone, Debug)]
pub struct BloomFilter {
    bits: Box<[u64]>,
    num_bits: usize,
    num_probes: u32,
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::with_rate(131_072, 7)
    }
}

impl BloomFilter {
    pub fn with_rate(requested_bits: usize, num_probes: u32) -> Self {
        let words = (requested_bits.max(1024) + 63) / 64;
        let num_bits = words * 64;
        Self {
            bits: vec![0u64; words].into_boxed_slice(),
            num_bits,
            num_probes: num_probes.clamp(2, 16),
        }
    }

    pub fn from_raw_parts(num_probes: u32, words: Vec<u64>) -> Self {
        let num_bits = words.len() * 64;
        Self {
            bits: words.into_boxed_slice(),
            num_bits,
            num_probes,
        }
    }

    #[inline]
    pub fn num_probes(&self) -> u32 {
        self.num_probes
    }

    #[inline]
    pub fn words(&self) -> &[u64] {
        &self.bits
    }

    #[inline]
    fn hash_pair(item: &[u8]) -> (u64, u64) {
        let h1 = uniform_hash64(0x243f_6a88_85a3_08d3, 0x1319_8a2e_0370_7344, item);
        let h2 = uniform_hash64(0xa409_3822_299f_31d0, 0x082e_fa98_ec4e_6c89, item) | 1;
        (h1, h2)
    }

    /// Inserts `item`, returning `true` if at least one bit flipped from 0 -> 1.
    pub fn add(&mut self, item: &[u8]) -> bool {
        let (h1, h2) = Self::hash_pair(item);
        let m = self.num_bits as u64;
        let mut newly_set = false;
        for i in 0..self.num_probes {
            let bit_idx = (h1.wrapping_add((i as u64).wrapping_mul(h2)) % m) as usize;
            let word = bit_idx >> 6;
            let mask = 1u64 << (bit_idx & 63);
            if (self.bits[word] & mask) == 0 {
                self.bits[word] |= mask;
                newly_set = true;
            }
        }
        newly_set
    }

    pub fn exists(&self, item: &[u8]) -> bool {
        let (h1, h2) = Self::hash_pair(item);
        let m = self.num_bits as u64;
        for i in 0..self.num_probes {
            let bit_idx = (h1.wrapping_add((i as u64).wrapping_mul(h2)) % m) as usize;
            let word = bit_idx >> 6;
            let mask = 1u64 << (bit_idx & 63);
            if (self.bits[word] & mask) == 0 {
                return false;
            }
        }
        true
    }
}

pub const CMS_DEPTH: usize = 4;
pub const CMS_WIDTH: usize = 2048;

const CMS_SEEDS: [(u64, u64); CMS_DEPTH] = [
    (0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b),
    (0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1),
    (0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f),
    (0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179),
];

/// 4x2048 Count-Min Sketch for heavy-hitter point frequency estimation.
#[derive(Clone, Debug)]
pub struct CountMinSketch {
    matrix: Box<[[u64; CMS_WIDTH]; CMS_DEPTH]>,
}

impl Default for CountMinSketch {
    fn default() -> Self {
        Self::new()
    }
}

impl CountMinSketch {
    pub fn new() -> Self {
        Self {
            matrix: Box::new([[0u64; CMS_WIDTH]; CMS_DEPTH]),
        }
    }

    pub fn from_matrix(matrix: Box<[[u64; CMS_WIDTH]; CMS_DEPTH]>) -> Self {
        Self { matrix }
    }

    #[inline]
    pub fn matrix(&self) -> &[[u64; CMS_WIDTH]; CMS_DEPTH] {
        &self.matrix
    }

    pub fn incr_by(&mut self, item: &[u8], delta: u64) -> u64 {
        let mut min_est = u64::MAX;
        for row in 0..CMS_DEPTH {
            let (s0, s1) = CMS_SEEDS[row];
            let col = (uniform_hash64(s0, s1, item) as usize) & (CMS_WIDTH - 1);
            let next = self.matrix[row][col].saturating_add(delta);
            self.matrix[row][col] = next;
            if next < min_est {
                min_est = next;
            }
        }
        min_est
    }

    pub fn query(&self, item: &[u8]) -> u64 {
        let mut min_est = u64::MAX;
        for row in 0..CMS_DEPTH {
            let (s0, s1) = CMS_SEEDS[row];
            let col = (uniform_hash64(s0, s1, item) as usize) & (CMS_WIDTH - 1);
            let val = self.matrix[row][col];
            if val < min_est {
                min_est = val;
            }
        }
        min_est
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hyperloglog_accuracy_under_1_5_percent_and_bloom_cms() {
        let mut hll_a = HyperLogLog::new();
        let mut hll_b = HyperLogLog::new();
        let n = 50_000usize;

        for i in 0..n {
            let key = format!("unique:event:{i}");
            if i % 2 == 0 {
                hll_a.add(key.as_bytes());
            } else {
                hll_b.add(key.as_bytes());
            }
        }

        let mut merged = hll_a.clone();
        merged.merge_from(&hll_b);
        let est = merged.count();
        let rel_err = ((est as f64) - (n as f64)).abs() / (n as f64);
        assert!(
            rel_err < 0.015,
            "expected HLL relative error < 1.5%, got {:.4}% (est={}, actual={})",
            rel_err * 100.0,
            est,
            n
        );

        let mut bf = BloomFilter::default();
        for i in 0..2000 {
            let k = format!("bf:{i}");
            bf.add(k.as_bytes());
        }
        for i in 0..2000 {
            let k = format!("bf:{i}");
            assert!(bf.exists(k.as_bytes()));
        }

        let mut cms = CountMinSketch::new();
        cms.incr_by(b"hot_key", 1250);
        cms.incr_by(b"cold_key", 3);
        assert!(cms.query(b"hot_key") >= 1250);
        assert!(cms.query(b"hot_key") <= 1260);
        assert_eq!(cms.query(b"never_seen"), 0);
    }
}
