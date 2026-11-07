use crate::error::{EngineError, EngineResult};

/// Bit-level writer packing variable-width fields (`1..=64` bits) MSB-first into a byte buffer.
#[derive(Clone, Debug, Default)]
pub struct BitWriter {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(128),
            bit_len: 0,
        }
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_raw(bytes: Vec<u8>, bit_len: usize) -> Self {
        Self { bytes, bit_len }
    }

    #[inline]
    pub fn write_bit(&mut self, bit: bool) {
        let byte_idx = self.bit_len >> 3;
        let bit_in_byte = 7 - (self.bit_len & 7);
        if byte_idx == self.bytes.len() {
            self.bytes.push(0);
        }
        if bit {
            self.bytes[byte_idx] |= 1u8 << bit_in_byte;
        }
        self.bit_len += 1;
    }

    pub fn write_bits(&mut self, val: u64, count: u8) {
        if count == 0 {
            return;
        }
        for shift in (0..count).rev() {
            self.write_bit(((val >> shift) & 1) != 0);
        }
    }

    pub fn write_signed(&mut self, val: i64, bits: u8) {
        if bits == 64 {
            self.write_bits(val as u64, 64);
        } else {
            let mask = (1u64 << bits) - 1;
            self.write_bits((val as u64) & mask, bits);
        }
    }
}

/// Bit-level reader unpacking MSB-first bitstreams produced by `BitWriter`.
pub struct BitReader<'a> {
    bytes: &'a [u8],
    bit_len: usize,
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(bytes: &'a [u8], bit_len: usize) -> Self {
        Self {
            bytes,
            bit_len,
            pos: 0,
        }
    }

    #[inline]
    pub fn read_bit(&mut self) -> EngineResult<bool> {
        if self.pos >= self.bit_len {
            return Err(EngineError::CorruptedPersistence(
                "Gorilla bitstream EOF".to_string(),
            ));
        }
        let byte_idx = self.pos >> 3;
        let bit_in_byte = 7 - (self.pos & 7);
        self.pos += 1;
        Ok(((self.bytes[byte_idx] >> bit_in_byte) & 1) != 0)
    }

    pub fn read_bits(&mut self, count: u8) -> EngineResult<u64> {
        let mut acc = 0u64;
        for _ in 0..count {
            acc = (acc << 1) | u64::from(self.read_bit()?);
        }
        Ok(acc)
    }

    pub fn read_signed(&mut self, bits: u8) -> EngineResult<i64> {
        let raw = self.read_bits(bits)?;
        if bits == 64 {
            return Ok(raw as i64);
        }
        let sign_bit = 1u64 << (bits - 1);
        if (raw & sign_bit) != 0 {
            let ext_mask = !((1u64 << bits) - 1);
            Ok((raw | ext_mask) as i64)
        } else {
            Ok(raw as i64)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TsAggregation {
    Avg,
    Min,
    Max,
    Sum,
    P99,
}

impl TsAggregation {
    pub fn from_bytes(raw: &[u8]) -> EngineResult<Self> {
        if raw.eq_ignore_ascii_case(b"avg") {
            Ok(TsAggregation::Avg)
        } else if raw.eq_ignore_ascii_case(b"min") {
            Ok(TsAggregation::Min)
        } else if raw.eq_ignore_ascii_case(b"max") {
            Ok(TsAggregation::Max)
        } else if raw.eq_ignore_ascii_case(b"sum") {
            Ok(TsAggregation::Sum)
        } else if raw.eq_ignore_ascii_case(b"p99") {
            Ok(TsAggregation::P99)
        } else {
            Err(EngineError::InvalidArgument(
                "unknown aggregation, expected avg|min|max|sum|p99".to_string(),
            ))
        }
    }
}

/// Facebook Gorilla (Pelkonen et al., VLDB 2015) XOR + Delta-of-Delta Compressed Time-Series.
#[derive(Clone, Debug, Default)]
pub struct GorillaTimeSeries {
    stream: BitWriter,
    count: usize,
    first_ts: i64,
    prev_ts: i64,
    prev_delta: i64,
    prev_val_bits: u64,
    prev_leading: u8,
    prev_trailing: u8,
    has_prev_window: bool,
}

impl GorillaTimeSeries {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub fn compressed_byte_len(&self) -> usize {
        self.stream.byte_len()
    }

    #[inline]
    pub fn latest(&self) -> Option<(i64, f64)> {
        if self.count == 0 {
            None
        } else {
            Some((self.prev_ts, f64::from_bits(self.prev_val_bits)))
        }
    }

    pub fn append(&mut self, ts: i64, val: f64) -> EngineResult<()> {
        if val.is_nan() {
            return Err(EngineError::InvalidArgument(
                "NaN is not supported in Gorilla TimeSeries".to_string(),
            ));
        }
        let val_bits = val.to_bits();

        if self.count == 0 {
            self.stream.write_signed(ts, 64);
            self.stream.write_bits(val_bits, 64);
            self.first_ts = ts;
            self.prev_ts = ts;
            self.prev_val_bits = val_bits;
            self.count = 1;
            return Ok(());
        }

        if ts < self.prev_ts {
            return Err(EngineError::InvalidArgument(
                "TS.ADD timestamp must be monotonically non-decreasing".to_string(),
            ));
        }

        // 1. Compress Timestamp via Delta-of-Delta
        let delta = ts - self.prev_ts;
        if self.count == 1 {
            self.stream.write_signed(delta, 32);
        } else {
            let dod = delta - self.prev_delta;
            if dod == 0 {
                self.stream.write_bit(false);
            } else if (-63..=64).contains(&dod) {
                self.stream.write_bits(0b10, 2);
                self.stream.write_signed(dod, 7);
            } else if (-255..=256).contains(&dod) {
                self.stream.write_bits(0b110, 3);
                self.stream.write_signed(dod, 9);
            } else if (-2047..=2048).contains(&dod) {
                self.stream.write_bits(0b1110, 4);
                self.stream.write_signed(dod, 12);
            } else {
                self.stream.write_bits(0b1111, 4);
                self.stream.write_signed(dod, 64);
            }
        }
        self.prev_delta = delta;
        self.prev_ts = ts;

        // 2. Compress f64 Value via Gorilla XOR Leading/Trailing Zero Window
        let xor = val_bits ^ self.prev_val_bits;
        if xor == 0 {
            self.stream.write_bit(false);
        } else {
            self.stream.write_bit(true);
            let leading = (xor.leading_zeros() as u8).min(31);
            let trailing = xor.trailing_zeros() as u8;

            if self.has_prev_window
                && leading >= self.prev_leading
                && trailing >= self.prev_trailing
            {
                self.stream.write_bit(false);
                let meaningful_len = 64 - self.prev_leading - self.prev_trailing;
                let shifted = xor >> self.prev_trailing;
                self.stream.write_bits(shifted, meaningful_len);
            } else {
                self.stream.write_bit(true);
                let meaningful_len = (64u8 - leading).saturating_sub(trailing).max(1);
                let actual_trailing = 64u8 - leading - meaningful_len;
                self.stream.write_bits(leading as u64, 5);
                self.stream.write_bits((meaningful_len - 1) as u64, 6);
                let shifted = xor >> actual_trailing;
                self.stream.write_bits(shifted, meaningful_len);
                self.prev_leading = leading;
                self.prev_trailing = actual_trailing;
                self.has_prev_window = true;
            }
        }

        self.prev_val_bits = val_bits;
        self.count += 1;
        Ok(())
    }

    pub fn decode_all(&self) -> EngineResult<Vec<(i64, f64)>> {
        if self.count == 0 {
            return Ok(Vec::new());
        }
        let mut reader = BitReader::new(self.stream.as_bytes(), self.stream.bit_len());
        let mut out = Vec::with_capacity(self.count);

        let mut prev_ts = reader.read_signed(64)?;
        let mut prev_val_bits = reader.read_bits(64)?;
        out.push((prev_ts, f64::from_bits(prev_val_bits)));

        let mut prev_delta = 0i64;
        let mut prev_leading = 0u8;
        let mut prev_trailing = 0u8;

        for idx in 1..self.count {
            let delta = if idx == 1 {
                reader.read_signed(32)?
            } else if !reader.read_bit()? {
                prev_delta
            } else if !reader.read_bit()? {
                prev_delta + reader.read_signed(7)?
            } else if !reader.read_bit()? {
                prev_delta + reader.read_signed(9)?
            } else if !reader.read_bit()? {
                prev_delta + reader.read_signed(12)?
            } else {
                prev_delta + reader.read_signed(64)?
            };
            prev_delta = delta;
            prev_ts += delta;

            if reader.read_bit()? {
                let (leading, meaningful_len, trailing) = if !reader.read_bit()? {
                    let mlen = 64 - prev_leading - prev_trailing;
                    (prev_leading, mlen, prev_trailing)
                } else {
                    let l = reader.read_bits(5)? as u8;
                    let mlen = (reader.read_bits(6)? as u8) + 1;
                    let tr = 64u8 - l - mlen;
                    prev_leading = l;
                    prev_trailing = tr;
                    (l, mlen, tr)
                };
                let _ = leading;
                let meaningful = reader.read_bits(meaningful_len)?;
                let xor = meaningful << trailing;
                prev_val_bits ^= xor;
            }

            out.push((prev_ts, f64::from_bits(prev_val_bits)));
        }

        Ok(out)
    }

    pub fn range_query(
        &self,
        from_ts: i64,
        to_ts: i64,
        agg: Option<(TsAggregation, i64)>,
    ) -> EngineResult<Vec<(i64, f64)>> {
        if from_ts > to_ts || self.count == 0 {
            return Ok(Vec::new());
        }
        let all = self.decode_all()?;
        let filtered: Vec<(i64, f64)> = all
            .into_iter()
            .filter(|&(ts, _)| ts >= from_ts && ts <= to_ts)
            .collect();

        let Some((agg_kind, bucket_ms)) = agg else {
            return Ok(filtered);
        };
        if bucket_ms <= 0 {
            return Err(EngineError::InvalidArgument(
                "bucket_ms must be > 0".to_string(),
            ));
        }

        let mut buckets: Vec<(i64, Vec<f64>)> = Vec::new();
        for (ts, v) in filtered {
            let b_start = (ts.div_euclid(bucket_ms)) * bucket_ms;
            if let Some(last) = buckets.last_mut() {
                if last.0 == b_start {
                    last.1.push(v);
                    continue;
                }
            }
            buckets.push((b_start, vec![v]));
        }

        let mut out = Vec::with_capacity(buckets.len());
        for (b_ts, mut vals) in buckets {
            let res = match agg_kind {
                TsAggregation::Sum => vals.iter().sum::<f64>(),
                TsAggregation::Avg => vals.iter().sum::<f64>() / (vals.len() as f64),
                TsAggregation::Min => vals.iter().copied().fold(f64::INFINITY, f64::min),
                TsAggregation::Max => vals.iter().copied().fold(f64::NEG_INFINITY, f64::max),
                TsAggregation::P99 => {
                    vals.sort_by(|a, b| a.total_cmp(b));
                    let idx = (((vals.len() as f64) - 1.0) * 0.99).round() as usize;
                    vals[idx.min(vals.len() - 1)]
                }
            };
            out.push((b_ts, res));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gorilla_compression_under_1_8_bytes_per_sample_and_aggregations() -> EngineResult<()> {
        let mut ts = GorillaTimeSeries::new();
        let n = 2_000usize;
        let base_ts = 1_700_000_000_000i64;

        let mut expected = Vec::with_capacity(n);
        for i in 0..n {
            let t = base_ts + (i as i64) * 1000;
            // Smooth sensor telemetry: slowly drifting 0.25-quantized CPU temperature/load readings
            let v = 42.0 + (((i / 8) % 16) as f64) * 0.25;
            ts.append(t, v)?;
            expected.push((t, v));
        }

        let bytes_per_sample = (ts.compressed_byte_len() as f64) / (n as f64);
        assert!(
            bytes_per_sample < 1.8,
            "expected Gorilla compression < 1.8 bytes/sample, got {:.3} bytes/sample",
            bytes_per_sample
        );

        let decoded = ts.decode_all()?;
        assert_eq!(decoded, expected);

        let bucketed = ts.range_query(
            base_ts,
            base_ts + 9_999,
            Some((TsAggregation::Avg, 5_000)),
        )?;
        assert_eq!(bucketed.len(), 2);
        Ok(())
    }
}
