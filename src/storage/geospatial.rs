use crate::error::{EngineError, EngineResult};
use crate::storage::skiplist::SortedSet;

pub const GEO_LAT_MIN: f64 = -85.05112878;
pub const GEO_LAT_MAX: f64 = 85.05112878;
pub const GEO_LON_MIN: f64 = -180.0;
pub const GEO_LON_MAX: f64 = 180.0;
pub const GEO_STEP_MAX: u8 = 26; // 26 bits lat + 26 bits lon = 52-bit Morton integer
pub const EARTH_RADIUS_METERS: f64 = 6_372_797.560856;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeoUnit {
    Meters,
    Kilometers,
    Miles,
    Feet,
}

impl GeoUnit {
    pub fn from_bytes(raw: &[u8]) -> EngineResult<Self> {
        if raw.eq_ignore_ascii_case(b"m") {
            Ok(GeoUnit::Meters)
        } else if raw.eq_ignore_ascii_case(b"km") {
            Ok(GeoUnit::Kilometers)
        } else if raw.eq_ignore_ascii_case(b"mi") {
            Ok(GeoUnit::Miles)
        } else if raw.eq_ignore_ascii_case(b"ft") {
            Ok(GeoUnit::Feet)
        } else {
            Err(EngineError::InvalidArgument(
                "unsupported unit provided. please use M, KM, FT, MI".to_string(),
            ))
        }
    }

    #[inline]
    pub fn to_meters(self, val: f64) -> f64 {
        match self {
            GeoUnit::Meters => val,
            GeoUnit::Kilometers => val * 1000.0,
            GeoUnit::Miles => val * 1609.34,
            GeoUnit::Feet => val * 0.3048,
        }
    }

    #[inline]
    pub fn from_meters(self, meters: f64) -> f64 {
        match self {
            GeoUnit::Meters => meters,
            GeoUnit::Kilometers => meters / 1000.0,
            GeoUnit::Miles => meters / 1609.34,
            GeoUnit::Feet => meters / 0.3048,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GeoMatch {
    pub member: Box<[u8]>,
    pub dist_unit: f64,
    pub lon: f64,
    pub lat: f64,
}

#[inline]
fn spread_u32_to_even_bits(v: u32) -> u64 {
    let mut x = (v as u64) & 0x03FF_FFFF;
    x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
    x = (x | (x << 8)) & 0x00FF_00FF_00FF_00FF;
    x = (x | (x << 4)) & 0x0F0F_0F0F_0F0F_0F0F;
    x = (x | (x << 2)) & 0x3333_3333_3333_3333;
    (x | (x << 1)) & 0x5555_5555_5555_5555
}

#[inline]
fn compact_even_bits_to_u32(mut x: u64) -> u32 {
    x &= 0x5555_5555_5555_5555;
    x = (x | (x >> 1)) & 0x3333_3333_3333_3333;
    x = (x | (x >> 2)) & 0x0F0F_0F0F_0F0F_0F0F;
    x = (x | (x >> 4)) & 0x00FF_00FF_00FF_00FF;
    x = (x | (x >> 8)) & 0x0000_FFFF_0000_FFFF;
    x = (x | (x >> 16)) & 0x0000_0000_FFFF_FFFF;
    (x as u32) & 0x03FF_FFFF
}

#[inline]
fn interleave_morton(lon_bits: u32, lat_bits: u32) -> u64 {
    spread_u32_to_even_bits(lon_bits) | (spread_u32_to_even_bits(lat_bits) << 1)
}

#[inline]
fn deinterleave_morton(hash52: u64) -> (u32, u32) {
    let lon_bits = compact_even_bits_to_u32(hash52);
    let lat_bits = compact_even_bits_to_u32(hash52 >> 1);
    (lon_bits, lat_bits)
}

/// Encodes `(lon, lat)` into a 52-bit Morton Z-order integer at `step` bits (`1..=26`).
pub fn geohash_encode_step(lon: f64, lat: f64, step: u8) -> EngineResult<u64> {
    if !(GEO_LON_MIN..=GEO_LON_MAX).contains(&lon) || !(GEO_LAT_MIN..=GEO_LAT_MAX).contains(&lat) {
        return Err(EngineError::InvalidArgument(format!(
            "invalid longitude,latitude pair {},{}",
            lon, lat
        )));
    }
    let scale = (1u64 << step) as f64;
    let mut lon_norm = ((lon - GEO_LON_MIN) / (GEO_LON_MAX - GEO_LON_MIN)) * scale;
    let mut lat_norm = ((lat - GEO_LAT_MIN) / (GEO_LAT_MAX - GEO_LAT_MIN)) * scale;
    let max_idx = ((1u64 << step) - 1) as f64;
    lon_norm = lon_norm.floor().clamp(0.0, max_idx);
    lat_norm = lat_norm.floor().clamp(0.0, max_idx);

    let lon_q = lon_norm as u32;
    let lat_q = lat_norm as u32;
    Ok(interleave_morton(lon_q, lat_q))
}

#[inline]
pub fn geohash_encode_52bit(lon: f64, lat: f64) -> EngineResult<u64> {
    geohash_encode_step(lon, lat, GEO_STEP_MAX)
}

/// Decodes a 52-bit Morton Z-order integer back into `(lon, lat)` cell center coordinates.
pub fn geohash_decode_52bit(hash52: u64) -> (f64, f64) {
    let (lon_q, lat_q) = deinterleave_morton(hash52);
    let scale = (1u64 << GEO_STEP_MAX) as f64;
    let lon = GEO_LON_MIN + (((lon_q as f64) + 0.5) / scale) * (GEO_LON_MAX - GEO_LON_MIN);
    let lat = GEO_LAT_MIN + (((lat_q as f64) + 0.5) / scale) * (GEO_LAT_MAX - GEO_LAT_MIN);
    (lon, lat)
}

/// Exact WGS84 spherical Haversine distance in meters.
pub fn haversine_meters(lon1: f64, lat1: f64, lon2: f64, lat2: f64) -> f64 {
    let lat1_r = lat1.to_radians();
    let lat2_r = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let sin_dlat = (dlat * 0.5).sin();
    let sin_dlon = (dlon * 0.5).sin();
    let a = sin_dlat * sin_dlat + lat1_r.cos() * lat2_r.cos() * sin_dlon * sin_dlon;
    let c = 2.0 * a.clamp(0.0, 1.0).sqrt().asin();
    EARTH_RADIUS_METERS * c
}

fn estimate_step_for_radius(radius_meters: f64, lat_deg: f64) -> u8 {
    if radius_meters <= 0.0 {
        return GEO_STEP_MAX;
    }
    // Account for meridian convergence near high latitudes so 3x3 cells always cover the circle.
    let cos_lat = lat_deg.to_radians().cos().abs().max(0.05);
    let effective_radius = radius_meters / cos_lat;
    let mut step = 1u8;
    while step < GEO_STEP_MAX {
        let cell_width_m = (40_075_016.686 / ((1u64 << step) as f64)).max(1.0);
        if cell_width_m < effective_radius * 2.0 {
            break;
        }
        step += 1;
    }
    step.saturating_sub(1).max(1)
}

/// Computes the 9-cell (center + 8 neighbors) 52-bit Morton score intervals covering `(lon, lat, radius_m)`.
pub fn nine_cell_morton_ranges(lon: f64, lat: f64, radius_meters: f64) -> EngineResult<Vec<(u64, u64)>> {
    let step = estimate_step_for_radius(radius_meters, lat);
    let scale = 1u32 << step;
    let center_hash = geohash_encode_step(lon, lat, step)?;
    let (cx, cy) = deinterleave_morton(center_hash);

    let shift = ((GEO_STEP_MAX - step) * 2) as u32;
    let span = if shift >= 52 {
        (1u64 << 52) - 1
    } else {
        (1u64 << shift) - 1
    };

    let mut raw_ranges = Vec::with_capacity(9);
    for dx in [-1i64, 0, 1] {
        // Longitude wraps around the +/-180 antimeridian.
        let nx = ((cx as i64 + dx).rem_euclid(scale as i64)) as u32;
        for dy in [-1i64, 0, 1] {
            let ny_i64 = cy as i64 + dy;
            if ny_i64 < 0 || ny_i64 >= scale as i64 {
                continue;
            }
            let ny = ny_i64 as u32;
            let cell_prefix = interleave_morton(nx, ny);
            let min_score = cell_prefix << shift;
            let max_score = min_score | span;
            raw_ranges.push((min_score, max_score));
        }
    }

    raw_ranges.sort_unstable_by_key(|r| r.0);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(raw_ranges.len());
    for (lo, hi) in raw_ranges {
        if let Some(last) = merged.last_mut() {
            if lo <= last.1.saturating_add(1) {
                if hi > last.1 {
                    last.1 = hi;
                }
                continue;
            }
        }
        merged.push((lo, hi));
    }
    Ok(merged)
}

pub fn georadius_query(
    zset: &SortedSet,
    center_lon: f64,
    center_lat: f64,
    radius: f64,
    unit: GeoUnit,
    ascending: bool,
    count: Option<usize>,
) -> EngineResult<Vec<GeoMatch>> {
    if radius < 0.0 {
        return Err(EngineError::InvalidArgument(
            "radius cannot be negative".to_string(),
        ));
    }
    let radius_m = unit.to_meters(radius);
    let ranges = nine_cell_morton_ranges(center_lon, center_lat, radius_m)?;

    let mut matches = Vec::new();
    for (lo, hi) in ranges {
        let candidates = zset.zrange_by_score(lo as f64, hi as f64);
        for (member, score) in candidates {
            let hash52 = score as u64;
            let (m_lon, m_lat) = geohash_decode_52bit(hash52);
            let dist_m = haversine_meters(center_lon, center_lat, m_lon, m_lat);
            if dist_m <= radius_m {
                matches.push(GeoMatch {
                    member: member.to_vec().into_boxed_slice(),
                    dist_unit: unit.from_meters(dist_m),
                    lon: m_lon,
                    lat: m_lat,
                });
            }
        }
    }

    matches.sort_by(|a, b| {
        let ord = a.dist_unit.total_cmp(&b.dist_unit);
        let dir = if ascending { ord } else { ord.reverse() };
        dir.then_with(|| a.member.cmp(&b.member))
    });
    if let Some(limit) = count {
        matches.truncate(limit);
    }
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_52bit_morton_geohash_haversine_and_georadius() -> EngineResult<()> {
        let mut zset = SortedSet::new();
        // Classic Redis geo test cities in Sicily + Rome + Paris
        let cities: &[(&[u8], f64, f64)] = &[
            (b"Palermo", 13.361389, 38.115556),
            (b"Catania", 15.087269, 37.502669),
            (b"Agrigento", 13.583333, 37.316667),
            (b"Rome", 12.496366, 41.902782),
            (b"Paris", 2.352222, 48.856614),
        ];

        for &(name, lon, lat) in cities {
            let h = geohash_encode_52bit(lon, lat)?;
            let (dec_lon, dec_lat) = geohash_decode_52bit(h);
            assert!((dec_lon - lon).abs() < 1e-5);
            assert!((dec_lat - lat).abs() < 1e-5);
            zset.zadd(h as f64, name.to_vec().into_boxed_slice());
        }

        // Palermo <-> Catania is ~166.27 km
        let p_score = zset.zscore(b"Palermo").unwrap_or(0.0) as u64;
        let c_score = zset.zscore(b"Catania").unwrap_or(0.0) as u64;
        let (p_lon, p_lat) = geohash_decode_52bit(p_score);
        let (c_lon, c_lat) = geohash_decode_52bit(c_score);
        let dist_km = haversine_meters(p_lon, p_lat, c_lon, c_lat) / 1000.0;
        assert!((dist_km - 166.274).abs() < 0.2);

        // Radius 200 km around (15.0, 37.5) must return Catania, Agrigento, Palermo in distance order, excluding Rome & Paris
        let hits = georadius_query(&zset, 15.0, 37.5, 200.0, GeoUnit::Kilometers, true, None)?;
        let names: Vec<&[u8]> = hits.iter().map(|m| m.member.as_ref()).collect();
        assert_eq!(names, vec![b"Catania".as_slice(), b"Agrigento".as_slice(), b"Palermo".as_slice()]);
        Ok(())
    }
}
