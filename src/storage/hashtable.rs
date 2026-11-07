/// 64-bit FNV-1a non-cryptographic byte-slice hash.
#[inline]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// SipHash-2-4 keyed PRF over arbitrary byte slices for collision-resistant table indexing.
#[inline]
pub fn siphash24(k0: u64, k1: u64, bytes: &[u8]) -> u64 {
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    let len = bytes.len();
    let blocks = len / 8;
    for b_idx in 0..blocks {
        let off = b_idx * 8;
        let m = u64::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let mut tail: u64 = ((len & 0xff) as u64) << 56;
    let rem_start = blocks * 8;
    let rem = &bytes[rem_start..];
    for (i, &byte) in rem.iter().enumerate() {
        tail |= (byte as u64) << (i * 8);
    }

    v3 ^= tail;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= tail;

    v2 ^= 0xff;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[derive(Clone, Debug)]
struct Bucket<V> {
    hash: u64,
    key: Box<[u8]>,
    val: V,
}

/// Custom Robin Hood Open-Addressing Hash Table with backward-shift deletion.
#[derive(Clone, Debug)]
pub struct RawHashTable<V> {
    slots: Box<[Option<Bucket<V>>]>,
    len: usize,
    seed0: u64,
    seed1: u64,
}

impl<V> Default for RawHashTable<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> RawHashTable<V> {
    pub fn new() -> Self {
        Self::with_capacity_and_seeds(16, 0x9e37_79b9_7f4a_7c15, 0xbf58_476d_1ce4_e5b9)
    }

    pub fn with_capacity_and_seeds(cap: usize, seed0: u64, seed1: u64) -> Self {
        let actual_cap = cap.max(8).next_power_of_two();
        let mut vec = Vec::with_capacity(actual_cap);
        vec.resize_with(actual_cap, || None);
        Self {
            slots: vec.into_boxed_slice(),
            len: 0,
            seed0,
            seed1,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    #[inline]
    fn hash_key(&self, key: &[u8]) -> u64 {
        siphash24(self.seed0, self.seed1, key) ^ fnv1a_64(key).rotate_left(7)
    }

    #[inline]
    fn probe_distance(hash: u64, slot_idx: usize, mask: usize) -> usize {
        let ideal = (hash as usize) & mask;
        slot_idx.wrapping_sub(ideal) & mask
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        if self.len == 0 {
            return None;
        }
        let hash = self.hash_key(key);
        let mask = self.slots.len() - 1;
        let mut idx = (hash as usize) & mask;
        let mut dist = 0usize;

        loop {
            match &self.slots[idx] {
                None => return None,
                Some(bucket) => {
                    let existing_dist = Self::probe_distance(bucket.hash, idx, mask);
                    if dist > existing_dist {
                        return None;
                    }
                    if bucket.hash == hash && bucket.key.as_ref() == key {
                        return Some(&bucket.val);
                    }
                }
            }
            idx = (idx + 1) & mask;
            dist += 1;
        }
    }

    pub fn get_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        if self.len == 0 {
            return None;
        }
        let hash = self.hash_key(key);
        let mask = self.slots.len() - 1;
        let mut idx = (hash as usize) & mask;
        let mut dist = 0usize;

        loop {
            let stop_or_found = match &self.slots[idx] {
                None => return None,
                Some(bucket) => {
                    let existing_dist = Self::probe_distance(bucket.hash, idx, mask);
                    if dist > existing_dist {
                        return None;
                    }
                    bucket.hash == hash && bucket.key.as_ref() == key
                }
            };
            if stop_or_found {
                return self.slots[idx].as_mut().map(|b| &mut b.val);
            }
            idx = (idx + 1) & mask;
            dist += 1;
        }
    }

    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    pub fn insert(&mut self, key: Box<[u8]>, val: V) -> Option<V> {
        if (self.len + 1) * 4 >= self.slots.len() * 3 {
            self.grow();
        }
        let hash = self.hash_key(&key);
        self.insert_hashed(hash, key, val)
    }

    fn insert_hashed(&mut self, hash: u64, key: Box<[u8]>, val: V) -> Option<V> {
        let mask = self.slots.len() - 1;
        let mut idx = (hash as usize) & mask;
        let mut dist = 0usize;
        let mut incoming = Bucket { hash, key, val };

        loop {
            match &mut self.slots[idx] {
                None => {
                    self.slots[idx] = Some(incoming);
                    self.len += 1;
                    return None;
                }
                Some(existing) => {
                    if existing.hash == incoming.hash && existing.key == incoming.key {
                        let old = std::mem::replace(&mut existing.val, incoming.val);
                        return Some(old);
                    }
                    let existing_dist = Self::probe_distance(existing.hash, idx, mask);
                    if existing_dist < dist {
                        std::mem::swap(existing, &mut incoming);
                        dist = existing_dist;
                    }
                }
            }
            idx = (idx + 1) & mask;
            dist += 1;
        }
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<(Box<[u8]>, V)> {
        if self.len == 0 {
            return None;
        }
        let hash = self.hash_key(key);
        let mask = self.slots.len() - 1;
        let mut idx = (hash as usize) & mask;
        let mut dist = 0usize;

        let found_idx = loop {
            match &self.slots[idx] {
                None => return None,
                Some(bucket) => {
                    let existing_dist = Self::probe_distance(bucket.hash, idx, mask);
                    if dist > existing_dist {
                        return None;
                    }
                    if bucket.hash == hash && bucket.key.as_ref() == key {
                        break idx;
                    }
                }
            }
            idx = (idx + 1) & mask;
            dist += 1;
        };

        let removed = self.slots[found_idx].take()?;
        self.len -= 1;

        let mut curr = found_idx;
        loop {
            let next = (curr + 1) & mask;
            let should_shift = match &self.slots[next] {
                None => false,
                Some(next_bucket) => Self::probe_distance(next_bucket.hash, next, mask) > 0,
            };
            if !should_shift {
                break;
            }
            self.slots[curr] = self.slots[next].take();
            curr = next;
        }

        Some((removed.key, removed.val))
    }

    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.len = 0;
    }

    fn grow(&mut self) {
        let new_cap = (self.slots.len() * 2).max(16);
        let mut new_vec = Vec::with_capacity(new_cap);
        new_vec.resize_with(new_cap, || None);
        let old_slots = std::mem::replace(&mut self.slots, new_vec.into_boxed_slice());
        self.len = 0;

        for bucket in old_slots.into_vec().into_iter().flatten() {
            self.insert_hashed(bucket.hash, bucket.key, bucket.val);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &V)> {
        self.slots
            .iter()
            .filter_map(|slot| slot.as_ref().map(|b| (b.key.as_ref(), &b.val)))
    }

    /// Cursor-based bounded slot scan for O(1)-amortized probabilistic TTL sampling.
    pub fn sample_keys<F>(&self, cursor: &mut usize, max_slots_to_scan: usize, mut predicate: F) -> Vec<Box<[u8]>>
    where
        F: FnMut(&[u8], &V) -> bool,
    {
        let mut matched = Vec::new();
        if self.len == 0 || self.slots.is_empty() {
            return matched;
        }
        let mask = self.slots.len() - 1;
        let limit = max_slots_to_scan.min(self.slots.len());
        for _ in 0..limit {
            let idx = *cursor & mask;
            *cursor = cursor.wrapping_add(1);
            if let Some(bucket) = &self.slots[idx] {
                if predicate(bucket.key.as_ref(), &bucket.val) {
                    matched.push(bucket.key.clone());
                }
            }
        }
        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_robin_hood_insert_lookup_delete() {
        let mut map = RawHashTable::new();
        for i in 0..2000u32 {
            let k = format!("key:{i}").into_bytes().into_boxed_slice();
            assert_eq!(map.insert(k, i), None);
        }
        assert_eq!(map.len(), 2000);

        for i in (0..2000u32).step_by(2) {
            let k = format!("key:{i}");
            let removed = map.remove(k.as_bytes());
            assert_eq!(removed.map(|(_, v)| v), Some(i));
        }
        assert_eq!(map.len(), 1000);

        for i in 0..2000u32 {
            let k = format!("key:{i}");
            if i % 2 == 0 {
                assert_eq!(map.get(k.as_bytes()), None);
            } else {
                assert_eq!(map.get(k.as_bytes()), Some(&i));
            }
        }
    }
}
