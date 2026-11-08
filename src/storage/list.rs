/// Power-of-two circular double-ended ring buffer backing the Redis `List` data type.
#[derive(Clone, Debug)]
pub struct RingList {
    buf: Box<[Option<Box<[u8]>>]>,
    head: usize,
    len: usize,
}

impl Default for RingList {
    fn default() -> Self {
        Self::new()
    }
}

impl RingList {
    pub fn new() -> Self {
        Self::with_capacity(8)
    }

    pub fn with_capacity(cap: usize) -> Self {
        let actual = cap.max(4).next_power_of_two();
        let mut vec = Vec::with_capacity(actual);
        vec.resize_with(actual, || None);
        Self {
            buf: vec.into_boxed_slice(),
            head: 0,
            len: 0,
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

    pub fn push_front(&mut self, val: Box<[u8]>) {
        if self.len == self.buf.len() {
            self.reallocate(self.buf.len() * 2);
        }
        let mask = self.buf.len() - 1;
        self.head = self.head.wrapping_sub(1) & mask;
        self.buf[self.head] = Some(val);
        self.len += 1;
    }

    pub fn push_back(&mut self, val: Box<[u8]>) {
        if self.len == self.buf.len() {
            self.reallocate(self.buf.len() * 2);
        }
        let mask = self.buf.len() - 1;
        let tail = (self.head + self.len) & mask;
        self.buf[tail] = Some(val);
        self.len += 1;
    }

    pub fn pop_front(&mut self) -> Option<Box<[u8]>> {
        if self.len == 0 {
            return None;
        }
        let mask = self.buf.len() - 1;
        let item = self.buf[self.head].take();
        self.head = (self.head + 1) & mask;
        self.len -= 1;
        self.maybe_shrink();
        item
    }

    pub fn pop_back(&mut self) -> Option<Box<[u8]>> {
        if self.len == 0 {
            return None;
        }
        let mask = self.buf.len() - 1;
        let last_idx = (self.head + self.len - 1) & mask;
        let item = self.buf[last_idx].take();
        self.len -= 1;
        self.maybe_shrink();
        item
    }

    pub fn get(&self, index: i64) -> Option<&[u8]> {
        let len_i64 = self.len as i64;
        let resolved = if index < 0 { len_i64 + index } else { index };
        if resolved < 0 || resolved >= len_i64 {
            return None;
        }
        let mask = self.buf.len() - 1;
        let phys = (self.head + resolved as usize) & mask;
        self.buf[phys].as_deref()
    }

    pub fn range(&self, start: i64, stop: i64) -> Vec<&[u8]> {
        if self.len == 0 {
            return Vec::new();
        }
        let len_i64 = self.len as i64;
        let mut s = if start < 0 { len_i64 + start } else { start };
        let mut e = if stop < 0 { len_i64 + stop } else { stop };
        if s < 0 {
            s = 0;
        }
        if e >= len_i64 {
            e = len_i64 - 1;
        }
        if s > e || s >= len_i64 {
            return Vec::new();
        }
        let count = (e - s + 1) as usize;
        let mut out = Vec::with_capacity(count);
        let mask = self.buf.len() - 1;
        for offset in (s as usize)..=(e as usize) {
            let phys = (self.head + offset) & mask;
            if let Some(val) = &self.buf[phys] {
                out.push(val.as_ref());
            }
        }
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        let mask = self.buf.len() - 1;
        let head = self.head;
        (0..self.len).filter_map(move |offset| {
            let phys = (head + offset) & mask;
            self.buf[phys].as_deref()
        })
    }

    fn maybe_shrink(&mut self) {
        if self.buf.len() > 16 && self.len * 4 < self.buf.len() {
            self.reallocate(self.buf.len() / 2);
        }
    }

    fn reallocate(&mut self, new_cap: usize) {
        let cap = new_cap.max(4).next_power_of_two();
        let mut next_vec = Vec::with_capacity(cap);
        next_vec.resize_with(cap, || None);
        let old_mask = self.buf.len() - 1;
        for i in 0..self.len {
            let old_idx = (self.head + i) & old_mask;
            next_vec[i] = self.buf[old_idx].take();
        }
        self.buf = next_vec.into_boxed_slice();
        self.head = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_list_wraparound_and_ranges() {
        let mut list = RingList::new();
        for i in 0..50 {
            list.push_back(format!("v{i}").into_bytes().into_boxed_slice());
        }
        for i in 0..20 {
            assert_eq!(list.pop_front().as_deref(), Some(format!("v{i}").as_bytes()));
        }
        list.push_front(b"front".to_vec().into_boxed_slice());
        assert_eq!(list.len(), 31);
        assert_eq!(list.get(0), Some(b"front".as_slice()));
        assert_eq!(list.get(-1), Some(b"v49".as_slice()));

        let slice = list.range(0, 2);
        assert_eq!(slice, vec![b"front".as_slice(), b"v20".as_slice(), b"v21".as_slice()]);
    }
}
